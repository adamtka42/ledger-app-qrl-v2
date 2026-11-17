/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "sign_tx.h"
#include "address.h"
#include "sw.h"
#include "globals.h"
#include "request_context.h"
#include "display.h"
#include "validate.h"
#include "send_response.h"
#include "keccak256.h"
#include "tx_stream.h"
#include "dispatcher.h"  // DATA_FIRST, DATA_MORE, DATA_LAST

#ifdef HAVE_STAKING_DEPOSIT
static bool staking_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    return cx_hash_sha256(data, len, out, 32) == 32;
}

static void observe_staking(void *context,
                            uint32_t offset,
                            uint32_t total,
                            const uint8_t *data,
                            size_t len) {
    transaction_ctx_t *session = context;
    if (staking_deposit_is_target(&session->tx_data))
        staking_deposit_feed(&session->staking, offset, total, data, len);
}
#endif

static int abort_sign_tx(uint16_t sw) {
    reset_request_context();
    return io_send_sw(sw);
}

int handler_sign_tx(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    if ((p1 != DATA_FIRST && p1 != DATA_MORE && p1 != DATA_LAST) || p2 > 17 ||
        (p1 != DATA_LAST && p2 != 0)) {
        return abort_sign_tx(SW_WRONG_P1P2);
    }

    if (p1 == DATA_FIRST) {
        reset_request_context();

        if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
            !buffer_read_bip32_path(cdata,
                                    G_context.bip32_path,
                                    (size_t) G_context.bip32_path_len)) {
            return abort_sign_tx(SW_WRONG_DATA_LENGTH);
        }

        if (!is_valid_zond_bip32_path(G_context.bip32_path, (size_t) G_context.bip32_path_len)) {
            return abort_sign_tx(SW_WRONG_DATA_LENGTH);
        }

        tx_stream_init(&G_context.tx_info.stream, &G_context.tx_info.tx_data);
        keccak256_init(&G_context.tx_info.hash_ctx);
#ifdef HAVE_STAKING_DEPOSIT
        staking_deposit_init(&G_context.tx_info.staking, staking_hash);
        G_context.tx_info.stream.on_data = observe_staking;
        G_context.tx_info.stream.observer_context = &G_context.tx_info;
#endif
        // A rejected first command must never leave a session that can continue.
        G_context.req_type = CONFIRM_TRANSACTION;
        G_context.state = STATE_RECEIVING;

        return io_send_sw(SW_OK);
    }

    if (p1 == DATA_MORE || (p1 == DATA_LAST && p2 == 0)) {
        if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_RECEIVING) {
            return abort_sign_tx(SW_BAD_STATE);
        }
        if (cdata->offset >= cdata->size) {
            return abort_sign_tx(SW_WRONG_DATA_LENGTH);
        }

        const uint8_t *chunk = cdata->ptr + cdata->offset;
        size_t chunk_len = cdata->size - cdata->offset;

        // Every raw byte is part of the sighash preimage: the type byte, the
        // RLP headers and the `data` / `access_list` bytes the parser skips.
        keccak256_absorb(&G_context.tx_info.hash_ctx, chunk, chunk_len);

        tx_stream_status_e status =
            tx_stream_feed(&G_context.tx_info.stream, &G_context.tx_info.tx_data, chunk, chunk_len);
        if (status == TX_STREAM_ERROR) {
            return abort_sign_tx(SW_TX_PARSING_FAIL);
        }

        if (p1 == DATA_MORE) {
            if (status == TX_STREAM_FINISHED) {
                // the outer list is already closed but the host announces more data
                return abort_sign_tx(SW_TX_PARSING_FAIL);
            }
            // more APDUs with transaction parts are expected
            return io_send_sw(SW_OK);
        }

        // last APDU for this transaction
        if (status != TX_STREAM_FINISHED) {
            return abort_sign_tx(SW_TX_PARSING_FAIL);  // truncated transaction
        }
        keccak256_finalize(&G_context.tx_info.hash_ctx);
        keccak256_squeeze(&G_context.tx_info.hash_ctx, G_context.tx_info.m_hash);
        keccak256_clear(&G_context.tx_info.hash_ctx);
        G_context.state = STATE_PARSED;

        zond_tx_t *tx = &G_context.tx_info.tx_data;
        bool staking = false;
#ifdef HAVE_STAKING_DEPOSIT
        if (staking_deposit_is_target(tx) && G_context.tx_info.staking.selected) {
            if (G_context.tx_info.token_metadata.verified ||
                G_context.tx_info.contract_descriptor.verified)
                return abort_sign_tx(SW_BAD_STATE);
            if (!staking_deposit_validate(&G_context.tx_info.staking, tx))
                return abort_sign_tx(SW_STAKING_DEPOSIT_INVALID);
            staking = G_context.tx_info.staking_call = true;
        }
#endif
        bool token = token_call_prepare(tx,
                                        &G_context.tx_info.token_metadata,
                                        &G_context.tx_info.token_call);
        const contract_descriptor_t *descriptor = &G_context.tx_info.contract_descriptor;
        G_context.tx_info.contract_call = contract_call_matches(tx, descriptor);
        if (descriptor->verified && !G_context.tx_info.contract_call) {
            return abort_sign_tx(SW_CONTRACT_CALL_MISMATCH);
        }
        bool blind = (tx->has_data || tx->has_access_list) && !token &&
                     !G_context.tx_info.contract_call && !staking;
        if (blind && !N_storage.enable_blind_signing) {
            return abort_sign_tx(SW_DENY);
        }
        return ui_display_transaction_bs_choice(blind, tx);
    }

    if (p1 == DATA_LAST && p2 > 0 && p2 < 18) {
        if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_APPROVED ||
            !N_storage.is_sending_signature) {
            return io_send_sw(SW_BAD_STATE);
        }
        if (cdata->offset != cdata->size) {
            return abort_sign_tx(SW_WRONG_DATA_LENGTH);
        }
        return helper_send_response_sig(p2);
    }

    return abort_sign_tx(SW_WRONG_P1P2);
}
