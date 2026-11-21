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

#include <stdbool.h>  // bool
#include <stdio.h>    // snprintf
#include <string.h>   // memset

#include "os.h"
#include "os_pic.h"
#include "glyphs.h"
#include "os_io_seproxyhal.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "request_context.h"
#include "sw.h"
#include "tx_format.h"
#include "validate.h"
#include "menu.h"
#include "address.h"

static char g_from_address[1 + ADDRESS_SIZE * 2 + 1];
static char g_amount[TX_FORMAT_MAX_AMOUNT_LEN + TOKEN_SYMBOL_MAX + 2];
static char g_to_address[1 + ADDRESS_SIZE * 2 + 1];
static char g_token_contract[1 + ADDRESS_SIZE * 2 + 1];
static char g_max_fees[TX_FORMAT_MAX_AMOUNT_LEN + 5];
static char g_chain_id[TX_FORMAT_MAX_DECIMAL_DIGITS + 1];
static char g_nonce[21];
static char g_gas_limit[21];
static char g_gas_tip_cap[TX_FORMAT_MAX_AMOUNT_LEN + 5];
static char g_tx_hash[65];
static char g_contract_values[CONTRACT_CALL_MAX_FIELDS]
                             [CONTRACT_CALL_LABEL_MAX + 1 + ADDRESS_SIZE * 2 + 2];
static char g_contract_labels[CONTRACT_CALL_MAX_FIELDS][CONTRACT_CALL_LABEL_MAX + 4];

// Maximum review fields: From/Owner, Amount/Spending limit, To/Spender or Operation, Token
// contract, Chain ID, Gas limit, Priority fee / gas, Max fees, Nonce, Transaction hash.
// Contract calls add Operation and up to three numbered arguments to native fields.
// NFT transfers show From, NFT owner, To, Collection, NFT contract, Token ID and Quantity.
enum { MAX_REVIEW_PAIRS = 10 + CONTRACT_CALL_MAX_FIELDS, NFT_REVIEW_PAIRS = 13 };
_Static_assert(NFT_REVIEW_PAIRS <= MAX_REVIEW_PAIRS, "NFT review does not fit");
// NFT reviews borrow the contract argument buffers; the two flows are exclusive.
enum { NFT_VALUE_OWNER, NFT_VALUE_TOKEN_ID, NFT_VALUE_QUANTITY };
_Static_assert(CONTRACT_CALL_MAX_FIELDS > NFT_VALUE_QUANTITY &&
                   sizeof(g_contract_values[0]) > TX_FORMAT_MAX_DECIMAL_DIGITS &&
                   sizeof(g_contract_values[0]) >= sizeof(g_from_address),
               "NFT values do not fit the contract argument buffers");
_Static_assert(ADDRESS_SIZE == ADDRESS_LENGTH, "calldata addresses are full account addresses");
static nbgl_contentTagValue_t pairs[MAX_REVIEW_PAIRS];
static nbgl_contentTagValueList_t pairList;

static int abort_display(uint16_t status) {
    reset_request_context();
    ui_menu_main();
    return io_send_sw(status);
}

enum { APPROVAL_LIMITED, APPROVAL_REVOKE, APPROVAL_UNLIMITED };
typedef struct {
    const char *review;
    const char *confirmation;
} approval_titles_t;

static const approval_titles_t APPROVAL_TITLES[] = {
#ifdef TOKEN_METADATA_TEST_KEY
    [APPROVAL_LIMITED] = {"TEST token approval", "Approve token\nspending"},
    [APPROVAL_REVOKE] = {"TEST revoke approval", "Revoke token\napproval"},
    [APPROVAL_UNLIMITED] = {"TEST unlimited approval", "Approve unlimited\nspending"},
#else
    [APPROVAL_LIMITED] = {"Approve token spending", "Approve token\nspending"},
    [APPROVAL_REVOKE] = {"Revoke token approval", "Revoke token\napproval"},
    [APPROVAL_UNLIMITED] = {"Approve unlimited spending", "Approve unlimited\nspending"},
#endif
};

enum { NFT_SEND, NFT_APPROVE, NFT_REVOKE, NFT_APPROVE_ALL, NFT_REVOKE_ALL };
static const approval_titles_t NFT_TITLES[] = {
#ifdef TOKEN_METADATA_TEST_KEY
    [NFT_SEND] = {"TEST NFT transfer", "Send NFT"},
    [NFT_APPROVE] = {"TEST NFT approval", "Approve NFT"},
    [NFT_REVOKE] = {"TEST revoke NFT approval", "Revoke NFT\napproval"},
    [NFT_APPROVE_ALL] = {"TEST approve NFT collection", "Approve entire\nNFT collection"},
    [NFT_REVOKE_ALL] = {"TEST revoke NFT collection", "Revoke NFT\ncollection approval"},
#else
    [NFT_SEND] = {"Send NFT", "Send NFT"},
    [NFT_APPROVE] = {"Approve NFT", "Approve NFT"},
    [NFT_REVOKE] = {"Revoke NFT approval", "Revoke NFT\napproval"},
    [NFT_APPROVE_ALL] = {"Approve entire NFT collection", "Approve entire\nNFT collection"},
    [NFT_REVOKE_ALL] = {"Revoke NFT collection approval", "Revoke NFT\ncollection approval"},
#endif
};

static void bytes_to_lower_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hex[bytes[i] >> 4];
        out[2 * i + 1] = hex[bytes[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main.
    // The spinner belongs only on the signing path: showing "Signing" after the
    // user pressed Reject is misleading, and the frame is transient on that path
    // (rejection only sends SW_DENY), which made the screen count racy.
    if (confirm) {
        nbgl_useCaseSpinner("Signing");
        if (validate_transaction(true)) {
            nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
        } else {
            nbgl_useCaseStatus("Transaction signing failed", false, ui_menu_main);
        }
    } else {
        validate_transaction(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

void print_tx_utils(zond_tx_t *tx) {
    PRINTF("======== ZOND TX ========\n");
    PRINTF("Chain ID: 0x");
    for (int i = 0; i < tx->chain_id_len; i++) PRINTF("%02x", tx->chain_id[i]);
    PRINTF("\n");

    PRINTF("Nonce: 0x");
    for (int i = 0; i < tx->nonce_len; i++) PRINTF("%02x", tx->nonce[i]);
    PRINTF("\n");

    PRINTF("Gas Tip Cap: 0x");
    for (int i = 0; i < tx->gas_tip_cap_len; i++) PRINTF("%02x", tx->gas_tip_cap[i]);
    PRINTF("\n");

    PRINTF("Gas Fee Cap: 0x");
    for (int i = 0; i < tx->gas_fee_cap_len; i++) PRINTF("%02x", tx->gas_fee_cap[i]);
    PRINTF("\n");

    PRINTF("Gas: 0x");
    for (int i = 0; i < tx->gas_len; i++) PRINTF("%02x", tx->gas[i]);
    PRINTF("\n");

    PRINTF("To: 0x");
    for (int i = 0; i < tx->to_len; i++) PRINTF("%02x", tx->to[i]);
    PRINTF("\n");

    PRINTF("Value: 0x");
    for (int i = 0; i < tx->value_len; i++) PRINTF("%02x", tx->value[i]);
    PRINTF("\n");
    PRINTF("================\n");
}

// Public function to start the transaction review
// - Check if the app is in the right state for transaction review
// - Format the amount and address strings in g_amount and g_address buffers
// - Display the first screen of the transaction review
// - Display a warning if the transaction is blind-signed
int ui_display_transaction_bs_choice(bool is_blind_signed, zond_tx_t *tx) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        return abort_display(SW_BAD_STATE);
    }
    const bool is_contract_creation = (tx->to_len == 0);
    const bool is_contract = G_context.tx_info.contract_call;
    const contract_descriptor_t *descriptor = &G_context.tx_info.contract_descriptor;
    if (is_contract && (is_blind_signed || !contract_call_matches(tx, descriptor))) {
        return abort_display(SW_BAD_STATE);
    }
    const token_call_t *token = &G_context.tx_info.token_call;
    const token_metadata_t *metadata = &G_context.tx_info.token_metadata;
    const bool is_token = token->kind != TOKEN_CALL_NONE;
    const bool is_approval = token->kind == TOKEN_CALL_APPROVE;
    const bool is_unlimited = token_call_is_unlimited_approval(token);
    const bool is_revocation = token_call_is_approval_revocation(token);
    const nft_call_t *nft = &G_context.tx_info.nft_call;
    const nft_metadata_t *collection = &G_context.tx_info.nft_metadata;
    const bool is_nft = nft->kind != NFT_CALL_NONE;
    const bool is_nft_transfer = nft->kind == NFT_CALL_TRANSFER;
    // Clearing a single approval names no spender; revoking an operator still does.
    const bool is_nft_revocation = nft_call_is_approval_revocation(nft);
    if (is_nft && (is_blind_signed || is_token || is_contract || !collection->verified)) {
        return abort_display(SW_BAD_STATE);
    }
    const char *review_title = "Review transaction\n";
#ifdef SCREEN_SIZE_WALLET
    const char *confirmation_title = "Sign transaction\n";
#else
    const char *confirmation_title = NULL;
#endif
    if (is_approval) {
        size_t mode = APPROVAL_LIMITED;
        if (is_unlimited)
            mode = APPROVAL_UNLIMITED;
        else if (is_revocation)
            mode = APPROVAL_REVOKE;
        review_title = PIC(APPROVAL_TITLES[mode].review);
        confirmation_title = PIC(APPROVAL_TITLES[mode].confirmation);
    } else if (is_token) {
#ifdef TOKEN_METADATA_TEST_KEY
        review_title = "TEST token transfer";
#else
        review_title = "Send tokens";
#endif
    }

    if (is_nft) {
        size_t mode = NFT_SEND;
        if (nft->kind == NFT_CALL_APPROVE)
            mode = is_nft_revocation ? NFT_REVOKE : NFT_APPROVE;
        else if (nft->kind == NFT_CALL_APPROVE_ALL)
            mode = nft->approved ? NFT_APPROVE_ALL : NFT_REVOKE_ALL;
        review_title = PIC(NFT_TITLES[mode].review);
        confirmation_title = PIC(NFT_TITLES[mode].confirmation);
    }

    if (is_contract) {
#ifdef CONTRACT_DESCRIPTOR_TEST_KEY
        review_title = "TEST contract call";
#else
        review_title = "Review contract call";
#endif
        confirmation_title = "Sign contract call";
    }

    print_tx_utils(tx);

    PRINTF("DERIVE ADDRESS START\n");
    nbgl_useCaseSpinner("Getting address");
    cx_err_t error =
        address_from_bip32_path(G_context.bip32_path, G_context.bip32_path_len, G_context.address);
    if (error != CX_OK) {
        return abort_display(SW_DISPLAY_ADDRESS_FAIL);
    }
    PRINTF("DERIVE ADDRESS END\n");
    PRINTF("from ");
    for (int i = 0; i < ADDRESS_SIZE; i++) {
        PRINTF("%02x", G_context.address[i]);
    }
    PRINTF("\n");

    // Format from address
    memset(g_from_address, 0, sizeof(g_from_address));
    if (!format_checksummed_address(G_context.address, g_from_address, sizeof(g_from_address))) {
        return abort_display(SW_DISPLAY_ADDRESS_FAIL);
    }

    // Format amount
    char amount[TX_FORMAT_MAX_AMOUNT_LEN] = {0};
    if (is_unlimited) {
        memcpy(amount, "Unlimited", sizeof("Unlimited"));
    } else if (is_token) {
        char integer[TX_FORMAT_MAX_DECIMAL_DIGITS + 1];
        if (!uint8_array_to_decimal(token->amount,
                                    sizeof(token->amount),
                                    integer,
                                    sizeof(integer)) ||
            !format_with_decimals(integer, metadata->decimals, amount, sizeof(amount))) {
            return abort_display(SW_DISPLAY_AMOUNT_FAIL);
        }
    } else if (!format_qrl_amount(tx->value, tx->value_len, amount, sizeof(amount))) {
        return abort_display(SW_DISPLAY_AMOUNT_FAIL);
    }
    PRINTF("amount %s\n", amount);
    memset(g_amount, 0, sizeof(g_amount));
    snprintf(g_amount, sizeof(g_amount), "%s %s", is_token ? metadata->symbol : "QRL", amount);

    // An empty recipient creates a contract; it is not the zero address.
    memset(g_to_address, 0, sizeof(g_to_address));
    const uint8_t *to = is_token ? token->target : is_nft ? nft->target : tx->to;
    if (!is_contract_creation &&
        !format_checksummed_address(to, g_to_address, sizeof(g_to_address))) {
        return abort_display(SW_DISPLAY_ADDRESS_FAIL);
    }
    if ((is_token || is_nft) &&
        !format_checksummed_address(tx->to, g_token_contract, sizeof(g_token_contract))) {
        return abort_display(SW_DISPLAY_ADDRESS_FAIL);
    }
    PRINTF("to %s\n", g_to_address);

    // Format max_fees
    uint8_t fee_product[TX_FORMAT_MAX_INTEGER_BYTES];
    size_t fee_product_len = sizeof(fee_product);
    char max_fees[TX_FORMAT_MAX_AMOUNT_LEN] = {0};
    if (!multiply_uint8_arrays(tx->gas_fee_cap,
                               tx->gas_fee_cap_len,
                               tx->gas,
                               tx->gas_len,
                               fee_product,
                               &fee_product_len) ||
        !format_qrl_amount(fee_product, fee_product_len, max_fees, sizeof(max_fees)))
        return abort_display(SW_DISPLAY_AMOUNT_FAIL);
    PRINTF("max fees %s\n", max_fees);
    memset(g_max_fees, 0, sizeof(g_max_fees));
    snprintf(g_max_fees, sizeof(g_max_fees), "QRL %s", max_fees);

    // Setup data to display
    if (!uint8_array_to_decimal(tx->chain_id, tx->chain_id_len, g_chain_id, sizeof(g_chain_id)) ||
        !uint8_array_to_decimal(tx->gas, tx->gas_len, g_gas_limit, sizeof(g_gas_limit)) ||
        !format_qrl_amount(tx->gas_tip_cap, tx->gas_tip_cap_len, amount, sizeof(amount)))
        return abort_display(SW_DISPLAY_AMOUNT_FAIL);
    snprintf(g_gas_tip_cap, sizeof(g_gas_tip_cap), "QRL %s", amount);

    size_t count = 0;
#define ADD_PAIR(label, text)                   \
    do {                                        \
        if (count >= MAX_REVIEW_PAIRS) {        \
            return abort_display(SW_BAD_STATE); \
        }                                       \
        pairs[count].item = (label);            \
        pairs[count++].value = (text);          \
    } while (0)
    if (is_nft) {
        ADD_PAIR(is_nft_transfer ? "From" : "Owner", g_from_address);
        // An approved operator may move a token it does not hold itself.
        if (is_nft_transfer && memcmp(nft->owner, G_context.address, ADDRESS_SIZE) != 0) {
            if (!format_checksummed_address(nft->owner,
                                            g_contract_values[NFT_VALUE_OWNER],
                                            sizeof(g_contract_values[NFT_VALUE_OWNER])))
                return abort_display(SW_DISPLAY_ADDRESS_FAIL);
            ADD_PAIR("NFT owner", g_contract_values[NFT_VALUE_OWNER]);
        }
        if (is_nft_transfer) {
            ADD_PAIR("To", g_to_address);
        } else if (nft->kind == NFT_CALL_APPROVE_ALL) {
            ADD_PAIR("Operator", g_to_address);
        } else if (!is_nft_revocation) {
            ADD_PAIR("Spender", g_to_address);
        }
        ADD_PAIR("Collection", collection->name);
        ADD_PAIR("NFT contract", g_token_contract);
        if (nft->kind != NFT_CALL_APPROVE_ALL) {
            if (!uint8_array_to_decimal(nft->token_id,
                                        sizeof(nft->token_id),
                                        g_contract_values[NFT_VALUE_TOKEN_ID],
                                        sizeof(g_contract_values[NFT_VALUE_TOKEN_ID])))
                return abort_display(SW_DISPLAY_AMOUNT_FAIL);
            ADD_PAIR("Token ID", g_contract_values[NFT_VALUE_TOKEN_ID]);
        } else if (nft->approved) {
            ADD_PAIR("Access", "All NFTs in collection");
        }
        if (nft->has_quantity) {
            if (!uint8_array_to_decimal(nft->quantity,
                                        sizeof(nft->quantity),
                                        g_contract_values[NFT_VALUE_QUANTITY],
                                        sizeof(g_contract_values[NFT_VALUE_QUANTITY])))
                return abort_display(SW_DISPLAY_AMOUNT_FAIL);
            ADD_PAIR("Quantity", g_contract_values[NFT_VALUE_QUANTITY]);
        }
    } else {
        ADD_PAIR(is_approval ? "Owner" : "From", g_from_address);
        ADD_PAIR(is_approval ? "Spending limit" : "Amount", g_amount);
        if (is_contract_creation) {
            ADD_PAIR("Operation", "Create contract");
        } else {
            ADD_PAIR(is_approval ? "Spender" : "To", g_to_address);
        }
    }
    if (is_token) {
        ADD_PAIR("Token contract", g_token_contract);
    }
    if (is_contract) {
        ADD_PAIR("Operation", descriptor->operation);
        for (size_t i = 0; i < descriptor->field_count; i++) {
            const contract_field_t *field = &descriptor->fields[i];
            const uint8_t *word = tx->data + 4 + ADDRESS_LENGTH * i;
            char *value = g_contract_values[i];
            if (field->kind == CONTRACT_FIELD_ADDRESS) {
                if (!format_checksummed_address(word, value, sizeof(g_contract_values[i])))
                    return abort_display(SW_DISPLAY_ADDRESS_FAIL);
            } else if (field->kind == CONTRACT_FIELD_UINT256) {
                if (!uint8_array_to_decimal(word + ADDRESS_LENGTH - MAX_FIELD_SIZE,
                                            MAX_FIELD_SIZE,
                                            value,
                                            sizeof(g_contract_values[i])))
                    return abort_display(SW_DISPLAY_AMOUNT_FAIL);
            } else {
                strcpy(value, word[ADDRESS_LENGTH - 1] ? "true" : "false");
            }
#ifndef SCREEN_SIZE_WALLET
            // Nano truncates long titles, including their pagination suffix.
            // Keep a short device title and show the complete attested label in the value.
            const size_t label_len = strlen(field->label);
            const size_t value_len = strlen(value);
            if (label_len + 1 + value_len >= sizeof(g_contract_values[i]))
                return abort_display(SW_BAD_STATE);
            memmove(value + label_len + 1, value, value_len + 1);
            memcpy(value, field->label, label_len);
            value[label_len] = '\n';
            memcpy(g_contract_labels[i], "Arg 1", sizeof("Arg 1"));
            g_contract_labels[i][4] = (char) ('1' + i);
#else
            // Numbered labels cannot impersonate device fields such as From or Max fees.
            g_contract_labels[i][0] = (char) ('1' + i);
            g_contract_labels[i][1] = '.';
            g_contract_labels[i][2] = ' ';
            memcpy(g_contract_labels[i] + 3, field->label, sizeof(field->label));
#endif
            ADD_PAIR(g_contract_labels[i], value);
        }
    }
    ADD_PAIR("Chain ID", g_chain_id);
    ADD_PAIR("Gas limit", g_gas_limit);
    ADD_PAIR("Priority fee / gas", g_gas_tip_cap);
    ADD_PAIR("Max fees", g_max_fees);
    if (N_storage.display_nonce) {
        if (!uint8_array_to_decimal(tx->nonce, tx->nonce_len, g_nonce, sizeof(g_nonce)))
            return abort_display(SW_DISPLAY_AMOUNT_FAIL);
        ADD_PAIR("Nonce", g_nonce);
    }
    if (N_storage.display_tx_hash) {
        bytes_to_lower_hex(G_context.tx_info.m_hash, 32, g_tx_hash);
        ADD_PAIR("Transaction hash", g_tx_hash);
    }
#undef ADD_PAIR

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = count;
    pairList.pairs = pairs;

    if (is_blind_signed) {
        // Start blind-signing review flow
        nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                       &pairList,
                                       &ICON_APP_BOILERPLATE,
                                       "Review transaction\n",
                                       NULL,
#ifdef SCREEN_SIZE_WALLET
                                       "Sign transaction\n",
#else
                                       NULL,
#endif
                                       NULL,
                                       review_choice);
    } else {
        // Start review flow
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &pairList,
                           &ICON_APP_BOILERPLATE,
                           review_title,
                           NULL,
                           confirmation_title,
                           review_choice);
    }
    return 0;
}

// Flow used to display a clear-signed transaction
int ui_display_transaction(zond_tx_t *tx) {
    return ui_display_transaction_bs_choice(false, tx);
}
