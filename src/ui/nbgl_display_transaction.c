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

// "Q", the address in hex and a NUL.
#define ADDRESS_TEXT_SIZE (1 + ADDRESS_SIZE * 2 + 1)

static char g_from_address[ADDRESS_TEXT_SIZE];
static char g_amount[TX_FORMAT_MAX_AMOUNT_LEN + TOKEN_SYMBOL_MAX + 2];
static char g_to_address[ADDRESS_TEXT_SIZE];
static char g_token_contract[ADDRESS_TEXT_SIZE];
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
#ifdef HAVE_STAKING_DEPOSIT
// Native fields plus Operation, Validator key root, Withdraw to, RANDAO and Deposit data root.
enum { MAX_REVIEW_PAIRS = 14 };
#else
enum { MAX_REVIEW_PAIRS = 10 + CONTRACT_CALL_MAX_FIELDS };
#endif
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

static size_t approval_mode(const token_call_t *token) {
    if (token_call_is_unlimited_approval(token)) return APPROVAL_UNLIMITED;
    if (token_call_is_approval_revocation(token)) return APPROVAL_REVOKE;
    return APPROVAL_LIMITED;
}

static void bytes_to_lower_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hex[bytes[i] >> 4];
        out[2 * i + 1] = hex[bytes[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

#ifdef HAVE_STAKING_DEPOSIT
// The deposit fields a staking review shows. They borrow the contract and token
// buffers, which belong to mutually exclusive review modes.
enum { STAKING_VALUE_KEY_ROOT, STAKING_VALUE_WITHDRAWAL, STAKING_VALUE_RANDAO };
_Static_assert(CONTRACT_CALL_MAX_FIELDS > STAKING_VALUE_RANDAO,
               "staking values do not fit the contract argument buffers");

static uint16_t format_staking_values(const staking_deposit_t *deposit) {
    bytes_to_lower_hex(deposit->pubkey_root, 32, g_contract_values[STAKING_VALUE_KEY_ROOT]);
    if (!format_checksummed_address(deposit->withdrawal,
                                    g_contract_values[STAKING_VALUE_WITHDRAWAL],
                                    sizeof(g_contract_values[STAKING_VALUE_WITHDRAWAL])))
        return SW_DISPLAY_ADDRESS_FAIL;
    bytes_to_lower_hex(deposit->randao, 32, g_contract_values[STAKING_VALUE_RANDAO]);
    bytes_to_lower_hex(deposit->expected_root, 32, g_token_contract);
    return SW_OK;
}
#endif

// The token amount, scaled by the decimals of its signed metadata. An unlimited
// approval has no amount worth scaling.
static bool format_token_amount(const token_call_t *token,
                                const token_metadata_t *metadata,
                                char *out,
                                size_t size) {
    if (token_call_is_unlimited_approval(token)) {
        static const char unlimited[] = "Unlimited";
        if (size < sizeof(unlimited)) return false;
        memcpy(out, unlimited, sizeof(unlimited));
        return true;
    }
    char integer[TX_FORMAT_MAX_DECIMAL_DIGITS + 1];
    return uint8_array_to_decimal(token->amount, sizeof(token->amount), integer, sizeof(integer)) &&
           format_with_decimals(integer, metadata->decimals, out, size);
}

// Argument i of a described contract call, typed as its descriptor says, with
// its label in g_contract_labels[i] and its value in g_contract_values[i].
static uint16_t format_contract_argument(const zond_tx_t *tx,
                                         const contract_descriptor_t *descriptor,
                                         size_t i) {
    const contract_field_t *field = &descriptor->fields[i];
    const uint8_t *word = abi_arg(tx->data, i);
    char *value = g_contract_values[i];
    const size_t size = sizeof(g_contract_values[i]);
    if (field->kind == CONTRACT_FIELD_ADDRESS) {
        if (!format_checksummed_address(word, value, size)) return SW_DISPLAY_ADDRESS_FAIL;
    } else if (field->kind == CONTRACT_FIELD_UINT256) {
        if (!uint8_array_to_decimal(word + ABI_UINT256_OFFSET, MAX_FIELD_SIZE, value, size))
            return SW_DISPLAY_AMOUNT_FAIL;
    } else {
        strcpy(value, word[ABI_WORD_LEN - 1] ? "true" : "false");
    }
#ifndef SCREEN_SIZE_WALLET
    // Nano truncates long titles, including their pagination suffix.
    // Keep a short device title and show the complete attested label in the value.
    const size_t label_len = strlen(field->label);
    const size_t value_len = strlen(value);
    if (label_len + 1 + value_len >= size) return SW_BAD_STATE;
    memmove(value + label_len + 1, value, value_len + 1);
    memcpy(value, field->label, label_len);
    value[label_len] = '\n';
    snprintf(g_contract_labels[i], sizeof(g_contract_labels[i]), "Arg %u", (unsigned) (i + 1));
#else
    // Numbered labels cannot impersonate device fields such as From or Max fees.
    snprintf(g_contract_labels[i],
             sizeof(g_contract_labels[i]),
             "%u. %s",
             (unsigned) (i + 1),
             field->label);
#endif
    return SW_OK;
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
// - Format the amount and address strings in g_amount and g_to_address
// - Display the first screen of the transaction review
// - Display a warning if the transaction is blind-signed
int ui_display_transaction_bs_choice(bool is_blind_signed, zond_tx_t *tx) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        return abort_display(SW_BAD_STATE);
    }
#ifdef HAVE_STAKING_DEPOSIT
    const bool is_staking = G_context.tx_info.staking_call;
    const staking_deposit_t *deposit = &G_context.tx_info.staking;
    if (is_staking && (is_blind_signed || !staking_deposit_is_target(tx) ||
                       !staking_deposit_validate(deposit, tx)))
        return abort_display(SW_BAD_STATE);
#else
    const bool is_staking = false;
#endif
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
    const char *review_title = "Review transaction\n";
#ifdef SCREEN_SIZE_WALLET
    const char *confirmation_title = "Sign transaction\n";
#else
    const char *confirmation_title = NULL;
#endif
    if (is_approval) {
        const size_t mode = approval_mode(token);
        review_title = PIC(APPROVAL_TITLES[mode].review);
        confirmation_title = PIC(APPROVAL_TITLES[mode].confirmation);
    } else if (is_token) {
#ifdef TOKEN_METADATA_TEST_KEY
        review_title = "TEST token transfer";
#else
        review_title = "Send tokens";
#endif
    }

    if (is_contract) {
#ifdef CONTRACT_DESCRIPTOR_TEST_KEY
        review_title = "TEST contract call";
#else
        review_title = "Review contract call";
#endif
        confirmation_title = "Sign contract call";
    }

    if (is_staking) {
#ifdef STAKING_DEPOSIT_TEST_PROFILE
        review_title = "TEST staking deposit";
#else
        review_title = "Stake QRL";
#endif
        confirmation_title = "Sign staking deposit";
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
    const bool amount_ok =
        is_token ? format_token_amount(token, metadata, amount, sizeof(amount))
                 : format_qrl_amount(tx->value, tx->value_len, amount, sizeof(amount));
    if (!amount_ok) return abort_display(SW_DISPLAY_AMOUNT_FAIL);
    PRINTF("amount %s\n", amount);
    memset(g_amount, 0, sizeof(g_amount));
    snprintf(g_amount,
             sizeof(g_amount),
             "%s %s",
             is_token ? metadata->symbol : TOKEN_NATIVE_TICKER,
             amount);

    // An empty recipient creates a contract; it is not the zero address.
    memset(g_to_address, 0, sizeof(g_to_address));
    if (!is_contract_creation && !format_checksummed_address(is_token ? token->target : tx->to,
                                                             g_to_address,
                                                             sizeof(g_to_address))) {
        return abort_display(SW_DISPLAY_ADDRESS_FAIL);
    }
    if (is_token &&
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
    ADD_PAIR(is_approval ? "Owner" : "From", g_from_address);
    ADD_PAIR(is_approval ? "Spending limit" : "Amount", g_amount);
    if (is_contract_creation) {
        ADD_PAIR("Operation", "Create contract");
    } else {
#ifdef SCREEN_SIZE_WALLET
        const char *deposit_label = "Deposit contract";
#else
        const char *deposit_label = "Contract";
#endif
        ADD_PAIR(is_staking ? deposit_label : is_approval ? "Spender" : "To", g_to_address);
    }
    if (is_token) {
#ifdef SCREEN_SIZE_WALLET
        ADD_PAIR("Token contract", g_token_contract);
#else
        // Nano cuts the middle out of the longer title once a page counter is added.
        ADD_PAIR("Contract", g_token_contract);
#endif
    }
    if (is_contract) {
        ADD_PAIR("Operation", descriptor->operation);
        for (size_t i = 0; i < descriptor->field_count; i++) {
            const uint16_t sw = format_contract_argument(tx, descriptor, i);
            if (sw != SW_OK) return abort_display(sw);
            ADD_PAIR(g_contract_labels[i], g_contract_values[i]);
        }
    }
#ifdef HAVE_STAKING_DEPOSIT
    if (is_staking) {
        const uint16_t sw = format_staking_values(deposit);
        if (sw != SW_OK) return abort_display(sw);
        ADD_PAIR("Operation", "Stake QRL");
#ifdef SCREEN_SIZE_WALLET
        ADD_PAIR("Validator key root", g_contract_values[STAKING_VALUE_KEY_ROOT]);
#else
        ADD_PAIR("Validator root", g_contract_values[STAKING_VALUE_KEY_ROOT]);
#endif
        ADD_PAIR("Withdraw to", g_contract_values[STAKING_VALUE_WITHDRAWAL]);
#ifdef SCREEN_SIZE_WALLET
        ADD_PAIR("RANDAO commitment", g_contract_values[STAKING_VALUE_RANDAO]);
        ADD_PAIR("Deposit data root", g_token_contract);
#else
        ADD_PAIR("RANDAO", g_contract_values[STAKING_VALUE_RANDAO]);
        ADD_PAIR("Deposit root", g_token_contract);
#endif
    }
#endif
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
