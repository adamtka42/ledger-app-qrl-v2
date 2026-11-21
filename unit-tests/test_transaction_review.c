/* Real review and approval code, with faults in derivation/formatting/crypto.
 * Capture NBGL calls to ensure errors never leave a spinner or claim success. */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "os.h"
#include "globals.h"
#include "address.h"
#include "display.h"
#include "menu.h"
#include "nbgl_use_case.h"
#include "sign.h"
#include "sw.h"
#include "tx_format.h"

global_ctx_t G_context;
const internal_storage_t N_storage_real = {0};
const uint8_t C_app_qrl_64px = 0;
const uint8_t C_app_qrl_14px = 0;
static internal_storage_t storage;
typedef enum {
    NO_FAULT,
    DERIVE_FAIL,
    ADDRESS_FAIL,
    AMOUNT_FAIL,
    PRODUCT_FAIL,
    DECIMAL_FAIL,
    SIGN_FAIL,
    VERIFY_FAIL,
    VERIFY_INVALID
} fault_t;
static fault_t fault;
static unsigned fault_at, fault_calls, menu_calls, review_calls, sign_calls, nvm_writes;
static unsigned review_status_calls, status_calls;
static int review_status;
static uint16_t response;
static bool spinner, status_success;
static const char *status_text;
static void (*review_callback)(bool);
static const char *review_title, *review_finish;
static const nbgl_contentTagValueList_t *review_pairs;
static void (*status_callback)(void);

static bool fail_at(fault_t operation) {
    return fault == operation && ++fault_calls == fault_at;
}

/* Redirect persistent storage to the test copy; constants need no relocation here. */
void *test_pic(const void *address) {
    return address == (const void *) &N_storage_real ? (void *) &storage : (void *) address;
}

void nvm_write(void *destination, const void *source, size_t length) {
    const global_ctx_t zero = {0};
    assert_memory_equal(&G_context, &zero, sizeof(G_context));
    assert_ptr_equal(destination, &storage.is_sending_signature);
    assert_int_equal(length, 1);
    assert_int_equal(*(const uint8_t *) source, 0);
    memcpy(destination, source, length);
    nvm_writes++;
}

int io_send_sw(uint16_t status) {
    response = status;
    return 0;
}

void ui_menu_main(void) {
    spinner = false;
    menu_calls++;
}

void nbgl_useCaseSpinner(const char *text) {
    assert_non_null(text);
    spinner = true;
}

void nbgl_useCaseReview(int type,
                        const nbgl_contentTagValueList_t *pairs,
                        const void *icon,
                        const char *title,
                        const char *subtitle,
                        const char *finish,
                        void (*choice)(bool)) {
    (void) icon;
    (void) subtitle;
    review_title = title;
    review_finish = finish;
    review_pairs = pairs;
    assert_int_equal(type, TYPE_TRANSACTION);
    if (G_context.tx_info.nft_call.kind == NFT_CALL_NONE)
        assert_int_equal(pairs->nbPairs, G_context.tx_info.contract_call ? 13 : 9);
    if (G_context.tx_info.contract_call) {
        assert_string_equal(title, "Review contract call");
        assert_string_equal(finish, "Sign contract call");
        assert_string_equal(pairs->pairs[1].value, "QRL 0");
        assert_string_equal(pairs->pairs[3].item, "Operation");
        assert_string_equal(pairs->pairs[3].value, "Configure account");
#ifdef SCREEN_SIZE_WALLET
        assert_string_equal(pairs->pairs[4].item, "1. Owner");
        assert_string_equal(pairs->pairs[5].item, "2. IntegerField");
        assert_string_equal(
            pairs->pairs[5].value,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935");
        assert_string_equal(pairs->pairs[6].item, "3. Enabled");
        assert_string_equal(pairs->pairs[6].value, "true");
#else
        assert_string_equal(pairs->pairs[4].item, "Arg 1");
        assert_memory_equal(pairs->pairs[4].value, "Owner\nQ", 7);
        assert_string_equal(pairs->pairs[5].item, "Arg 2");
        assert_string_equal(pairs->pairs[5].value,
                            "IntegerField\n11579208923731619542357098500868790785326998466564056403"
                            "9457584007913129639935");
        assert_string_equal(pairs->pairs[6].item, "Arg 3");
        assert_string_equal(pairs->pairs[6].value, "Enabled\ntrue");
#endif
        assert_string_equal(pairs->pairs[11].item, "Nonce");
        assert_string_equal(pairs->pairs[12].item, "Transaction hash");
    }
    assert_non_null(pairs->pairs);
    spinner = false;
    review_callback = choice;
    review_calls++;
}

void nbgl_useCaseReviewBlindSigning(int type,
                                    const nbgl_contentTagValueList_t *pairs,
                                    const void *icon,
                                    const char *title,
                                    const char *subtitle,
                                    const char *finish,
                                    const void *warning,
                                    void (*choice)(bool)) {
    (void) warning;
    nbgl_useCaseReview(type, pairs, icon, title, subtitle, finish, choice);
}

void nbgl_useCaseReviewStatus(int status, void (*done)(void)) {
    spinner = false;
    review_status = status;
    review_status_calls++;
    status_callback = done;
}

void nbgl_useCaseStatus(const char *text, bool success, void (*done)(void)) {
    spinner = false;
    status_text = text;
    status_success = success;
    status_calls++;
    status_callback = done;
}

cx_err_t address_from_bip32_path(const uint32_t path[],
                                 size_t path_len,
                                 uint8_t address[ADDRESS_SIZE]) {
    assert_ptr_equal(path, G_context.bip32_path);
    assert_int_equal(path_len, 5);
    if (fail_at(DERIVE_FAIL)) return CX_INTERNAL_ERROR;
    memset(address, 0x11, ADDRESS_SIZE);
    return CX_OK;
}

bool __real_format_checksummed_address(const uint8_t *, char *, size_t);
bool __wrap_format_checksummed_address(const uint8_t *bytes, char *out, size_t size) {
    return !fail_at(ADDRESS_FAIL) && __real_format_checksummed_address(bytes, out, size);
}

bool __real_format_qrl_amount(const uint8_t *, size_t, char *, size_t);
bool __wrap_format_qrl_amount(const uint8_t *bytes, size_t length, char *out, size_t size) {
    return !fail_at(AMOUNT_FAIL) && __real_format_qrl_amount(bytes, length, out, size);
}

bool __real_multiply_uint8_arrays(const uint8_t *,
                                  size_t,
                                  const uint8_t *,
                                  size_t,
                                  uint8_t *,
                                  size_t *);
bool __wrap_multiply_uint8_arrays(const uint8_t *a,
                                  size_t a_len,
                                  const uint8_t *b,
                                  size_t b_len,
                                  uint8_t *out,
                                  size_t *size) {
    return !fail_at(PRODUCT_FAIL) && __real_multiply_uint8_arrays(a, a_len, b, b_len, out, size);
}

bool __real_uint8_array_to_decimal(const uint8_t *, size_t, char *, size_t);
bool __wrap_uint8_array_to_decimal(const uint8_t *bytes, size_t length, char *out, size_t size) {
    return !fail_at(DECIMAL_FAIL) && __real_uint8_array_to_decimal(bytes, length, out, size);
}

ErrorCode crypto_sign_optimized(const uint32_t path[],
                                size_t path_len,
                                uint8_t *message,
                                size_t length) {
    (void) path;
    (void) path_len;
    (void) message;
    (void) length;
    sign_calls++;
    return fault == SIGN_FAIL ? ERR_INVALID_SIGNATURE : ERR_NONE;
}

ErrorCode crypto_verify_optimized(const uint32_t path[],
                                  size_t path_len,
                                  uint8_t *signature,
                                  size_t signature_len,
                                  uint8_t *message,
                                  size_t message_len,
                                  bool *verified) {
    (void) path;
    (void) path_len;
    (void) signature;
    (void) signature_len;
    (void) message;
    (void) message_len;
    *verified = fault != VERIFY_INVALID;
    return fault == VERIFY_FAIL ? ERR_INVALID_SIGNATURE : ERR_NONE;
}

void wipe_nvm_secrets(void) {
}

int helper_send_response_address(void) {
    fail_msg("Unexpected address export");
    return -1;
}

int helper_send_response_sig(uint8_t index) {
    assert_int_equal(index, 0);
    assert_int_equal(G_context.state, STATE_APPROVED);
    storage.is_sending_signature = 1;
    return io_send_sw(SW_OK);
}

static void start_session(fault_t operation, unsigned occurrence) {
    memset(&G_context, 0, sizeof(G_context));
    G_context.req_type = CONFIRM_TRANSACTION;
    G_context.state = STATE_PARSED;
    G_context.bip32_path_len = 5;
    zond_tx_t *tx = &G_context.tx_info.tx_data;
    tx->to_len = ADDRESS_SIZE;
    memset(tx->to, 0x22, ADDRESS_SIZE);
    tx->chain_id_len = tx->nonce_len = tx->gas_len = tx->value_len = 1;
    tx->gas_fee_cap_len = tx->gas_tip_cap_len = 1;
    tx->chain_id[0] = tx->nonce[0] = tx->gas[0] = tx->value[0] = 1;
    tx->gas_fee_cap[0] = tx->gas_tip_cap[0] = 1;
    memset(&storage, 0, sizeof(storage));
    storage.is_sending_signature = storage.display_nonce = storage.display_tx_hash = 1;
    fault = operation;
    fault_at = occurrence;
    fault_calls = menu_calls = review_calls = sign_calls = nvm_writes = 0;
    review_status_calls = status_calls = 0;
    response = 0;
    spinner = status_success = false;
    status_text = NULL;
    review_callback = NULL;
    status_callback = NULL;
}

static void assert_discarded(uint16_t expected) {
    const global_ctx_t zero = {0};
    assert_memory_equal(&G_context, &zero, sizeof(G_context));
    assert_int_equal(storage.is_sending_signature, 0);
    assert_int_equal(nvm_writes, 1);
    assert_int_equal(response, expected);
    assert_false(spinner);
}

static void test_preparation_failure_returns_home(void **state) {
    (void) state;
    const struct {
        fault_t operation;
        unsigned occurrence;
        uint16_t status;
    } cases[] = {
        {DERIVE_FAIL, 1, SW_DISPLAY_ADDRESS_FAIL},
        {ADDRESS_FAIL, 1, SW_DISPLAY_ADDRESS_FAIL},
        {ADDRESS_FAIL, 2, SW_DISPLAY_ADDRESS_FAIL},
        {AMOUNT_FAIL, 1, SW_DISPLAY_AMOUNT_FAIL},
        {AMOUNT_FAIL, 2, SW_DISPLAY_AMOUNT_FAIL},
        {AMOUNT_FAIL, 3, SW_DISPLAY_AMOUNT_FAIL},
        {PRODUCT_FAIL, 1, SW_DISPLAY_AMOUNT_FAIL},
        {DECIMAL_FAIL, 1, SW_DISPLAY_AMOUNT_FAIL},
        {DECIMAL_FAIL, 2, SW_DISPLAY_AMOUNT_FAIL},
        {DECIMAL_FAIL, 3, SW_DISPLAY_AMOUNT_FAIL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        start_session(cases[i].operation, cases[i].occurrence);
        ui_display_transaction_bs_choice(false, &G_context.tx_info.tx_data);
        assert_discarded(cases[i].status);
        assert_int_equal(menu_calls, 1);
        assert_int_equal(review_calls, 0);
        assert_int_equal(sign_calls, 0);
    }
}

static void test_invalid_review_state_returns_home(void **state) {
    (void) state;
    start_session(NO_FAULT, 0);
    G_context.state = STATE_RECEIVING;
    ui_display_transaction_bs_choice(false, &G_context.tx_info.tx_data);
    assert_discarded(SW_BAD_STATE);
    assert_int_equal(menu_calls, 1);
    assert_int_equal(review_calls, 0);
}

static void test_review_status_matches_signature_result(void **state) {
    (void) state;
    const fault_t cases[] = {NO_FAULT, SIGN_FAIL, VERIFY_FAIL, VERIFY_INVALID};
    for (unsigned blind = 0; blind < 2; blind++) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            start_session(cases[i], 0);
            ui_display_transaction_bs_choice(blind != 0, &G_context.tx_info.tx_data);
            assert_non_null(review_callback);
            review_callback(true);
            assert_int_equal(sign_calls, 1);
            assert_int_equal(menu_calls, 0);
            assert_false(spinner);
            if (cases[i] == NO_FAULT) {
                assert_int_equal(response, SW_OK);
                assert_int_equal(review_status_calls, 1);
                assert_int_equal(review_status, STATUS_TYPE_TRANSACTION_SIGNED);
                assert_int_equal(status_calls, 0);
            } else {
                assert_discarded(SW_SIGNATURE_FAIL);
                assert_int_equal(review_status_calls, 0);
                assert_int_equal(status_calls, 1);
                assert_false(status_success);
                assert_string_equal(status_text, "Transaction signing failed");
            }
            assert_ptr_equal(status_callback, ui_menu_main);
            status_callback();
            assert_int_equal(menu_calls, 1);
        }
    }
}

static void test_rejection_status(void **state) {
    (void) state;
    for (unsigned blind = 0; blind < 2; blind++) {
        start_session(NO_FAULT, 0);
        ui_display_transaction_bs_choice(blind != 0, &G_context.tx_info.tx_data);
        assert_non_null(review_callback);
        review_callback(false);
        assert_discarded(SW_DENY);
        assert_int_equal(sign_calls, 0);
        assert_int_equal(review_status_calls, 1);
        assert_int_equal(review_status, STATUS_TYPE_TRANSACTION_REJECTED);
        assert_int_equal(status_calls, 0);
    }
}

static void test_contract_review_capacity_and_validation(void **state) {
    (void) state;
    for (unsigned invalid = 0; invalid < 2; invalid++) {
        start_session(NO_FAULT, 0);
        zond_tx_t *tx = &G_context.tx_info.tx_data;
        tx->value_len = 0;
        tx->has_data = true;
        tx->data_len = 196;
        memset(tx->data, 0x12, 4);
        memset(tx->data + 4, 0x11, 64);
        memset(tx->data + 100, 0xff, 32);
        tx->data[195] = invalid ? 2 : 1;
        contract_descriptor_t *d = &G_context.tx_info.contract_descriptor;
        d->verified = true;
        d->field_count = 3;
        d->chain_id[31] = 1;
        memcpy(d->contract, tx->to, ADDRESS_LENGTH);
        memcpy(d->selector, tx->data, 4);
        strcpy(d->operation, "Configure account");
        d->fields[0].kind = CONTRACT_FIELD_ADDRESS;
        d->fields[1].kind = CONTRACT_FIELD_UINT256;
        d->fields[2].kind = CONTRACT_FIELD_BOOL;
        strcpy(d->fields[0].label, "Owner");
        strcpy(d->fields[1].label, "IntegerField");
        strcpy(d->fields[2].label, "Enabled");
        G_context.tx_info.contract_call = true;
        ui_display_transaction_bs_choice(false, tx);
        if (invalid) {
            assert_discarded(SW_BAD_STATE);
            assert_int_equal(menu_calls, 1);
            assert_int_equal(review_calls, 0);
        } else {
            assert_int_equal(review_calls, 1);
            assert_non_null(review_callback);
        }
    }
}

static void start_nft_session(nft_call_kind_e kind) {
    start_session(NO_FAULT, 0);
    zond_tx_t *tx = &G_context.tx_info.tx_data;
    tx->value_len = 0;
    tx->has_data = true;
    nft_metadata_t *collection = &G_context.tx_info.nft_metadata;
    collection->verified = true;
    strcpy(collection->name, "Quantum Cats");
    nft_call_t *call = &G_context.tx_info.nft_call;
    call->kind = kind;
    memset(call->owner, 0x11, ADDRESS_LENGTH);  // the signer derived by the mock
    memset(call->target, 0x33, ADDRESS_LENGTH);
    call->token_id[MAX_FIELD_SIZE - 1] = 42;
}

static void assert_pair(size_t index, const char *item, const char *value) {
    assert_true(index < review_pairs->nbPairs);
    assert_string_equal(review_pairs->pairs[index].item, item);
    if (value != NULL) assert_string_equal(review_pairs->pairs[index].value, value);
}

static void test_nft_transfer_review(void **state) {
    (void) state;
    zond_tx_t *tx = &G_context.tx_info.tx_data;

    start_nft_session(NFT_CALL_TRANSFER);
    ui_display_transaction_bs_choice(false, tx);
    assert_int_equal(review_calls, 1);
    assert_string_equal(review_title, "Send NFT");
    assert_string_equal(review_finish, "Send NFT");
    assert_int_equal(review_pairs->nbPairs, 11);
    assert_pair(0, "From", NULL);
    assert_pair(1, "To", NULL);
    assert_int_equal(review_pairs->pairs[1].value[1], '3');
    assert_pair(2, "Collection", "Quantum Cats");
    assert_pair(3, "NFT contract", NULL);
    assert_int_equal(review_pairs->pairs[3].value[1], '2');
    assert_pair(4, "Token ID", "42");
    assert_pair(5, "Chain ID", "1");

    // An operator moving someone else's tokens, with a quantity: the largest review.
    start_nft_session(NFT_CALL_TRANSFER);
    nft_call_t *call = &G_context.tx_info.nft_call;
    memset(call->owner, 0x44, ADDRESS_LENGTH);
    memset(call->token_id, 0xff, MAX_FIELD_SIZE);
    call->has_quantity = true;
    call->quantity[MAX_FIELD_SIZE - 1] = 5;
    ui_display_transaction_bs_choice(false, tx);
    assert_int_equal(review_calls, 1);
    assert_int_equal(review_pairs->nbPairs, 13);
    assert_pair(0, "From", NULL);
    assert_pair(1, "NFT owner", NULL);
    assert_int_equal(review_pairs->pairs[1].value[1], '4');
    assert_pair(2, "To", NULL);
    assert_pair(5,
                "Token ID",
                "115792089237316195423570985008687907853269984665640564039457584007913129639935");
    assert_pair(6, "Quantity", "5");
    assert_pair(12, "Transaction hash", NULL);
}

static void test_nft_approval_reviews(void **state) {
    (void) state;
    zond_tx_t *tx = &G_context.tx_info.tx_data;

    start_nft_session(NFT_CALL_APPROVE);
    ui_display_transaction_bs_choice(false, tx);
    assert_string_equal(review_title, "Approve NFT");
    assert_int_equal(review_pairs->nbPairs, 11);
    assert_pair(0, "From", NULL);  // an approved operator may sign this too
    assert_pair(1, "Spender", NULL);
    assert_pair(2, "Collection", "Quantum Cats");
    assert_pair(4, "Token ID", "42");

    start_nft_session(NFT_CALL_APPROVE);
    memset(G_context.tx_info.nft_call.target, 0, ADDRESS_LENGTH);
    ui_display_transaction_bs_choice(false, tx);
    assert_string_equal(review_title, "Revoke NFT approval");
    assert_int_equal(review_pairs->nbPairs, 10);
    assert_pair(0, "From", NULL);
    assert_pair(1, "Collection", "Quantum Cats");
    assert_pair(3, "Token ID", "42");

    start_nft_session(NFT_CALL_APPROVE_ALL);
    G_context.tx_info.nft_call.approved = true;
    ui_display_transaction_bs_choice(false, tx);
    assert_string_equal(review_title, "Approve entire NFT collection");
    assert_int_equal(review_pairs->nbPairs, 11);
    assert_pair(0, "Owner", NULL);
    assert_pair(1, "Operator", NULL);
    assert_pair(4, "Access", "All NFTs in collection");

    start_nft_session(NFT_CALL_APPROVE_ALL);
    ui_display_transaction_bs_choice(false, tx);
    assert_string_equal(review_title, "Revoke NFT collection approval");
    assert_int_equal(review_pairs->nbPairs, 10);
    assert_pair(0, "Owner", NULL);
    assert_pair(1, "Operator", NULL);
    assert_pair(4, "Chain ID", "1");
}

static void test_nft_review_requires_consistent_session(void **state) {
    (void) state;
    zond_tx_t *tx = &G_context.tx_info.tx_data;
    for (int mutation = 0; mutation < 4; mutation++) {
        start_nft_session(NFT_CALL_TRANSFER);
        if (mutation == 0) G_context.tx_info.nft_metadata.verified = false;
        if (mutation == 1) G_context.tx_info.token_call.kind = TOKEN_CALL_TRANSFER;
        if (mutation == 2) G_context.tx_info.contract_call = true;
        ui_display_transaction_bs_choice(mutation == 3, tx);
        assert_discarded(SW_BAD_STATE);
        assert_int_equal(menu_calls, 1);
        assert_int_equal(review_calls, 0);
    }
    // A failure while formatting NFT fields never leaves a review on screen.
    const struct {
        fault_t operation;
        unsigned occurrence;
        uint16_t status;
    } faults[] = {
        {ADDRESS_FAIL, 3, SW_DISPLAY_ADDRESS_FAIL},  // NFT contract
        {ADDRESS_FAIL, 4, SW_DISPLAY_ADDRESS_FAIL},  // NFT owner
        {DECIMAL_FAIL, 3, SW_DISPLAY_AMOUNT_FAIL},   // token ID
        {DECIMAL_FAIL, 4, SW_DISPLAY_AMOUNT_FAIL},   // quantity
    };
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++) {
        start_nft_session(NFT_CALL_TRANSFER);
        memset(G_context.tx_info.nft_call.owner, 0x44, ADDRESS_LENGTH);
        G_context.tx_info.nft_call.has_quantity = true;
        G_context.tx_info.nft_call.quantity[0] = 1;
        fault = faults[i].operation;
        fault_at = faults[i].occurrence;
        ui_display_transaction_bs_choice(false, tx);
        assert_discarded(faults[i].status);
        assert_int_equal(review_calls, 0);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_preparation_failure_returns_home),
        cmocka_unit_test(test_invalid_review_state_returns_home),
        cmocka_unit_test(test_review_status_matches_signature_result),
        cmocka_unit_test(test_rejection_status),
        cmocka_unit_test(test_contract_review_capacity_and_validation),
        cmocka_unit_test(test_nft_transfer_review),
        cmocka_unit_test(test_nft_approval_reviews),
        cmocka_unit_test(test_nft_review_requires_consistent_session),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
