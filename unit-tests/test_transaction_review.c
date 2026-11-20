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
#include "tx_stream.h"
#include <stdio.h>

/* The same file also builds without staking, covering the default firmware. */
#ifdef HAVE_STAKING_DEPOSIT
#include "staking_hash.h"
#define STAKING_CALL (G_context.tx_info.staking_call)
#else
#define STAKING_CALL false
#endif

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
static void (*status_callback)(void);

static bool fail_at(fault_t operation) {
    return fault == operation && ++fault_calls == fault_at;
}

void *test_pic(const void *address) {
    assert_ptr_equal(address, &N_storage_real);
    return &storage;
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
    (void) title;
    (void) subtitle;
    (void) finish;
    assert_int_equal(type, TYPE_TRANSACTION);
    assert_int_equal(pairs->nbPairs, STAKING_CALL ? 14 : G_context.tx_info.contract_call ? 13 : 9);
    if (STAKING_CALL) {
        assert_string_equal(title, "Stake QRL");
        assert_string_equal(finish, "Sign staking deposit");
        assert_string_equal(pairs->pairs[1].value, "QRL 40000");
#ifdef SCREEN_SIZE_WALLET
        assert_string_equal(pairs->pairs[2].item, "Deposit contract");
#else
        assert_string_equal(pairs->pairs[2].item, "Contract");
#endif
        assert_string_equal(pairs->pairs[3].value, "Stake QRL");
#ifdef SCREEN_SIZE_WALLET
        assert_string_equal(pairs->pairs[4].item, "Validator key root");
#else
        assert_string_equal(pairs->pairs[4].item, "Validator root");
#endif
        assert_string_equal(pairs->pairs[5].item, "Withdraw to");
        /* Fixed expectations from the independent go-qrl depositroot vector;
         * do not derive them from the decoder buffers being reviewed. */
        assert_string_equal(pairs->pairs[4].value,
                            "f323c59c3d728d8f33462aa1fa3df4298e68ad9f05b470909b099da2e078304c");
        assert_string_equal(pairs->pairs[5].value,
                            "QAcA815d956C82Bca26916e21621d6d054C7C5748F622b1192577Beb208b7b1E4"
                            "F64106cc801ED333EA7C4Eb1d074d498070c98B64cA6C9274C60b95649E0a3a6");
        assert_string_equal(pairs->pairs[6].value,
                            "893c4612b107746836b9c4419f8a899d1aaa9ff50d0653170014382c9e47e345");
#ifdef SCREEN_SIZE_WALLET
        assert_string_equal(pairs->pairs[6].item, "RANDAO commitment");
        assert_string_equal(pairs->pairs[7].item, "Deposit data root");
#else
        assert_string_equal(pairs->pairs[6].item, "RANDAO");
        assert_string_equal(pairs->pairs[7].item, "Deposit root");
#endif
        assert_string_equal(pairs->pairs[7].value,
                            "9130e8f540b6a58a24da8b51e8661a2fbe937234490e7d59a6e2bbb99a3872e8");
        assert_string_equal(pairs->pairs[13].item, "Transaction hash");
    }
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

#ifdef HAVE_STAKING_DEPOSIT
static void observe_deposit(void *context,
                            uint32_t offset,
                            uint32_t total,
                            const uint8_t *data,
                            size_t len) {
    staking_deposit_feed(context, offset, total, data, len);
}

static void test_staking_review_capacity_and_guard(void **unused) {
    (void) unused;
    uint8_t preimage[8300];
    FILE *file = fopen(STAKING_PREIMAGE, "rb");
    assert_non_null(file);
    size_t len = fread(preimage, 1, sizeof(preimage), file);
    fclose(file);
    for (unsigned corrupt = 0; corrupt < 2; corrupt++) {
        start_session(NO_FAULT, 0);
        transaction_ctx_t *session = &G_context.tx_info;
        tx_stream_init(&session->stream, &session->tx_data);
        staking_deposit_init(&session->staking, test_staking_hash);
        session->stream.on_data = observe_deposit;
        session->stream.observer_context = &session->staking;
        assert_int_equal(tx_stream_feed(&session->stream, &session->tx_data, preimage, len),
                         TX_STREAM_FINISHED);
        session->staking_call = true;
        if (corrupt) session->staking.expected_root[0] ^= 1;
        ui_display_transaction_bs_choice(false, &session->tx_data);
        if (corrupt) {
            assert_discarded(SW_BAD_STATE);
            assert_int_equal(menu_calls, 1);
            assert_int_equal(review_calls, 0);
        } else {
            assert_int_equal(review_calls, 1);
            review_callback(false);
            assert_discarded(SW_DENY);
        }
    }
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_preparation_failure_returns_home),
        cmocka_unit_test(test_invalid_review_state_returns_home),
        cmocka_unit_test(test_review_status_matches_signature_result),
        cmocka_unit_test(test_rejection_status),
        cmocka_unit_test(test_contract_review_capacity_and_validation),
#ifdef HAVE_STAKING_DEPOSIT
        cmocka_unit_test(test_staking_review_capacity_and_guard),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
