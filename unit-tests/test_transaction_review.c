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
    assert_int_equal(pairs->nbPairs, 9);
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_preparation_failure_returns_home),
        cmocka_unit_test(test_invalid_review_state_returns_home),
        cmocka_unit_test(test_review_status_matches_signature_result),
        cmocka_unit_test(test_rejection_status),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
