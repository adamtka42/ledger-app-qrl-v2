/* Exercise the real approval callback with injected signing/verification failures.
 * In particular, a stale NVM export flag must not leave a failed request approved. */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "os.h"
#include "globals.h"
#include "request_context.h"
#include "sign.h"
#include "sw.h"
#include "validate.h"

global_ctx_t G_context;
const internal_storage_t N_storage_real = {0};
static internal_storage_t storage;
static ErrorCode sign_result, verify_result;
static bool verified;
static unsigned sign_calls, verify_calls, wipe_calls, exported;
static unsigned nvm_writes;
static uint16_t response;

void *test_pic(const void *address) {
    assert_ptr_equal(address, &N_storage_real);
    return &storage;
}

void nvm_write(void *destination, const void *source, size_t length) {
    const global_ctx_t zero = {0};
    assert_memory_equal(&G_context, &zero, sizeof(G_context));
    assert_ptr_equal(destination, &storage.is_sending_signature);
    assert_int_equal(length, sizeof(storage.is_sending_signature));
    assert_int_equal(*(const uint8_t *) source, 0);
    assert_int_not_equal(storage.is_sending_signature, 0);
    memcpy(destination, source, length);
    nvm_writes++;
}

int io_send_sw(uint16_t status) {
    response = status;
    return 0;
}

int helper_send_response_address(void) {
    fail_msg("Unexpected address export");
    return -1;
}

int helper_send_response_sig(uint8_t index) {
    assert_int_equal(index, 0);
    assert_int_equal(G_context.req_type, CONFIRM_TRANSACTION);
    assert_int_equal(G_context.state, STATE_APPROVED);
    assert_int_equal(verify_calls, 1);
    assert_true(verified);
    storage.is_sending_signature = 1;
    exported++;
    return 0;
}

ErrorCode crypto_sign_optimized(const uint32_t path[],
                                size_t path_len,
                                uint8_t *message,
                                size_t message_len) {
    assert_ptr_equal(path, G_context.bip32_path);
    assert_int_equal(path_len, 5);
    assert_ptr_equal(message, G_context.tx_info.m_hash);
    assert_int_equal(message_len, 32);
    /* Approval is granted only after both cryptographic operations succeed. */
    assert_int_equal(G_context.state, STATE_PARSED);
    sign_calls++;
    return sign_result;
}

ErrorCode crypto_verify_optimized(const uint32_t path[],
                                  size_t path_len,
                                  uint8_t *signature,
                                  size_t signature_len,
                                  uint8_t *message,
                                  size_t message_len,
                                  bool *is_verified) {
    assert_ptr_equal(path, G_context.bip32_path);
    assert_int_equal(path_len, 5);
    assert_ptr_equal(signature, storage.sig);
    assert_int_equal(signature_len, CRYPTO_BYTES);
    assert_ptr_equal(message, G_context.tx_info.m_hash);
    assert_int_equal(message_len, 32);
    assert_int_equal(G_context.state, STATE_PARSED);
    verify_calls++;
    *is_verified = verified;
    return verify_result;
}

void wipe_nvm_secrets(void) {
    wipe_calls++;
}

static void reset_session(void) {
    memset(&G_context, 0x42, sizeof(G_context));
    G_context.req_type = CONFIRM_TRANSACTION;
    G_context.state = STATE_PARSED;
    G_context.bip32_path_len = 5;
    memset(&storage, 0, sizeof(storage));
    storage.is_sending_signature = 1;
    sign_result = verify_result = ERR_NONE;
    verified = true;
    sign_calls = verify_calls = wipe_calls = exported = 0;
    nvm_writes = 0;
    response = 0;
}

static void assert_discarded(uint16_t expected_status) {
    const global_ctx_t zero = {0};
    assert_memory_equal(&G_context, &zero, sizeof(G_context));
    assert_int_equal(response, expected_status);
    assert_int_equal(exported, 0);
    assert_int_equal(storage.is_sending_signature, 0);
    assert_int_equal(nvm_writes, 1);
}

static void test_reset_cancels_pending_export(void **state) {
    (void) state;
    const global_ctx_t zero = {0};
    for (unsigned restart = 0; restart < 2; restart++) {
        reset_session();
        if (restart) memset(&G_context, 0, sizeof(G_context));
        G_context.state = restart ? STATE_NONE : STATE_APPROVED;
        storage.enable_blind_signing = 1;
        storage.display_nonce = 1;
        storage.display_tx_hash = 1;
        storage.initialized = 1;
        storage.sig[0] = 0xa5;
        storage.pk[0] = 0xb6;
        reset_request_context();
        assert_memory_equal(&G_context, &zero, sizeof(G_context));
        assert_int_equal(storage.is_sending_signature, 0);
        assert_int_equal(nvm_writes, 1);
        assert_int_equal(storage.enable_blind_signing, 1);
        assert_int_equal(storage.display_nonce, 1);
        assert_int_equal(storage.display_tx_hash, 1);
        assert_int_equal(storage.initialized, 1);
        assert_int_equal(storage.sig[0], 0xa5);
        assert_int_equal(storage.pk[0], 0xb6);
        // Repeated reset must not write to an already inactive flag.
        reset_request_context();
        assert_int_equal(nvm_writes, 1);
    }
}

static void test_idle_reset_does_not_write_nvm(void **state) {
    (void) state;
    reset_session();
    storage.is_sending_signature = 0;
    reset_request_context();
    const global_ctx_t zero = {0};
    assert_memory_equal(&G_context, &zero, sizeof(G_context));
    assert_int_equal(storage.is_sending_signature, 0);
    assert_int_equal(nvm_writes, 0);
}

static void test_invalid_callback_cannot_sign(void **state) {
    (void) state;
    const state_e invalid_states[] = {STATE_NONE, STATE_RECEIVING, STATE_APPROVED};
    for (unsigned choice = 0; choice < 2; choice++) {
        for (size_t i = 0; i < sizeof(invalid_states) / sizeof(invalid_states[0]); i++) {
            reset_session();
            G_context.state = invalid_states[i];
            assert_false(validate_transaction(choice != 0));
            assert_discarded(SW_BAD_STATE);
            assert_int_equal(sign_calls, 0);
        }
        reset_session();
        G_context.req_type = CONFIRM_ADDRESS;
        assert_false(validate_transaction(choice != 0));
        assert_discarded(SW_BAD_STATE);
        assert_int_equal(sign_calls, 0);
    }
}

static void test_rejection_discards_request(void **state) {
    (void) state;
    reset_session();
    assert_false(validate_transaction(false));
    assert_discarded(SW_DENY);
    assert_int_equal(sign_calls, 0);
}

static void test_failed_signing_discards_request(void **state) {
    (void) state;
    reset_session();
    sign_result = ERR_INVALID_SIGNATURE;
    assert_false(validate_transaction(true));
    assert_discarded(SW_SIGNATURE_FAIL);
    assert_int_equal(sign_calls, 1);
    assert_int_equal(verify_calls, 0);
    assert_int_equal(wipe_calls, 1);
}

static void test_failed_verification_discards_request(void **state) {
    (void) state;
    for (unsigned fault = 0; fault < 2; fault++) {
        reset_session();
        verified = fault != 0;
        verify_result = fault == 0 ? ERR_NONE : ERR_INVALID_SIGNATURE;
        assert_false(validate_transaction(true));
        assert_discarded(SW_SIGNATURE_FAIL);
        assert_int_equal(verify_calls, 1);
        assert_int_equal(wipe_calls, 1);
    }
}

static void test_verified_signature_is_exported(void **state) {
    (void) state;
    reset_session();
    storage.is_sending_signature = 0;
    assert_true(validate_transaction(true));
    assert_int_equal(G_context.state, STATE_APPROVED);
    assert_int_equal(sign_calls, 1);
    assert_int_equal(verify_calls, 1);
    assert_int_equal(wipe_calls, 1);
    assert_int_equal(exported, 1);
    assert_int_equal(response, 0);
    assert_int_equal(storage.is_sending_signature, 1);
    assert_int_equal(nvm_writes, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reset_cancels_pending_export),
        cmocka_unit_test(test_idle_reset_does_not_write_nvm),
        cmocka_unit_test(test_invalid_callback_cannot_sign),
        cmocka_unit_test(test_rejection_discards_request),
        cmocka_unit_test(test_failed_signing_discards_request),
        cmocka_unit_test(test_failed_verification_discards_request),
        cmocka_unit_test(test_verified_signature_is_exported),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
