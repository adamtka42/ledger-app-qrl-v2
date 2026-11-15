#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "cx.h"
#include "signed_metadata.h"

static uint8_t key[65], payload[SIGNED_METADATA_MAX_BODY_LEN + 72];
static const char *expected_domain;
static size_t expected_domain_len, expected_body_len, expected_sig_len;
static unsigned hash_calls, key_calls, verify_calls;
static enum { SUCCESS, HASH_FAILURE, KEY_FAILURE, SIGNATURE_FAILURE } fault;

size_t cx_hash_sha256(const uint8_t *data, size_t len, uint8_t *digest, size_t digest_len) {
    hash_calls++;
    assert_int_equal(len, expected_domain_len + expected_body_len);
    assert_memory_equal(data, expected_domain, expected_domain_len);
    assert_memory_equal(data + expected_domain_len, payload, expected_body_len);
    assert_int_equal(digest_len, 32);
    memset(digest, 0x5a, digest_len);
    return fault == HASH_FAILURE ? 31 : 32;
}

cx_err_t cx_ecfp_init_public_key_no_throw(uint32_t curve,
                                          const uint8_t *raw,
                                          size_t len,
                                          cx_ecfp_public_key_t *out) {
    key_calls++;
    assert_int_equal(curve, CX_CURVE_SECP256R1);
    assert_int_equal(len, sizeof(key));
    assert_memory_equal(raw, key, len);
    out->marker = 0x42;
    return fault == KEY_FAILURE ? CX_INTERNAL_ERROR : CX_OK;
}

bool cx_ecdsa_verify_no_throw(const cx_ecfp_public_key_t *public_key,
                              const uint8_t *digest,
                              size_t digest_len,
                              const uint8_t *signature,
                              size_t signature_len) {
    verify_calls++;
    assert_int_equal(public_key->marker, 0x42);
    assert_int_equal(digest_len, 32);
    for (size_t i = 0; i < digest_len; i++) assert_int_equal(digest[i], 0x5a);
    assert_ptr_equal(signature, payload + expected_body_len);
    assert_int_equal(signature_len, expected_sig_len);
    return fault != SIGNATURE_FAILURE;
}

static void setup_case(const char *domain, size_t domain_len, size_t body_len, size_t sig_len) {
    memset(key, 0x11, sizeof(key));
    key[0] = 4;
    memset(payload, 0xa5, sizeof(payload));
    expected_domain = domain;
    expected_domain_len = domain_len;
    expected_body_len = body_len;
    expected_sig_len = sig_len;
    hash_calls = key_calls = verify_calls = 0;
    fault = SUCCESS;
}

static bool verify(void) {
    return signed_metadata_verify(key,
                                  sizeof(key),
                                  expected_domain,
                                  expected_domain_len,
                                  payload,
                                  expected_body_len + expected_sig_len,
                                  expected_body_len);
}

static void test_profiles_and_workspace_boundaries(void **state) {
    (void) state;
    const char *domains[] = {"QRL-TOKEN-METADATA-V1",
                             "QRL-CONTRACT-DESCRIPTOR-V1",
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"};
    const size_t bodies[] = {1, 111, SIGNED_METADATA_MAX_BODY_LEN};
    const size_t signatures[] = {8, 72};
    for (size_t d = 0; d < 3; d++) {
        for (size_t b = 0; b < 3; b++) {
            for (size_t s = 0; s < 2; s++) {
                setup_case(domains[d], strlen(domains[d]), bodies[b], signatures[s]);
                assert_true(verify());
                assert_int_equal(hash_calls, 1);
                assert_int_equal(key_calls, 1);
                assert_int_equal(verify_calls, 1);
            }
        }
    }
}

static void test_sdk_failures(void **state) {
    (void) state;
    for (unsigned f = HASH_FAILURE; f <= SIGNATURE_FAILURE; f++) {
        setup_case("domain", 6, 111, 72);
        fault = f;
        assert_false(verify());
        assert_int_equal(hash_calls, 1);
        assert_int_equal(key_calls, f == HASH_FAILURE ? 0 : 1);
        assert_int_equal(verify_calls, f == SIGNATURE_FAILURE ? 1 : 0);
    }
}

static void test_invalid_lengths_never_call_sdk(void **state) {
    (void) state;
    for (unsigned i = 0; i < 13; i++) {
        setup_case("domain", 6, 111, 8);
        const uint8_t *k = key, *data = payload;
        const char *domain = expected_domain;
        size_t key_len = sizeof(key), domain_len = 6, len = 119, body_len = 111;
        switch (i) {
            case 0:
                k = NULL;
                break;
            case 1:
                key_len--;
                break;
            case 2:
                key_len++;
                break;
            case 3:
                domain = NULL;
                break;
            case 4:
                domain_len = 0;
                break;
            case 5:
                domain_len = SIGNED_METADATA_MAX_DOMAIN_LEN + 1;
                break;
            case 6:
                data = NULL;
                break;
            case 7:
                body_len = 0;
                len = body_len + 8;
                break;
            case 8:
                body_len = SIGNED_METADATA_MAX_BODY_LEN + 1;
                len = body_len + 8;
                break;
            case 9:
                body_len = len + 1;
                break;
            case 10:
                len = body_len + 7;
                break;
            case 11:
                len = body_len + 73;
                break;
            case 12:
                len = SIZE_MAX;
                break;
        }
        assert_false(signed_metadata_verify(k, key_len, domain, domain_len, data, len, body_len));
        assert_int_equal(hash_calls + key_calls + verify_calls, 0);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_profiles_and_workspace_boundaries),
        cmocka_unit_test(test_sdk_failures),
        cmocka_unit_test(test_invalid_lengths_never_call_sdk),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
