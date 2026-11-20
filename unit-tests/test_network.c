#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "network.h"

static void test_listed_networks(void **state) {
    (void) state;
    const uint8_t mainnet[] = {0x01};
    const uint8_t testnet[] = {0x05, 0x39};  // 1337
    const uint8_t betanet[] = {0x7e, 0x7e};  // 32382
    assert_string_equal(network_name(mainnet, sizeof(mainnet)), "Mainnet");
    assert_string_equal(network_name(testnet, sizeof(testnet)), "Testnet");
    assert_string_equal(network_name(betanet, sizeof(betanet)), "BetaNet");
}

static void test_unlisted_networks(void **state) {
    (void) state;
    const uint8_t zero[] = {0x00};
    const uint8_t two[] = {0x02};
    const uint8_t devnet[] = {0x30, 0x18, 0x24};  // 3151908
    /* 2^64 + 1 must not wrap around to the listed chain ID 1. */
    const uint8_t wrapped[] = {0x01, 0, 0, 0, 0, 0, 0, 0, 0x01};
    uint8_t widest[32];
    memset(widest, 0xff, sizeof(widest));
    assert_null(network_name(NULL, 1));
    assert_null(network_name(two, 0));
    assert_null(network_name(zero, sizeof(zero)));
    assert_null(network_name(two, sizeof(two)));
    assert_null(network_name(devnet, sizeof(devnet)));
    assert_null(network_name(wrapped, sizeof(wrapped)));
    assert_null(network_name(widest, sizeof(widest)));
}

static void test_leading_zeros_do_not_change_the_value(void **state) {
    (void) state;
    uint8_t padded[32] = {0};
    padded[31] = 0x01;
    assert_string_equal(network_name(padded, sizeof(padded)), "Mainnet");
    padded[23] = 0x01;  // now 2^64 + 1
    assert_null(network_name(padded, sizeof(padded)));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_listed_networks),
        cmocka_unit_test(test_unlisted_networks),
        cmocka_unit_test(test_leading_zeros_do_not_change_the_value),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
