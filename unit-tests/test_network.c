#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

/* The table is static, so this test compiles network.c itself. */
#include "network.c"

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

/* A repeated chain ID would silently keep the name of its first entry, and C
 * accepts a name one character too long by dropping its terminator. */
static void test_every_listed_network_is_well_formed(void **state) {
    (void) state;
    const size_t count = sizeof(NETWORKS) / sizeof(NETWORKS[0]);
    assert_true(count > 0);
    for (size_t i = 0; i < count; i++) {
        const network_t *listed = &NETWORKS[i];
        assert_true(listed->name[0] != '\0');
        assert_non_null(memchr(listed->name, '\0', sizeof(listed->name)));
        uint8_t chain_id[8];
        for (size_t j = 0; j < sizeof(chain_id); j++)
            chain_id[j] = (uint8_t) (listed->chain_id >> (8 * (sizeof(chain_id) - 1 - j)));
        assert_ptr_equal(network_name(chain_id, sizeof(chain_id)), listed->name);
        for (size_t j = 0; j < i; j++) assert_true(listed->chain_id != NETWORKS[j].chain_id);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_listed_networks),
        cmocka_unit_test(test_unlisted_networks),
        cmocka_unit_test(test_leading_zeros_do_not_change_the_value),
        cmocka_unit_test(test_every_listed_network_is_well_formed),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
