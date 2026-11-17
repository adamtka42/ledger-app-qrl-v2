#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>
#include "staking_deposit.h"

/* This executable uses a production profile pinned to chain 257 (0x0101).
 * Its low byte equals chain 1, so comparing only the suffix is insufficient. */
static zond_tx_t target(void) {
    zond_tx_t tx = {0};
    tx.chain_id_len = 2;
    tx.chain_id[0] = tx.chain_id[1] = 1;
    tx.to_len = ADDRESS_LENGTH;
    memset(tx.to, 0x42, sizeof(tx.to));
    return tx;
}

static void test_full_chain_binding(void **unused) {
    (void) unused;
    zond_tx_t tx = target();
    assert_true(staking_deposit_is_target(&tx));

    /* Same low byte, but the nonzero pinned high byte must not disappear. */
    tx.chain_id_len = 1;
    assert_false(staking_deposit_is_target(&tx));
    tx = target();
    tx.chain_id[0] = 2;
    assert_false(staking_deposit_is_target(&tx));
    tx = target();
    tx.chain_id[1] = 0;
    assert_false(staking_deposit_is_target(&tx));

    /* An additional nonzero high byte must also prevent a match. */
    tx = target();
    tx.chain_id_len = 3;
    tx.chain_id[2] = 1;
    assert_false(staking_deposit_is_target(&tx));
}

static void test_contract_and_lengths(void **unused) {
    (void) unused;
    assert_false(staking_deposit_is_target(NULL));
    for (size_t i = 0; i < ADDRESS_LENGTH; i++) {
        zond_tx_t tx = target();
        tx.to[i] ^= 1;
        assert_false(staking_deposit_is_target(&tx));
    }
    zond_tx_t tx = target();
    tx.to_len--;
    assert_false(staking_deposit_is_target(&tx));
    tx = target();
    tx.chain_id_len = 0;
    assert_false(staking_deposit_is_target(&tx));
    tx.chain_id_len = sizeof(tx.chain_id) + 1;
    assert_false(staking_deposit_is_target(&tx));
}

int main(void) {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_full_chain_binding),
                                       cmocka_unit_test(test_contract_and_lengths)};
    return cmocka_run_group_tests(tests, NULL, NULL);
}
