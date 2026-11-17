#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>
#include "staking_hash.h"
#include "tx_stream.h"

static uint8_t calldata[STAKING_CALLDATA_LEN];
static const uint8_t reference_root[32] = {
    0x91, 0x30, 0xe8, 0xf5, 0x40, 0xb6, 0xa5, 0x8a, 0x24, 0xda, 0x8b, 0x51, 0xe8, 0x66, 0x1a, 0x2f,
    0xbe, 0x93, 0x72, 0x34, 0x49, 0x0e, 0x7d, 0x59, 0xa6, 0xe2, 0xbb, 0xb9, 0x9a, 0x38, 0x72, 0xe8};

static zond_tx_t transaction(uint64_t shor) {
    zond_tx_t tx = {0};
    tx.to_len = 64;
    memset(tx.to, 0x42, 64);
    tx.chain_id_len = 1;
    tx.chain_id[0] = 1;
    tx.has_data = true;
    tx.data_len = STAKING_CALLDATA_LEN;
    // Multiply uint64 shor by 1e9 using little-endian bytes, independently of decoder division.
    uint8_t input[8];
    for (size_t i = 0; i < 8; i++) input[i] = (uint8_t) (shor >> (8 * i));
    uint64_t carry = 0;
    uint8_t product[16] = {0};
    for (size_t i = 0; i < 16; i++) {
        carry += (i < 8 ? input[i] : 0) * UINT64_C(1000000000);
        product[15 - i] = (uint8_t) carry;
        carry >>= 8;
    }
    memcpy(tx.value, product, 16);
    tx.value_len = 16;
    return tx;
}

static void feed(staking_deposit_t *s, const uint8_t *data, size_t len, size_t chunk) {
    for (size_t pos = 0; pos < len; pos += chunk) {
        size_t n = len - pos;
        if (n > chunk) n = chunk;
        staking_deposit_feed(s, (uint32_t) pos, (uint32_t) len, data + pos, n);
    }
}

static void test_known_root_and_splits(void **unused) {
    (void) unused;
    zond_tx_t tx = transaction(UINT64_C(40000000000000));
    const size_t sizes[] = {1, 3, 4, 7, 31, 32, 33, 63, 64, 65, 127, 254, 255, 256, 511, 8004};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        staking_deposit_t s;
        staking_deposit_init(&s, test_staking_hash);
        feed(&s, calldata, sizeof(calldata), sizes[i]);
        assert_true(s.selected);
        assert_false(s.failed);
        assert_memory_equal(s.expected_root, reference_root, 32);
        assert_true(staking_deposit_is_target(&tx));
        assert_true(staking_deposit_validate(&s, &tx));
        assert_true(
            staking_deposit_validate(&s, &tx));  // Validation must be repeatable for UI guard.
        tx.value[15] ^= 1;
        assert_false(staking_deposit_validate(&s, &tx));
        tx.value[15] ^= 1;
    }
}

static void test_corruptions(void **unused) {
    (void) unused;
    const size_t indices[] = {4,    67,   68,   131,  132,  195,  196,  259,  260,
                              291,  292,  323,  324,  387,  388,  2979, 2980, 3011,
                              3012, 3075, 3076, 3139, 3140, 3203, 3204, 3235, 3236,
                              3267, 3268, 3331, 3332, 7958, 7959, 8003};
    zond_tx_t tx = transaction(UINT64_C(40000000000000));
    for (size_t i = 0; i < sizeof(indices) / sizeof(indices[0]); i++) {
        calldata[indices[i]] ^= 1;
        staking_deposit_t s;
        staking_deposit_init(&s, test_staking_hash);
        feed(&s, calldata, sizeof(calldata), 255);
        assert_true(s.selected);
        assert_false(staking_deposit_validate(&s, &tx));
        calldata[indices[i]] ^= 1;
    }
    staking_deposit_t s;
    staking_deposit_init(&s, test_staking_hash);
    feed(&s, calldata, sizeof(calldata) - 1, 255);
    assert_true(s.selected);
    assert_false(staking_deposit_validate(&s, &tx));
    staking_deposit_init(&s, test_staking_hash);
    staking_deposit_feed(&s, 1, sizeof(calldata), calldata, 4);
    assert_true(s.failed);
    staking_deposit_init(&s, test_staking_hash);
    staking_deposit_feed(&s, 0, sizeof(calldata) + 1, calldata, 255);
    assert_true(s.selected);
    assert_true(s.failed);
    staking_deposit_init(&s, NULL);
    feed(&s, calldata, sizeof(calldata), 255);
    assert_true(s.failed);
    staking_deposit_init(&s, test_staking_hash);
    feed(&s, calldata, sizeof(calldata), 255);
    tx.has_access_list = true;
    assert_false(staking_deposit_validate(&s, &tx));
    tx.has_access_list = false;
    tx.data_len++;
    assert_false(staking_deposit_validate(&s, &tx));
}

static void test_amount_and_profile(void **unused) {
    (void) unused;
    uint64_t shor;
    const uint64_t good[] = {STAKING_MIN_SHOR, UINT64_MAX};
    for (size_t i = 0; i < 2; i++) {
        zond_tx_t tx = transaction(good[i]);
        assert_true(staking_deposit_amount(&tx, &shor));
        assert_int_equal(shor, good[i]);
        tx.value[15]++;
        assert_false(staking_deposit_amount(&tx, &shor));
    }
    zond_tx_t tx = transaction(STAKING_MIN_SHOR - 1);
    assert_false(staking_deposit_amount(&tx, &shor));
    memset(tx.value, 0xff, 32);
    tx.value_len = 32;
    assert_false(staking_deposit_amount(&tx, &shor));
    /* (2^64 + STAKING_MIN_SHOR) * 1e9: remainder zero, quotient too large.
     * Without the overflow guard, wrapping would leave a valid minimum amount. */
    static const uint8_t overflow[] =
        {0x3b, 0x9a, 0xca, 0x6c, 0x6b, 0x93, 0x5b, 0x8b, 0xbd, 0x40, 0x00, 0x00};
    memcpy(tx.value, overflow, sizeof(overflow));
    tx.value_len = sizeof(overflow);
    assert_false(staking_deposit_amount(&tx, &shor));
    tx = transaction(STAKING_MIN_SHOR);
    tx.chain_id[0] = 2;
    assert_false(staking_deposit_is_target(&tx));
    tx.chain_id[0] = 1;
    tx.to[63] ^= 1;
    assert_false(staking_deposit_is_target(&tx));
}

static void test_other_selector_is_ignored(void **unused) {
    (void) unused;
    zond_tx_t tx = transaction(UINT64_C(40000000000000));
    for (size_t i = 0; i < 4; i++) {
        for (size_t chunk = 1; chunk <= 255; chunk += 254) {
            calldata[i] ^= 1;
            staking_deposit_t s;
            staking_deposit_init(&s, test_staking_hash);
            feed(&s, calldata, sizeof(calldata), chunk);
            assert_true(s.ignored);
            assert_false(s.selected);
            assert_false(s.failed);
            assert_false(staking_deposit_validate(&s, &tx));
            calldata[i] ^= 1;
        }
    }
}

static void observe(void *context,
                    uint32_t offset,
                    uint32_t total,
                    const uint8_t *data,
                    size_t len) {
    staking_deposit_feed(context, offset, total, data, len);
}

static void test_rlp_observer(void **unused) {
    (void) unused;
    uint8_t preimage[8300];
    FILE *file = fopen(STAKING_PREIMAGE, "rb");
    assert_non_null(file);
    size_t len = fread(preimage, 1, sizeof(preimage), file);
    fclose(file);
    assert_true(len > 8004);
    const size_t chunks[] = {1, 31, 64, 255, 256, 8300};
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        tx_stream_t stream;
        zond_tx_t tx;
        staking_deposit_t s;
        staking_deposit_init(&s, test_staking_hash);
        tx_stream_init(&stream, &tx);
        assert_null(stream.on_data);
        stream.on_data = observe;
        stream.observer_context = &s;
        tx_stream_status_e status = TX_STREAM_PROCESSING;
        for (size_t p = 0; p < len; p += chunks[i]) {
            size_t n = len - p;
            if (n > chunks[i]) n = chunks[i];
            status = tx_stream_feed(&stream, &tx, preimage + p, n);
            assert_int_not_equal(status, TX_STREAM_ERROR);
        }
        assert_int_equal(status, TX_STREAM_FINISHED);
        assert_memory_equal(tx.data, calldata, TX_CALLDATA_MAX_LEN);
        assert_true(staking_deposit_validate(&s, &tx));
        tx_stream_init(&stream, &tx);
        assert_null(stream.on_data);
    }
}

int main(void) {
    FILE *file = fopen(STAKING_FIXTURE, "rb");
    if (file == NULL || fread(calldata, 1, sizeof(calldata), file) != sizeof(calldata)) return 1;
    fclose(file);
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_known_root_and_splits),
                                       cmocka_unit_test(test_corruptions),
                                       cmocka_unit_test(test_amount_and_profile),
                                       cmocka_unit_test(test_other_selector_is_ignored),
                                       cmocka_unit_test(test_rlp_observer)};
    return cmocka_run_group_tests(tests, NULL, NULL);
}
