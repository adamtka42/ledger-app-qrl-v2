#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "typed_data.h"

static typed_data_t data;

static size_t unhex(const char *text, uint8_t *out, size_t capacity) {
    size_t length = strlen(text);
    assert_int_equal(length % 2, 0);
    assert_true(length / 2 <= capacity);
    for (size_t i = 0; i < length / 2; i++) {
        unsigned byte;
        assert_int_equal(sscanf(text + 2 * i, "%2x", &byte), 1);
        out[i] = (uint8_t) byte;
    }
    return length / 2;
}

static size_t vector(const char *name, uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], uint8_t digest[32]) {
    FILE *file = fopen(TYPED_DATA_VECTOR_FILE, "r");
    assert_non_null(file);
    char found[32], hash[65], payload[2 * TYPED_DATA_MAX_PAYLOAD + 1];
    while (fscanf(file, "%31s %64s %8192s", found, hash, payload) == 3) {
        if (strcmp(found, name) != 0) continue;
        fclose(file);
        assert_int_equal(unhex(hash, digest, 32), 32);
        return unhex(payload, bytes, TYPED_DATA_MAX_PAYLOAD);
    }
    fclose(file);
    fail_msg("Missing typed-data vector %s", name);
    return 0;
}

static void review_is_complete(void) {
    assert_true(data.pair_count > 0 && data.pair_count <= TYPED_DATA_MAX_PAIRS);
    for (size_t i = 0; i < data.pair_count; i++) {
        assert_true(data.pairs[i].label < data.review_used);
        assert_true(data.pairs[i].value < data.review_used);
        const char *value = data.review + data.pairs[i].value;
        assert_true(strlen(value) <= TYPED_DATA_REVIEW_PART);
        size_t newlines = 0;
        for (const char *p = value; *p; p++)
            if (*p == '\n') newlines++;
        assert_true(newlines <= 2);
    }
}

static void test_go_vectors(void **state) {
    (void) state;
    const char *names[] = {"wide",
                           "permission",
                           "nested",
                           "arrays",
                           "primitives",
                           "empty_struct",
                           "long_values",
                           "uint8",
                           "bool"};
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        size_t length = vector(names[i], bytes, digest);
        assert_true(typed_data_init(&data, length));
        assert_true(typed_data_feed(&data, bytes, length));
        assert_true(typed_data_finish(&data));
        assert_memory_equal(data.digest, digest, 32);
        review_is_complete();
        assert_false(typed_data_finish(&data));
        assert_false(typed_data_feed(&data, NULL, 0));
    }
}

static void test_all_stream_splits(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = vector("nested", bytes, digest);
    for (size_t split = 0; split <= length; split++) {
        assert_true(typed_data_init(&data, length));
        assert_true(typed_data_feed(&data, bytes, split));
        assert_true(typed_data_feed(&data, bytes + split, length - split));
        assert_true(typed_data_finish(&data));
        assert_memory_equal(data.digest, digest, 32);
    }
}

static void test_truncation_and_trailing_data(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = vector("permission", bytes, digest);
    for (size_t prefix = 3; prefix < length; prefix++) {
        assert_true(typed_data_init(&data, prefix));
        assert_true(typed_data_feed(&data, bytes, prefix));
        assert_false(typed_data_finish(&data));
    }
    bytes[length] = 0;
    assert_true(typed_data_init(&data, length + 1));
    assert_true(typed_data_feed(&data, bytes, length + 1));
    assert_false(typed_data_finish(&data));
}

static void test_canonical_values_and_limits(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = vector("bool", bytes, digest);
    bytes[length - 1] = 2;
    assert_true(typed_data_init(&data, length));
    assert_true(typed_data_feed(&data, bytes, length));
    assert_false(typed_data_finish(&data));
    length = vector("uint8", bytes, digest);
    bytes[length - 2] = 1;  // 511 does not fit the declared uint8.
    assert_true(typed_data_init(&data, length));
    assert_true(typed_data_feed(&data, bytes, length));
    assert_false(typed_data_finish(&data));
    length = vector("permission", bytes, digest);
    bytes[0] = 2;  // Unsupported format version.
    assert_true(typed_data_init(&data, length));
    assert_true(typed_data_feed(&data, bytes, length));
    assert_false(typed_data_finish(&data));
    assert_false(typed_data_init(NULL, 10));
    assert_false(typed_data_init(&data, 0));
    assert_false(typed_data_init(&data, TYPED_DATA_MAX_PAYLOAD + 1));
    assert_true(typed_data_init(&data, 3));
    assert_false(typed_data_feed(&data, NULL, 1));
    assert_false(typed_data_feed(&data, bytes, 4));
    assert_int_equal(data.received_len, 0);
    assert_false(typed_data_finish(&data));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_go_vectors),
        cmocka_unit_test(test_all_stream_splits),
        cmocka_unit_test(test_truncation_and_trailing_data),
        cmocka_unit_test(test_canonical_values_and_limits),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
