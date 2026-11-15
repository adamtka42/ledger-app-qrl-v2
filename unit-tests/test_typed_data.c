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
        assert_true(strlen(value) <= 2 * TYPED_DATA_MAX_VALUE + 2);
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
        assert_true(typed_data_finish(&data, NULL));
        assert_memory_equal(data.digest, digest, 32);
        review_is_complete();
        assert_false(typed_data_finish(&data, NULL));
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
        assert_true(typed_data_finish(&data, NULL));
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
        assert_false(typed_data_finish(&data, NULL));
    }
    bytes[length] = 0;
    assert_true(typed_data_init(&data, length + 1));
    assert_true(typed_data_feed(&data, bytes, length + 1));
    assert_false(typed_data_finish(&data, NULL));
}

static void test_canonical_values_and_limits(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = vector("bool", bytes, digest);
    bytes[length - 1] = 2;
    assert_true(typed_data_init(&data, length));
    assert_true(typed_data_feed(&data, bytes, length));
    assert_false(typed_data_finish(&data, NULL));
    length = vector("uint8", bytes, digest);
    bytes[length - 2] = 1;  // 511 does not fit the declared uint8.
    assert_true(typed_data_init(&data, length));
    assert_true(typed_data_feed(&data, bytes, length));
    assert_false(typed_data_finish(&data, NULL));
    length = vector("permission", bytes, digest);
    bytes[0] = 2;  // Unsupported format version.
    assert_true(typed_data_init(&data, length));
    assert_true(typed_data_feed(&data, bytes, length));
    assert_false(typed_data_finish(&data, NULL));
    assert_false(typed_data_init(NULL, 10));
    assert_false(typed_data_init(&data, 0));
    assert_false(typed_data_init(&data, TYPED_DATA_MAX_PAYLOAD + 1));
    assert_true(typed_data_init(&data, 3));
    assert_false(typed_data_feed(&data, NULL, 1));
    assert_false(typed_data_feed(&data, bytes, 4));
    assert_int_equal(data.received_len, 0);
    assert_false(typed_data_finish(&data, NULL));
}

static void append_name(uint8_t *bytes, size_t *length, const char *name) {
    size_t count = strlen(name);
    assert_true(count <= UINT8_MAX);
    assert_true(*length + 1 + count <= TYPED_DATA_MAX_PAYLOAD);
    bytes[(*length)++] = (uint8_t) count;
    memcpy(bytes + *length, name, count);
    *length += count;
}

/* Include complete values and array counts so the underscore regression cases
 * exercise name validation rather than failing on truncated payloads. */
static size_t identifier_payload(uint8_t bytes[TYPED_DATA_MAX_PAYLOAD],
                                 const char *primary,
                                 const char *inner,
                                 const char *reference,
                                 const char *field) {
    bytes[0] = 1;
    bytes[1] = 3;
    bytes[2] = 1;
    size_t length = 3;
    append_name(bytes, &length, "QRLTypedDataDomain");
    bytes[length++] = 1;
    append_name(bytes, &length, "name");
    append_name(bytes, &length, "string");
    append_name(bytes, &length, primary);
    bytes[length++] = 1;
    append_name(bytes, &length, field);
    append_name(bytes, &length, reference);
    append_name(bytes, &length, inner);
    bytes[length++] = 1;
    append_name(bytes, &length, "_enabled");
    append_name(bytes, &length, "bool");
    bytes[length++] = 0;
    bytes[length++] = 1;
    bytes[length++] = 'D';
    size_t reference_length = strlen(reference);
    if (reference_length >= 2 && strcmp(reference + reference_length - 2, "[]") == 0)
        bytes[length++] = 1;
    bytes[length++] = 1;
    return length;
}

static void test_type_and_field_identifiers(void **state) {
    (void) state;
    const struct {
        const char *primary;
        const char *inner;
        const char *reference;
        const char *field;
        bool valid;
    } cases[] = {
        {"Outer", "Inner", "Inner", "value", true},
        {"Outer_1", "Inner_2", "Inner_2", "_value", true},
        {"Outer_1", "Inner_2", "Inner_2[]", "_value", true},
        {"_Outer", "Inner", "Inner", "value", false},
        {"Outer", "_Inner", "_Inner", "value", false},
        {"Outer", "_Inner", "_Inner[]", "value", false},
        {"Outer", "_Unused", "bool", "value", false},
        {"Outer", "Inner", "_Inner", "value", false},
        {"Outer", "Inner", "_Inner[]", "value", false},
        {"Outer[]", "Inner", "Inner", "value", false},
        {"1Outer", "Inner", "Inner", "value", false},
    };
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t length = identifier_payload(bytes,
                                           cases[i].primary,
                                           cases[i].inner,
                                           cases[i].reference,
                                           cases[i].field);
        assert_true(typed_data_init(&data, length));
        assert_true(typed_data_feed(&data, bytes, length));
        assert_int_equal(typed_data_finish(&data, NULL), cases[i].valid);
        assert_int_equal(data.finished, cases[i].valid);
    }
}

static size_t short_page(const char *label, char *text) {
    assert_non_null(label);
    size_t length = strlen(text);
    return length < 80 ? length : 80;
}

static size_t invalid_page_length;

static size_t invalid_page(const char *label, char *text) {
    (void) label;
    (void) text;
    return invalid_page_length;
}

static void test_pagination_preserves_values_and_hash(void **state) {
    (void) state;
    const char *names[] = {"permission", "long_values", "nested", "arrays", "primitives"};
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    typed_data_t whole;
    for (size_t sample = 0; sample < sizeof(names) / sizeof(names[0]); sample++) {
        size_t length = vector(names[sample], bytes, digest);
        assert_true(typed_data_init(&whole, length));
        assert_true(typed_data_feed(&whole, bytes, length));
        assert_true(typed_data_finish(&whole, NULL));
        assert_true(typed_data_init(&data, length));
        assert_true(typed_data_feed(&data, bytes, length));
        assert_true(typed_data_finish(&data, short_page));
        assert_memory_equal(data.digest, digest, sizeof(digest));
        assert_memory_equal(data.payload, bytes, length);

        size_t next = 0;
        for (size_t i = 0; i < whole.pair_count; i++) {
            const char *label = whole.review + whole.pairs[i].label;
            const char *value = whole.review + whole.pairs[i].value;
            size_t remaining = strlen(value), parts = (remaining + 79) / 80;
            for (size_t part = 0; part < parts; part++) {
                assert_true(next < data.pair_count);
                const char *fragment = data.review + data.pairs[next].value;
                size_t count = strlen(fragment);
                assert_true(count > 0 && count <= 80 && count <= remaining);
                assert_memory_equal(fragment, value, count);
                char expected_label[48];
                if (parts == 1)
                    snprintf(expected_label, sizeof(expected_label), "%s", label);
                else
                    snprintf(expected_label,
                             sizeof(expected_label),
                             "%s (%u/%u)",
                             label,
                             (unsigned) part + 1,
                             (unsigned) parts);
                assert_string_equal(data.review + data.pairs[next].label, expected_label);
                next++;
                value += count;
                remaining -= count;
            }
            assert_int_equal(remaining, 0);
        }
        assert_int_equal(next, data.pair_count);
    }
}

static void test_invalid_page_lengths_fail_closed(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = vector("permission", bytes, digest);
    const size_t invalid[] = {0, SIZE_MAX, 1};  // One-byte pages exceed the pair budget.
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        invalid_page_length = invalid[i];
        assert_true(typed_data_init(&data, length));
        assert_true(typed_data_feed(&data, bytes, length));
        assert_false(typed_data_finish(&data, invalid_page));
        assert_false(data.finished);
        assert_memory_equal(data.payload, bytes, length);
    }
}

static size_t extra_pages;

static size_t fill_pair_budget(const char *label, char *text) {
    if (strcmp(label, "text") == 0 && extra_pages != 0) {
        extra_pages--;
        return 1;
    }
    return strlen(text);
}

static void test_review_pair_budget_boundary(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = vector("long_values", bytes, digest);
    assert_true(typed_data_init(&data, length));
    assert_true(typed_data_feed(&data, bytes, length));
    assert_true(typed_data_finish(&data, NULL));
    size_t room = TYPED_DATA_MAX_PAIRS - data.pair_count;
    for (size_t overflow = 0; overflow <= 1; overflow++) {
        extra_pages = room + overflow;
        assert_true(typed_data_init(&data, length));
        assert_true(typed_data_feed(&data, bytes, length));
        bool success = typed_data_finish(&data, fill_pair_budget);
        assert_int_equal(success, overflow == 0);
        if (success) {
            assert_int_equal(data.pair_count, TYPED_DATA_MAX_PAIRS);
            assert_memory_equal(data.digest, digest, sizeof(digest));
        }
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_go_vectors),
        cmocka_unit_test(test_all_stream_splits),
        cmocka_unit_test(test_truncation_and_trailing_data),
        cmocka_unit_test(test_canonical_values_and_limits),
        cmocka_unit_test(test_type_and_field_identifiers),
        cmocka_unit_test(test_pagination_preserves_values_and_hash),
        cmocka_unit_test(test_invalid_page_lengths_fail_closed),
        cmocka_unit_test(test_review_pair_budget_boundary),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
