#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "contract_call.h"

static size_t descriptor(uint8_t out[255], unsigned fields) {
    memset(out, 0, 255);
    out[0] = 1;
    out[32] = 1;
    memset(out + 33, 0x44, 64);
    memset(out + 97, 0x12, 4);
    size_t p = 101;
    out[p++] = 4;
    memcpy(out + p, "Call", 4);
    p += 4;
    out[p++] = (uint8_t) fields;
    for (unsigned i = 0; i < fields; i++) {
        out[p++] = (uint8_t) (i + 1);
        out[p++] = 3;
        memcpy(out + p, "Arg", 3);
        p += 3;
    }
    // Parse-only DER structure. Authentication is exercised on real firmware.
    memcpy(out + p, "\x30\x06\x02\x01\x01\x02\x01\x01", 8);
    return p + 8;
}

static void test_parse_bounds(void **state) {
    (void) state;
    uint8_t data[255];
    size_t n = descriptor(data, 3), body;
    contract_descriptor_t d;
    assert_true(contract_descriptor_parse(data, n, &d, &body));
    assert_int_equal(body, n - 8);
    assert_false(d.verified);
    assert_string_equal(d.operation, "Call");
    assert_int_equal(d.field_count, 3);
    for (size_t len = 0; len < n; len++)
        assert_false(contract_descriptor_parse(data, len, &d, &body));
    assert_false(contract_descriptor_parse(NULL, n, &d, &body));
    assert_false(contract_descriptor_parse(data, n, NULL, &body));
    assert_false(contract_descriptor_parse(data, n, &d, NULL));
    const struct {
        size_t offset;
        uint8_t value;
    } mutations[] = {
        {0, 2},
        {32, 0},
        {101, 0},
        {101, 25},
        {102, '-'},
        {102, '\n'},
        {105, ' '},
        {106, 0},
        {106, 4},
        {107, 0},
        {107, 4},
        {108, 0},
        {108, 13},
        {109, 0},
        {109, '\n'},
        {111, ' '},
    };
    for (size_t i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
        descriptor(data, 3);
        data[mutations[i].offset] = mutations[i].value;
        assert_false(contract_descriptor_parse(data, n, &d, &body));
        assert_int_equal(body, 0);
        assert_false(d.verified);
    }
    descriptor(data, 3);
    memset(data + 33, 0, 64);
    assert_false(contract_descriptor_parse(data, n, &d, &body));
    descriptor(data, 3);
    data[n] = 0;
    assert_false(contract_descriptor_parse(data, n + 1, &d, &body));
}

static size_t descriptor_with_limits(uint8_t out[255],
                                     size_t operation_len,
                                     size_t label_len,
                                     unsigned fields,
                                     size_t sig_len) {
    memset(out, 0, 255);
    out[0] = 1;
    out[32] = 1;
    memset(out + 33, 0x44, 64);
    memset(out + 97, 0x12, 4);
    size_t p = CONTRACT_DESCRIPTOR_FIXED_LEN;
    out[p++] = (uint8_t) operation_len;
    memset(out + p, 'A', operation_len);
    p += operation_len;
    out[p++] = (uint8_t) fields;
    for (unsigned i = 0; i < fields; i++) {
        out[p++] = CONTRACT_FIELD_ADDRESS;  // Fourth field must also have a supported type.
        out[p++] = (uint8_t) label_len;
        memset(out + p, 'B', label_len);
        p += label_len;
    }
    // DER envelope only; parser tests do not authenticate signature contents.
    out[p] = 0x30;
    out[p + 1] = (uint8_t) (sig_len - 2);
    return p + sig_len;
}

static void assert_parser_rejects(const uint8_t *data, size_t len) {
    struct {
        contract_descriptor_t descriptor;
        uint8_t canary[32];
    } out;
    memset(&out, 0xa5, sizeof(out));
    size_t body = SIZE_MAX;
    assert_false(contract_descriptor_parse(data, len, &out.descriptor, &body));
    assert_int_equal(body, 0);
    assert_false(out.descriptor.verified);
    for (size_t i = 0; i < sizeof(out.canary); i++) assert_int_equal(out.canary[i], 0xa5);
}

static void test_independent_parser_limits(void **state) {
    (void) state;
    uint8_t data[255];
    contract_descriptor_t out;
    size_t body;
    const size_t sig_lens[] = {8, 72};
    for (size_t i = 0; i < 2; i++) {
        size_t len = descriptor_with_limits(data,
                                            CONTRACT_CALL_TITLE_MAX,
                                            CONTRACT_CALL_LABEL_MAX,
                                            3,
                                            sig_lens[i]);
        assert_true(contract_descriptor_parse(data, len, &out, &body));
        assert_int_equal(strlen(out.operation), CONTRACT_CALL_TITLE_MAX);
        assert_int_equal(out.field_count, 3);
        assert_false(out.verified);
        for (size_t f = 0; f < 3; f++)
            assert_int_equal(strlen(out.fields[f].label), CONTRACT_CALL_LABEL_MAX);
        assert_int_equal(len - body, sig_lens[i]);
    }
    const struct {
        size_t operation, label;
        unsigned fields;
        size_t signature;
    } cases[] = {
        {25, 3, 1, 8},  // All 25 operation bytes are legal letters.
        {4, 13, 1, 8},  // All 13 label bytes are legal letters.
        {4, 3, 0, 8},   // Signature immediately follows the zero count.
        {4, 3, 4, 8},   // Four fully formed fields with supported types.
        {4, 3, 1, 7},   // Complete envelope, one byte below the signature minimum.
        {4, 3, 1, 73},  // Complete envelope, one byte above the signature maximum.
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t len = descriptor_with_limits(data,
                                            cases[i].operation,
                                            cases[i].label,
                                            cases[i].fields,
                                            cases[i].signature);
        assert_parser_rejects(data, len);
    }
    // Isolate character validation from the first-letter and trailing-space rules.
    size_t len = descriptor_with_limits(data, 4, 3, 1, 8);
    data[CONTRACT_DESCRIPTOR_FIXED_LEN + 1 + 2] = '!';
    assert_parser_rejects(data, len);
    len = descriptor_with_limits(data, 4, 3, 1, 8);
    data[CONTRACT_DESCRIPTOR_FIXED_LEN + 1 + 4 + 1 + 2 + 1] = '!';
    assert_parser_rejects(data, len);
    len = descriptor_with_limits(data, 4, 3, 1, 8);
    data[len - 8] = 0x31;  // Length remains correct; only the DER sequence tag is wrong.
    assert_parser_rejects(data, len);
}

static void test_match(void **state) {
    (void) state;
    uint8_t data[255];
    size_t n = descriptor(data, 3), body;
    contract_descriptor_t d;
    assert_true(contract_descriptor_parse(data, n, &d, &body));
    zond_tx_t tx = {0};
    tx.chain_id_len = 1;
    tx.chain_id[0] = 1;
    tx.to_len = 64;
    memset(tx.to, 0x44, 64);
    tx.has_data = true;
    tx.data_len = 196;
    memset(tx.data, 0x12, 4);
    memset(tx.data + 4, 0x11, 64);
    tx.data[131] = 100;
    tx.data[195] = 1;
    assert_false(contract_call_matches(&tx, &d));
    d.verified = true;
    assert_true(contract_call_matches(&tx, &d));
    const zond_tx_t good = tx;
    for (unsigned i = 0; i < 15; i++) {
        tx = good;
        switch (i) {
            case 0:
                tx.chain_id[0] = 2;
                break;
            case 1:
                tx.chain_id_len = 0;
                break;
            case 2:
                tx.chain_id_len = 33;
                break;
            case 3:
                tx.to[63] ^= 1;
                break;
            case 4:
                tx.to_len = 0;
                break;
            case 5:
                tx.value_len = 1;
                tx.value[0] = 1;
                break;
            case 6:
                tx.has_access_list = true;
                break;
            case 7:
                tx.has_data = false;
                break;
            case 8:
                tx.data_len--;
                break;
            case 9:
                tx.data_len++;
                break;
            case 10:
                tx.data[3] ^= 1;
                break;
            case 11:
                tx.data[68] = 1;
                break;
            case 12:
                tx.data[132] = 1;
                break;
            case 13:
                tx.data[195] = 2;
                break;
            case 14:
                tx.data_len = 65536;
                break;
        }
        assert_false(contract_call_matches(&tx, &d));
    }
    tx = good;
    memset(tx.data + 100, 0xff, 32);  // UINT256_MAX is an exact integer, never "Unlimited".
    assert_true(contract_call_matches(&tx, &d));
    tx.data[195] = 0;
    assert_true(contract_call_matches(&tx, &d));
    d.chain_id[0] = 1;
    assert_false(contract_call_matches(&tx, &d));
    assert_false(contract_call_matches(NULL, &d));
    assert_false(contract_call_matches(&tx, NULL));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_bounds),
        cmocka_unit_test(test_match),
        cmocka_unit_test(test_independent_parser_limits),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
