#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "address_format.h"
#include "permit.h"

static typed_data_t data;
static uint8_t payload[TYPED_DATA_MAX_PAYLOAD];
static size_t payload_len;

/* Everything a test may vary; defaults describe a standard permit for TKN. */
typedef struct {
    const char *primary;
    const char *field_names[6];
    const char *field_types[6];
    size_t field_count;
    bool with_contract, with_salt, extra_type;
    uint8_t chain_id;
    uint8_t contract_byte;
    uint8_t value[32];
    uint8_t deadline[64];
} permit_case_t;

static const permit_case_t STANDARD = {
    .primary = "Permit",
    .field_names = {"owner", "spender", "value", "nonce", "deadline"},
    .field_types = {"address", "address", "uint256", "uint256", "uint256"},
    .field_count = 5,
    .with_contract = true,
    .chain_id = 1,
    .contract_byte = 0x22,
    .value = {[28] = 0x01, [29] = 0x7d, [30] = 0x78, [31] = 0x40},    /* 25,000,000 */
    .deadline = {[60] = 0x77, [61] = 0x35, [62] = 0x94, [63] = 0x00}, /* 2,000,000,000 */
};

static void put(const void *bytes, size_t length) {
    assert_true(payload_len + length <= sizeof(payload));
    memcpy(payload + payload_len, bytes, length);
    payload_len += length;
}

static void put_byte(uint8_t value) {
    put(&value, 1);
}

static void put_name(const char *name) {
    put_byte((uint8_t) strlen(name));
    put(name, strlen(name));
}

static void put_field(const char *name, const char *type) {
    put_name(name);
    put_name(type);
}

static void put_filled(uint8_t value, size_t length) {
    uint8_t bytes[64];
    memset(bytes, value, sizeof(bytes));
    put(bytes, length);
}

static void put_uint(const uint8_t *low, size_t length) {
    put_filled(0, 64 - length);
    put(low, length);
}

static void build(const permit_case_t *c) {
    payload_len = 0;
    put_byte(1);
    put_byte(c->extra_type ? 3 : 2);
    put_byte(1);
    put_name("QRLTypedDataDomain");
    put_byte((uint8_t) (3 + c->with_contract + c->with_salt));
    put_field("name", "string");
    put_field("version", "string");
    put_field("chainId", "uint256");
    if (c->with_contract) put_field("verifyingContract", "address");
    if (c->with_salt) put_field("salt", "bytes32");
    put_name(c->primary);
    put_byte((uint8_t) c->field_count);
    for (size_t i = 0; i < c->field_count; i++) put_field(c->field_names[i], c->field_types[i]);
    if (c->extra_type) {
        put_name("Unused");
        put_byte(1);
        put_field("flag", "bool");
    }
    /* Domain values. */
    put("\x00\x0aTest Token", 12);
    put("\x00\x01"
        "1",
        3);
    put_uint(&c->chain_id, 1);
    if (c->with_contract) put_filled(c->contract_byte, 64);
    if (c->with_salt) put_filled(0x66, 32);
    /* Message values: owner, spender, value, nonce, deadline, optional string. */
    put_filled(0x44, 64);
    put_filled(0x11, 64);
    put_uint(c->value, sizeof(c->value));
    put_uint((const uint8_t *) "\x07", 1);
    put(c->deadline, sizeof(c->deadline));
    if (c->field_count > 5)
        put("\x00\x05"
            "extra",
            7);
}

static token_metadata_t token(void) {
    token_metadata_t metadata = {.decimals = 6, .symbol = "TKN", .verified = true};
    metadata.chain_id[31] = 1;
    memset(metadata.contract, 0x22, sizeof(metadata.contract));
    return metadata;
}

static void parse(const permit_case_t *c, typed_data_page_length_t page_length) {
    build(c);
    assert_true(typed_data_init(&data, payload_len));
    assert_true(typed_data_feed(&data, payload, payload_len));
    assert_true(typed_data_finish(&data, page_length));
}

static const char *label(size_t index) {
    return data.review + data.pairs[index].label;
}

static const char *value(size_t index) {
    return data.review + data.pairs[index].value;
}

static void test_deadline_format(void **state) {
    (void) state;
    static const struct {
        uint64_t seconds;
        const char *text;
    } cases[] = {
        {0, "1970-01-01 00:00:00 UTC"},
        {86399, "1970-01-01 23:59:59 UTC"},
        {951782400, "2000-02-29 00:00:00 UTC"},
        {1709251199, "2024-02-29 23:59:59 UTC"},
        {1709251200, "2024-03-01 00:00:00 UTC"},
        {2000000000, "2033-05-18 03:33:20 UTC"},
        {4102444800, "2100-01-01 00:00:00 UTC"},
        {4107542400, "2100-03-01 00:00:00 UTC"},
        {4294967296, "2106-02-07 06:28:16 UTC"},
        {253402300799, "9999-12-31 23:59:59 UTC"},
        {253402300800, "After year 9999"},
        {UINT64_MAX, "After year 9999"},
    };
    char text[PERMIT_DEADLINE_MAX_LEN];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t word[64] = {0};
        for (size_t j = 0; j < 8; j++) word[63 - j] = (uint8_t) (cases[i].seconds >> (8 * j));
        assert_true(permit_format_deadline(word, text, sizeof(text)));
        assert_string_equal(text, cases[i].text);
    }
    /* Any bit above 64 bits is far beyond the last displayable date. */
    uint8_t word[64] = {0};
    word[0] = 1;
    assert_true(permit_format_deadline(word, text, sizeof(text)));
    assert_string_equal(text, "After year 9999");
    memset(word, 0xff, sizeof(word));
    assert_true(permit_format_deadline(word, text, sizeof(text)));
    assert_string_equal(text, "After year 9999");
    /* Only the uint256 maximum itself stands for a permit that never expires. */
    memset(word, 0, 32);
    assert_true(permit_format_deadline(word, text, sizeof(text)));
    assert_string_equal(text, "No expiry date");
    word[63] = 0xfe;
    assert_true(permit_format_deadline(word, text, sizeof(text)));
    assert_string_equal(text, "After year 9999");
    word[63] = 0xff;
    word[32] = 0x7f;
    assert_true(permit_format_deadline(word, text, sizeof(text)));
    assert_string_equal(text, "After year 9999");
    word[32] = 0xff;
    word[31] = 1;
    assert_true(permit_format_deadline(word, text, sizeof(text)));
    assert_string_equal(text, "After year 9999");
    word[31] = 0;
    assert_false(permit_format_deadline(word, text, sizeof(text) - 1));
    assert_false(permit_format_deadline(NULL, text, sizeof(text)));
    assert_false(permit_format_deadline(word, NULL, sizeof(text)));
}

static void test_permit_rows(void **state) {
    (void) state;
    const token_metadata_t metadata = token();
    parse(&STANDARD, NULL);
    uint8_t digest[32];
    memcpy(digest, data.digest, sizeof(digest));
    assert_true(permit_prepare(&data, &metadata));
    assert_int_equal(data.permit_kind, PERMIT_LIMITED);
    /* Presentation never changes what is signed. */
    assert_memory_equal(data.digest, digest, sizeof(digest));

    char owner[130], spender[130], contract[130];
    uint8_t bytes[64];
    memset(bytes, 0x44, sizeof(bytes));
    assert_true(format_checksummed_address(bytes, owner, sizeof(owner)));
    assert_memory_equal(data.review + data.permit_owner, bytes, sizeof(bytes));
    memset(bytes, 0x11, sizeof(bytes));
    assert_true(format_checksummed_address(bytes, spender, sizeof(spender)));
    memset(bytes, 0x22, sizeof(bytes));
    assert_true(format_checksummed_address(bytes, contract, sizeof(contract)));

    const char *expected[][2] = {
        {"Token owner", owner},
        {"Spending limit", "TKN 25"},
        {"Spender", spender},
        {"Contract", contract},  // "Token contract" on touch screens
        {"Chain ID", "1"},
        {"Valid until", "2033-05-18 03:33:20 UTC"},
        {"Permit nonce", "7"},
    };
    assert_int_equal(data.pair_count, sizeof(expected) / sizeof(expected[0]));
    assert_int_equal(data.permit_owner_pairs, 1);
    for (size_t i = 0; i < data.pair_count; i++) {
        assert_string_equal(label(i), expected[i][0]);
        assert_string_equal(value(i), expected[i][1]);
    }
}

static void test_permit_kinds(void **state) {
    (void) state;
    const token_metadata_t metadata = token();
    permit_case_t c = STANDARD;

    memset(c.value, 0, sizeof(c.value));
    parse(&c, NULL);
    assert_true(permit_prepare(&data, &metadata));
    assert_int_equal(data.permit_kind, PERMIT_REVOKE);
    assert_string_equal(value(1), "TKN 0");

    memset(c.value, 0xff, sizeof(c.value));
    memset(c.deadline, 0xff, sizeof(c.deadline));
    memset(c.deadline, 0, 32);
    parse(&c, NULL);
    assert_true(permit_prepare(&data, &metadata));
    assert_int_equal(data.permit_kind, PERMIT_UNLIMITED);
    assert_string_equal(value(1), "TKN Unlimited");
    assert_string_equal(value(5), "No expiry date");

    /* One unit below the maximum is an ordinary, exactly displayed limit. */
    c.value[31] = 0xfe;
    parse(&c, NULL);
    assert_true(permit_prepare(&data, &metadata));
    assert_int_equal(data.permit_kind, PERMIT_LIMITED);
    assert_string_equal(value(1),
                        "TKN 115792089237316195423570985008687907853269984665640564039457584007"
                        "913129.639934");

    /* The smallest unit of an 18-decimal token keeps every digit. */
    token_metadata_t precise = token();
    precise.decimals = 18;
    memset(c.value, 0, sizeof(c.value));
    c.value[31] = 1;
    parse(&c, NULL);
    assert_true(permit_prepare(&data, &precise));
    assert_string_equal(value(1), "TKN 0.000000000000000001");
}

static void assert_generic(const permit_case_t *c, const token_metadata_t *metadata) {
    static char review[TYPED_DATA_REVIEW_BYTES];
    parse(c, NULL);
    const uint8_t pairs = data.pair_count;
    const size_t used = data.review_used;
    memcpy(review, data.review, sizeof(review));
    assert_true(permit_prepare(&data, metadata));
    assert_int_equal(data.permit_kind, PERMIT_NONE);
    assert_int_equal(data.pair_count, pairs);
    assert_int_equal(data.review_used, used);
    assert_memory_equal(data.review, review, sizeof(review));
}

static void test_other_messages_keep_generic_review(void **state) {
    (void) state;
    token_metadata_t metadata = token();
    permit_case_t c = STANDARD;

    assert_generic(&c, NULL);
    metadata.verified = false;
    assert_generic(&c, &metadata);
    metadata = token();
    metadata.contract[63] ^= 1;
    assert_generic(&c, &metadata);
    metadata = token();
    metadata.chain_id[31] = 2;
    assert_generic(&c, &metadata);
    metadata = token();
    metadata.chain_id[0] = 1; /* same low byte, different 256-bit chain ID */
    assert_generic(&c, &metadata);
    metadata = token();

    c.primary = "Permission";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.primary = "permit";
    assert_generic(&c, &metadata);
    /* A name that only extends or shortens the expected one is another name. */
    c = STANDARD;
    c.primary = "Permit2";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.primary = "Permi";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.field_names[0] = "owner2";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.field_names[4] = "deadlin";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.field_types[3] = "uint";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.field_names[2] = "nonce";
    c.field_names[3] = "value";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.field_names[1] = "operator";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.field_types[2] = "uint128";
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.field_names[5] = "memo";
    c.field_types[5] = "string";
    c.field_count = 6;
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.with_salt = true;
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.with_contract = false;
    assert_generic(&c, &metadata);
    c = STANDARD;
    c.extra_type = true;
    assert_generic(&c, &metadata);
}

static size_t narrow_page(const char *label, char *text) {
    (void) label;
    const size_t length = strlen(text);
    return length < 20 ? length : 20;
}

static void test_permit_rows_are_paginated(void **state) {
    (void) state;
    const token_metadata_t metadata = token();
    parse(&STANDARD, narrow_page);
    assert_true(permit_prepare(&data, &metadata));
    assert_int_equal(data.permit_kind, PERMIT_LIMITED);
    /* 129 address characters in 20-character fragments. */
    assert_int_equal(data.permit_owner_pairs, 7);
    assert_string_equal(label(0), "Token owner (1/7)");
    assert_string_equal(label(6), "Token owner (7/7)");
    assert_string_equal(label(7), "Spending limit");
    assert_string_equal(value(7), "TKN 25");
    char joined[130] = "", owner[130];
    for (size_t i = 0; i < 7; i++) strcat(joined, value(i));
    uint8_t bytes[64];
    memset(bytes, 0x44, sizeof(bytes));
    assert_true(format_checksummed_address(bytes, owner, sizeof(owner)));
    assert_string_equal(joined, owner);
    for (size_t i = 0; i < data.pair_count; i++) assert_true(strlen(value(i)) <= 20);
}

static void test_requires_finished_message(void **state) {
    (void) state;
    const token_metadata_t metadata = token();
    build(&STANDARD);
    assert_true(typed_data_init(&data, payload_len));
    assert_true(typed_data_feed(&data, payload, payload_len));
    assert_false(permit_prepare(&data, &metadata));
    assert_false(permit_prepare(NULL, &metadata));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_deadline_format),
        cmocka_unit_test(test_permit_rows),
        cmocka_unit_test(test_permit_kinds),
        cmocka_unit_test(test_other_messages_keep_generic_review),
        cmocka_unit_test(test_permit_rows_are_paginated),
        cmocka_unit_test(test_requires_finished_message),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
