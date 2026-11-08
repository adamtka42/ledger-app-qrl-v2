#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "personal_message.h"

static void assert_hash(const uint8_t digest[32], const char *hex) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        unsigned hi = (unsigned) (strchr(digits, hex[2 * i]) - digits);
        unsigned lo = (unsigned) (strchr(digits, hex[2 * i + 1]) - digits);
        assert_int_equal(digest[i], (hi << 4) | lo);
    }
}

static void test_web3_vectors(void **state) {
    (void) state;
    // Independently obtained from local web3-qrl-accounts.hashMessage(hexBytes).
    const char *texts[] = {"", "Hello world", "Login to example.app\nNonce: 123456", "0x1234"};
    const char *hashes[] = {
        "d1e20245c66f2cc8733c0a25cf6136279aab0d4e4d5eb18ede8759cd83b69516",
        "134c45c81b617d89c51b691341f45f5b75ec9fa825f1d44e8f8b354e734e822c",
        "54ae45a4e6b1a189621b3f2639da10d1caaf4cf039636d3e8c87407e9d62cc73",
        "a6f9ebfa74f9ae8d91e40360b934a06522a12cdf011a87918b13cd2c40b221cc",
    };
    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++) {
        personal_message_t message;
        assert_true(personal_message_init(&message, strlen(texts[i])));
        assert_true(personal_message_feed(&message, (const uint8_t *) texts[i], strlen(texts[i])));
        assert_true(personal_message_finish(&message));
        assert_hash(message.digest, hashes[i]);
        assert_false(personal_message_finish(&message));
        assert_false(personal_message_feed(&message, NULL, 0));
    }
}

static void check_roundtrip(const uint8_t *text, size_t length) {
    personal_message_t message;
    assert_true(personal_message_init(&message, length));
    assert_true(personal_message_feed(&message, text, length));
    assert_true(personal_message_finish(&message));
    uint8_t digest[32];
    memcpy(digest, message.digest, sizeof(digest));
    uint16_t offsets[PERSONAL_MESSAGE_MAX_PARTS];
    size_t count;
    assert_true(personal_message_prepare_review(&message, offsets, &count));
    assert_true(count >= 1 && count <= PERSONAL_MESSAGE_MAX_PARTS);
    size_t position = 0;
    for (size_t i = 0; i < count; i++) {
        const char *part = message.text + offsets[i];
        size_t part_length = strlen(part), newlines = 0;
        assert_true(part_length <= PERSONAL_MESSAGE_PART_LEN);
        for (size_t j = 0; j < part_length; j++)
            if (part[j] == '\n') newlines++;
        assert_true(newlines <= 2);
        assert_memory_equal(part, text + position, part_length);
        position += part_length;
    }
    assert_int_equal(position, length);
    assert_memory_equal(message.digest, digest, 32);
    assert_false(personal_message_prepare_review(&message, offsets, &count));
}

static void test_review_roundtrip(void **state) {
    (void) state;
    uint8_t text[PERSONAL_MESSAGE_MAX_LEN];
    memset(text, 'A', sizeof(text));
    for (size_t length = 0; length <= sizeof(text); length++) check_roundtrip(text, length);
    memset(text, '\n', PERSONAL_MESSAGE_MAX_NEWLINES);
    check_roundtrip(text, sizeof(text));
    check_roundtrip(text, PERSONAL_MESSAGE_MAX_NEWLINES);
}

static void test_stream_boundaries(void **state) {
    (void) state;
    uint8_t text[PERSONAL_MESSAGE_MAX_LEN];
    for (size_t i = 0; i < sizeof(text); i++) text[i] = 'A' + i % 26;
    personal_message_t reference;
    assert_true(personal_message_init(&reference, sizeof(text)));
    assert_true(personal_message_feed(&reference, text, sizeof(text)));
    assert_true(personal_message_finish(&reference));
    for (size_t split = 0; split <= sizeof(text); split++) {
        personal_message_t message;
        assert_true(personal_message_init(&message, sizeof(text)));
        assert_true(personal_message_feed(&message, text, split));
        assert_true(personal_message_feed(&message, text + split, sizeof(text) - split));
        assert_true(personal_message_finish(&message));
        assert_memory_equal(message.digest, reference.digest, 32);
    }
}

static void test_invalid_input(void **state) {
    (void) state;
    personal_message_t message;
    assert_false(personal_message_init(&message, PERSONAL_MESSAGE_MAX_LEN + 1));
    assert_false(personal_message_init(&message, UINT32_MAX));
    assert_false(personal_message_init(NULL, 1));
    const uint8_t invalid[] = {0, '\t', '\r', 0x1f, 0x7f, 0x80, 0xff};
    for (size_t i = 0; i < sizeof(invalid); i++) {
        assert_true(personal_message_init(&message, 3));
        assert_true(personal_message_feed(&message, (const uint8_t *) "Hi", 2));
        assert_false(personal_message_feed(&message, invalid + i, 1));
        assert_int_equal(message.received_len, 2);
        assert_memory_equal(message.text, "Hi", 2);
        assert_false(personal_message_finish(&message));
    }
    assert_true(personal_message_init(&message, 1));
    assert_false(personal_message_feed(&message, (const uint8_t *) "Hi", 2));
    assert_false(personal_message_feed(&message, NULL, 1));
    uint8_t newlines[PERSONAL_MESSAGE_MAX_NEWLINES + 1];
    memset(newlines, '\n', sizeof(newlines));
    assert_true(personal_message_init(&message, sizeof(newlines)));
    assert_false(personal_message_feed(&message, newlines, sizeof(newlines)));
    assert_int_equal(message.received_len, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_web3_vectors),
        cmocka_unit_test(test_review_roundtrip),
        cmocka_unit_test(test_stream_boundaries),
        cmocka_unit_test(test_invalid_input),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
