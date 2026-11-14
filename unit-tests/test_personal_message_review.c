/* Exercise the production NBGL callback with real message preparation. */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "os.h"
#include "address.h"
#include "display.h"
#include "globals.h"
#include "nbgl_use_case.h"
#include "request_context.h"
#include "sw.h"

global_ctx_t G_context;
const uint8_t C_app_qrl_64px = 0;
const uint8_t C_app_qrl_14px = 0;
static const nbgl_contentTagValueList_t *review;
static void (*choice_callback)(bool);
static bool derive_ok, sign_ok, spinner_active;
static unsigned menu_calls;
static unsigned reset_calls, validation_calls;
static uint16_t response;
static int displayed_status;
static const char *failure_text;

void reset_request_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    reset_calls++;
}

int io_send_sw(uint16_t status) {
    const global_ctx_t empty = {0};
    assert_memory_equal(&G_context, &empty, sizeof(G_context));
    assert_false(spinner_active);
    assert_int_equal(menu_calls, 1);
    response = status;
    return 0;
}

void ui_menu_main(void) {
    spinner_active = false;
    menu_calls++;
}

cx_err_t address_from_bip32_path(const uint32_t path[],
                                 size_t path_len,
                                 uint8_t address[ADDRESS_SIZE]) {
    assert_ptr_equal(path, G_context.bip32_path);
    assert_int_equal(path_len, 5);
    memset(address, 0x11, ADDRESS_SIZE);
    return derive_ok ? CX_OK : CX_INTERNAL_ERROR;
}

bool validate_personal_message(bool choice) {
    validation_calls++;
    reset_request_context();
    return choice && sign_ok;
}

void nbgl_useCaseSpinner(const char *text) {
    spinner_active = true;
    assert_non_null(text);
}

void nbgl_useCaseReview(int type,
                        const nbgl_contentTagValueList_t *pairs,
                        const void *icon,
                        const char *title,
                        const char *subtitle,
                        const char *finish,
                        void (*choice)(bool)) {
    assert_int_equal(type, TYPE_MESSAGE);
    assert_non_null(icon);
    assert_string_equal(title, "Review message");
    assert_null(subtitle);
    assert_string_equal(finish, "Sign message");
    assert_null(pairs->pairs);
    assert_non_null(pairs->callback);
    assert_true(pairs->wrapping);
    spinner_active = false;
    review = pairs;
    choice_callback = choice;
}

void nbgl_useCaseReviewStatus(int status, void (*done)(void)) {
    assert_non_null(done);
    displayed_status = status;
}

void nbgl_useCaseStatus(const char *text, bool success, void (*done)(void)) {
    assert_non_null(done);
    assert_false(success);
    failure_text = text;
}

#ifdef SCREEN_SIZE_WALLET
/* Deterministic font/layout substitutes. Real-device tests exercise the actual
 * SDK metrics; here a tight layout forces the fallback to a shorter page. */
#define MOCK_MAX_FRAGMENT_LEN 160u
bool nbgl_getTextMaxLenInNbLines(unsigned font,
                                 const char *text,
                                 uint16_t width,
                                 uint16_t lines,
                                 uint16_t *length,
                                 bool wrapping) {
    (void) font;
    (void) width;
    assert_true(wrapping);
    size_t limit = lines * 20;
    size_t available = strlen(text);
    *length = available < limit ? available : limit;
    return available > limit;
}

uint8_t nbgl_useCaseGetNbTagValuesInPage(uint8_t nbPairs,
                                         const nbgl_contentTagValueList_t *list,
                                         uint8_t startIndex,
                                         bool *requireSpecificDisplay) {
    assert_int_equal(nbPairs, 1);
    assert_int_equal(startIndex, 0);
    assert_true(list->wrapping);
    *requireSpecificDisplay = strlen(list->pairs[0].value) > MOCK_MAX_FRAGMENT_LEN;
    return 1;
}
#endif

static void prepare(const char *text, size_t length) {
    memset(&G_context, 0, sizeof(G_context));
    G_context.req_type = CONFIRM_MESSAGE;
    G_context.state = STATE_PARSED;
    G_context.bip32_path_len = 5;
    assert_true(personal_message_init(&G_context.message_info, length));
    assert_true(personal_message_feed(&G_context.message_info, (const uint8_t *) text, length));
    assert_true(personal_message_finish(&G_context.message_info));
    derive_ok = true;
    sign_ok = true;
    spinner_active = false;
    menu_calls = 0;
    review = NULL;
    choice_callback = NULL;
    reset_calls = validation_calls = response = 0;
    displayed_status = -1;
    failure_text = NULL;
}

static void check_review(const char *text, size_t length) {
    prepare(text, length);
    uint8_t digest[32];
    memcpy(digest, G_context.message_info.digest, sizeof(digest));
    assert_int_equal(ui_display_personal_message(), 0);
    assert_non_null(review);
    assert_true(review->nbPairs >= 3 && review->nbPairs <= 2 + PERSONAL_MESSAGE_MAX_PARTS);
    assert_memory_equal(G_context.message_info.digest, digest, sizeof(digest));
#ifndef SCREEN_SIZE_WALLET
    assert_int_equal(review->nbPairs, 3);
#endif

    char expected_length[11];
    snprintf(expected_length, sizeof(expected_length), "%u", (unsigned) length);
    const nbgl_contentTagValue_t *pair = review->callback(0);
    assert_non_null(pair);
    assert_string_equal(pair->item, "Account");
    assert_int_equal(strlen(pair->value), 1 + 2 * ADDRESS_SIZE);
    assert_false(pair->forcePageStart);
    pair = review->callback(1);
    assert_string_equal(pair->item, "Length (bytes)");
    assert_string_equal(pair->value, expected_length);
    assert_false(pair->forcePageStart);

    /* Snapshot the returned values before the next callback reuses its cache. */
    const char *parts[PERSONAL_MESSAGE_MAX_PARTS];
    size_t position = 0;
    for (size_t index = 2; index < review->nbPairs; index++) {
        pair = review->callback(index);
        assert_non_null(pair);
        assert_true(pair->forcePageStart);
#ifdef SCREEN_SIZE_WALLET
        /* A fragment must fit the mock layout, even if its text roundtrips. */
        assert_true(strlen(pair->value) <= MOCK_MAX_FRAGMENT_LEN);
#endif
        if (length == 0) {
            assert_string_equal(pair->value, "<empty message>");
        } else {
            size_t size = strlen(pair->value);
            assert_true(size <= PERSONAL_MESSAGE_MAX_LEN);
            assert_true(size <= length - position);
            assert_memory_equal(pair->value, text + position, size);
            position += size;
        }
        parts[index - 2] = pair->value;
    }
    assert_int_equal(position, length);

    /* NBGL also revisits pairs when paginating and when navigating backwards. */
    for (size_t index = review->nbPairs; index-- > 2;) {
        pair = review->callback(index);
        assert_string_equal(pair->value, parts[index - 2]);
        char expected_label[24];
        if (review->nbPairs == 3) {
            snprintf(expected_label, sizeof(expected_label), "Message");
        } else {
            snprintf(expected_label,
                     sizeof(expected_label),
                     "Message (%u/%u)",
                     (unsigned) index - 1,
                     (unsigned) review->nbPairs - 2);
        }
        assert_string_equal(pair->item, expected_label);
        /* Account/length retrieval must not overwrite the visible message label. */
        const char *label = pair->item;
        assert_string_equal(review->callback(0)->item, "Account");
        assert_string_equal(review->callback(1)->value, expected_length);
        assert_string_equal(label, expected_label);
    }
    assert_null(review->callback(review->nbPairs));
    assert_null(review->callback(UINT8_MAX));
    assert_memory_equal(G_context.message_info.digest, digest, sizeof(digest));
    reset_request_context();
    assert_null(review->callback(0));
    assert_null(review->callback(2));
}

static void test_review_callback_roundtrip(void **state) {
    (void) state;
    char text[PERSONAL_MESSAGE_MAX_LEN];
    for (size_t i = 0; i < sizeof(text); i++) text[i] = 'A' + i % 26;
    const size_t lengths[] = {0, 1, 63, 64, 65, 127, 128, 129, sizeof(text)};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        check_review(text, lengths[i]);
    }
    memset(text, '\n', PERSONAL_MESSAGE_MAX_NEWLINES);
    check_review(text, sizeof(text));
    check_review(text, PERSONAL_MESSAGE_MAX_NEWLINES);
    check_review("Login\nNonce: 123456", strlen("Login\nNonce: 123456"));
}

static void test_review_lifetime_and_decision(void **state) {
    (void) state;
    for (int decision = 0; decision < 3; decision++) {
        prepare("hello", 5);
        assert_int_equal(ui_display_personal_message(), 0);
        sign_ok = (decision != 2);
        choice_callback(decision != 0);
        assert_int_equal(validation_calls, 1);
        assert_null(review->callback(2));
        if (decision == 2) {
            assert_string_equal(failure_text, "Message signing failed");
            assert_int_equal(displayed_status, -1);
        } else {
            assert_int_equal(
                displayed_status,
                decision == 0 ? STATUS_TYPE_MESSAGE_REJECTED : STATUS_TYPE_MESSAGE_SIGNED);
        }
    }
}

static void test_callback_guards_individually(void **state) {
    (void) state;
    prepare("hello", 5);
    assert_int_equal(ui_display_personal_message(), 0);
    assert_non_null(review);

    /* Keep the other guards valid so each condition is independently tested. */
    G_context.req_type = CONFIRM_TRANSACTION;
    assert_null(review->callback(0));
    assert_null(review->callback(2));
    G_context.req_type = CONFIRM_MESSAGE;
    assert_string_equal(review->callback(2)->value, "hello");

    G_context.state = STATE_RECEIVING;
    assert_null(review->callback(0));
    assert_null(review->callback(2));
    G_context.state = STATE_PARSED;
    assert_string_equal(review->callback(2)->value, "hello");

    G_context.message_info.review_prepared = false;
    assert_null(review->callback(0));
    assert_null(review->callback(2));
    G_context.message_info.review_prepared = true;
    assert_string_equal(review->callback(2)->value, "hello");
}

static void test_review_preparation_errors(void **state) {
    (void) state;
    prepare("hello", 5);
    derive_ok = false;
    assert_int_equal(ui_display_personal_message(), 0);
    assert_int_equal(response, SW_DISPLAY_ADDRESS_FAIL);
    assert_int_equal(reset_calls, 1);
    assert_null(review);

    prepare("hello", 5);
    G_context.state = STATE_RECEIVING;
    assert_int_equal(ui_display_personal_message(), 0);
    assert_int_equal(response, SW_BAD_STATE);
    assert_int_equal(reset_calls, 1);
    assert_null(review);

    prepare("hello", 5);
    G_context.message_info.review_prepared = true;
    assert_int_equal(ui_display_personal_message(), 0);
    assert_int_equal(response, SW_BAD_STATE);
    assert_int_equal(reset_calls, 1);
    assert_null(review);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_review_callback_roundtrip),
        cmocka_unit_test(test_review_lifetime_and_decision),
        cmocka_unit_test(test_review_preparation_errors),
        cmocka_unit_test(test_callback_guards_individually),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
