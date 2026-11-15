/* Exercise parser pagination with the production NBGL measurement callback. */
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

global_ctx_t G_context;
const uint8_t C_app_qrl_64px = 0;
const uint8_t C_app_qrl_14px = 0;
static const nbgl_contentTagValueList_t *review;
#ifdef SCREEN_SIZE_WALLET
static bool layout_failure;
#endif

void *test_pic(const void *address) {
    return (void *) address;
}

void nvm_write(void *destination, const void *source, size_t length) {
    memcpy(destination, source, length);
}

void reset_request_context(void) {
    typed_data_storage_clear();
    memset(&G_context, 0, sizeof(G_context));
}

int io_send_sw(uint16_t status) {
    fail_msg("Unexpected UI error: %04x", status);
    return 0;
}

void ui_menu_main(void) {
}

cx_err_t address_from_bip32_path(const uint32_t path[],
                                 size_t path_len,
                                 uint8_t address[ADDRESS_SIZE]) {
    (void) path;
    (void) path_len;
    memset(address, 0x11, ADDRESS_SIZE);
    return CX_OK;
}

bool validate_typed_data(bool choice) {
    return choice;
}

void nbgl_useCaseSpinner(const char *text) {
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
    assert_string_equal(title, "Review typed data");
    assert_null(subtitle);
    assert_string_equal(finish, "Sign message");
    assert_non_null(choice);
    assert_true(pairs->wrapping);
    review = pairs;
}

void nbgl_useCaseReviewStatus(int status, void (*done)(void)) {
    (void) status;
    assert_non_null(done);
}

void nbgl_useCaseStatus(const char *text, bool success, void (*done)(void)) {
    (void) text;
    (void) success;
    assert_non_null(done);
}

#ifdef SCREEN_SIZE_WALLET
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
    *requireSpecificDisplay =
        layout_failure || strlen(list->pairs[0].value) > MOCK_MAX_FRAGMENT_LEN;
    return 1;
}
#endif

static size_t vector(const char *name, uint8_t bytes[TYPED_DATA_MAX_PAYLOAD]) {
    FILE *file = fopen(TYPED_DATA_VECTOR_FILE, "r");
    assert_non_null(file);
    char found[32], hash[65], payload[2 * TYPED_DATA_MAX_PAYLOAD + 1];
    while (fscanf(file, "%31s %64s %8192s", found, hash, payload) == 3) {
        if (strcmp(found, name) != 0) continue;
        fclose(file);
        size_t length = strlen(payload) / 2;
        for (size_t i = 0; i < length; i++) {
            unsigned value;
            assert_int_equal(sscanf(payload + i * 2, "%2x", &value), 1);
            bytes[i] = (uint8_t) value;
        }
        return length;
    }
    fclose(file);
    fail_msg("Missing vector %s", name);
    return 0;
}

static typed_data_page_length_t page_length(void) {
#ifdef SCREEN_SIZE_WALLET
    return ui_typed_data_page_length;
#else
    return NULL;
#endif
}

static void test_review_roundtrip(void **state) {
    (void) state;
    const char *names[] = {"permission", "wide", "long_values", "nested", "arrays", "empty_struct"};
    typed_data_t whole;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD];
    for (size_t sample = 0; sample < sizeof(names) / sizeof(names[0]); sample++) {
        reset_request_context();
        review = NULL;
        size_t length = vector(names[sample], bytes);
        assert_true(typed_data_init(&whole, length));
        assert_true(typed_data_feed(&whole, bytes, length));
        assert_true(typed_data_finish(&whole, NULL));
        typed_data_session_t *session = &G_context.typed_data;
        assert_true(typed_data_session_init(session, length));
        assert_true(typed_data_session_feed(session, bytes, length));
        assert_true(typed_data_session_finish(session, page_length()));
        G_context.req_type = CONFIRM_TYPED_DATA;
        G_context.state = STATE_PARSED;
        assert_int_equal(ui_display_typed_data(), 0);
        assert_non_null(review);
        assert_memory_equal(session->digest, whole.digest, sizeof(whole.digest));
        size_t extra = 2 + !session->has_chain_id + !session->has_verifying_contract;
        assert_int_equal(review->nbPairs, extra + session->pair_count);
        assert_string_equal(review->pairs[0].item, "Account");
        assert_int_equal(strlen(review->pairs[0].value), 1 + 2 * ADDRESS_SIZE);
#ifndef SCREEN_SIZE_WALLET
        assert_int_equal(session->pair_count, whole.pair_count);
#endif
        size_t next = 0;
        for (size_t field = 0; field < whole.pair_count; field++) {
            const char *label = whole.review + whole.pairs[field].label;
            const char *value = whole.review + whole.pairs[field].value;
            size_t remaining = strlen(value), first = next;
            do {
                assert_true(next < session->pair_count);
                const nbgl_contentTagValue_t *pair = &review->pairs[extra + next];
                assert_true(pair->forcePageStart);
                size_t count = strlen(pair->value);
                assert_true(count > 0 && count <= remaining);
#ifdef SCREEN_SIZE_WALLET
                assert_true(count <= MOCK_MAX_FRAGMENT_LEN);
#endif
                assert_memory_equal(pair->value, value, count);
                value += count;
                remaining -= count;
                next++;
            } while (remaining != 0);
            size_t parts = next - first;
            for (size_t i = first; i < next; i++) {
                char expected[48];
                if (parts == 1)
                    snprintf(expected, sizeof(expected), "%s", label);
                else
                    snprintf(expected,
                             sizeof(expected),
                             "%s (%u/%u)",
                             label,
                             (unsigned) (i - first + 1),
                             (unsigned) parts);
                assert_string_equal(review->pairs[extra + i].item, expected);
            }
        }
        assert_int_equal(next, session->pair_count);
        /* Revisit immutable NVM descriptors as NBGL does on backwards navigation. */
        for (size_t i = review->nbPairs; i-- > extra;) {
            assert_non_null(review->pairs[i].item);
            assert_non_null(review->pairs[i].value);
        }
    }
    reset_request_context();
}

static void test_layout_rejection_restores_text(void **state) {
    (void) state;
#ifdef SCREEN_SIZE_WALLET
    char text[201], original[sizeof(text)];
    memset(text, 'W', sizeof(text) - 1);
    text[sizeof(text) - 1] = '\0';
    memcpy(original, text, sizeof(text));
    layout_failure = true;
    assert_int_equal(ui_typed_data_page_length("longFieldName", text), 0);
    assert_memory_equal(text, original, sizeof(text));
    layout_failure = false;
    size_t count = ui_typed_data_page_length("longFieldName", text);
    assert_true(count > 0 && count <= MOCK_MAX_FRAGMENT_LEN);
    assert_memory_equal(text, original, sizeof(text));
#endif
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_review_roundtrip),
        cmocka_unit_test(test_layout_rejection_restores_text),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
