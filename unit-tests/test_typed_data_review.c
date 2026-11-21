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
#include "nbgl_fonts.h"
#include "nbgl_layout.h"
#include "permit.h"
#include "request_context.h"
#include "sw.h"

global_ctx_t G_context;
const uint8_t C_app_qrl_64px = 0;
const uint8_t C_app_qrl_14px = 0;
static const nbgl_contentTagValueList_t *review;
static bool derive_failure, format_failure, store_failure, spinner_active;
static unsigned menu_calls, reset_calls, font_calls;
static uint16_t expected_error, response;
static bool layout_failure;
static const char *expected_title = "Review typed data";
static const char *expected_finish = "Sign message";

void *test_pic(const void *address) {
    return (void *) address;
}

void nvm_write(void *destination, const void *source, size_t length) {
    memcpy(destination, source, length);
}

void reset_request_context(void) {
    typed_data_storage_clear();
    memset(&G_context, 0, sizeof(G_context));
    reset_calls++;
}

int io_send_sw(uint16_t status) {
    const global_ctx_t empty = {0};
    assert_int_equal(status, expected_error);
    assert_memory_equal(&G_context, &empty, sizeof(G_context));
    assert_int_equal(menu_calls, 1);
    assert_false(spinner_active);
    assert_int_equal(typed_data_review()[0], '\0');
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
    (void) path;
    (void) path_len;
    memset(address, 0x33, ADDRESS_SIZE);
    return derive_failure ? CX_INTERNAL_ERROR : CX_OK;
}

bool __real_format_checksummed_address(const uint8_t address[ADDRESS_SIZE],
                                       char *out,
                                       size_t length);
bool __wrap_format_checksummed_address(const uint8_t address[ADDRESS_SIZE],
                                       char *out,
                                       size_t length) {
    return !format_failure && __real_format_checksummed_address(address, out, length);
}

bool __real_typed_data_store_ui(const void *bytes, size_t length);
bool __wrap_typed_data_store_ui(const void *bytes, size_t length) {
    return !store_failure && __real_typed_data_store_ui(bytes, length);
}

bool validate_typed_data(bool choice) {
    return choice;
}

void nbgl_useCaseSpinner(const char *text) {
    assert_non_null(text);
    spinner_active = true;
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
    assert_string_equal(title, expected_title);
    assert_null(subtitle);
    assert_string_equal(finish, expected_finish);
    assert_non_null(choice);
    assert_true(pairs->wrapping);
    spinner_active = false;
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
#else
#define MOCK_MAX_FRAGMENT_LEN 40u
#endif

bool nbgl_getTextMaxLenInNbLines(unsigned font,
                                 const char *text,
                                 uint16_t width,
                                 uint16_t lines,
                                 uint16_t *length,
                                 bool wrapping) {
#ifdef SCREEN_SIZE_WALLET
    assert_int_equal(font, LARGE_MEDIUM_FONT);
#else
    assert_int_equal(font, BAGL_FONT_OPEN_SANS_REGULAR_11px_1bpp);
#endif
    assert_int_equal(width, AVAILABLE_WIDTH);
    assert_true(lines > 0 && lines <= NB_MAX_LINES_IN_REVIEW);
    assert_true(wrapping);
    font_calls++;
    size_t limit = lines * 20;
    size_t available = strlen(text);
    *length = available < limit ? available : limit;
    return available > limit;
}

#ifdef SCREEN_SIZE_WALLET
uint8_t nbgl_useCaseGetNbTagValuesInPage(uint8_t nbPairs,
                                         const nbgl_contentTagValueList_t *list,
                                         uint8_t startIndex,
                                         bool *requireSpecificDisplay) {
    assert_int_equal(nbPairs, 1);
    assert_int_equal(startIndex, 0);
    assert_true(list->wrapping);
    assert_int_equal(list->nbPairs, 1);
    assert_non_null(list->pairs);
    const char *title = list->pairs[0].item;
    assert_non_null(title);
    const char suffix[] = " (64/64)";
    size_t length = strlen(title);
    assert_true(length > strlen(suffix));
    assert_string_equal(title + length - strlen(suffix), suffix);
    *requireSpecificDisplay =
        layout_failure || strlen(list->pairs[0].value) > MOCK_MAX_FRAGMENT_LEN;
    return 1;
}
#else
uint8_t nbgl_getTextNbPagesInWidth(unsigned font, const char *text, uint8_t lines, uint16_t width) {
    assert_int_equal(font, BAGL_FONT_OPEN_SANS_REGULAR_11px_1bpp);
    assert_int_equal(width, AVAILABLE_WIDTH);
    assert_int_equal(lines, NB_MAX_LINES_IN_REVIEW);
    return layout_failure || strlen(text) > MOCK_MAX_FRAGMENT_LEN ? 2 : 1;
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
    return ui_typed_data_page_length;
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
        assert_string_equal(review->pairs[0].item, "Sign with");
        assert_int_equal(strlen(review->pairs[0].value), 1 + 2 * ADDRESS_SIZE);
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
                assert_true(count <= MOCK_MAX_FRAGMENT_LEN);
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
}

static void test_schema_account_is_distinct_from_signer(void **state) {
    (void) state;
    reset_request_context();
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD];
    size_t length = vector("permission", bytes);
    size_t renamed = 0;
    for (size_t i = 0; i + 7 <= length; i++) {
        if (memcmp(bytes + i, "spender", 7) == 0) {
            memcpy(bytes + i, "Account", 7);
            renamed++;
        }
    }
    assert_int_equal(renamed, 1);
    typed_data_session_t *session = &G_context.typed_data;
    assert_true(typed_data_session_init(session, length));
    assert_true(typed_data_session_feed(session, bytes, length));
    assert_true(typed_data_session_finish(session, page_length()));
    G_context.req_type = CONFIRM_TYPED_DATA;
    G_context.state = STATE_PARSED;
    assert_int_equal(ui_display_typed_data(), 0);
    assert_string_equal(review->pairs[0].item, "Sign with");

    uint8_t field_address[ADDRESS_SIZE];
    memset(field_address, 0x11, sizeof(field_address));
    char field_text[1 + 2 * ADDRESS_SIZE + 1], signing_text[sizeof(field_text)];
    assert_true(format_checksummed_address(field_address, field_text, sizeof(field_text)));
    assert_true(format_checksummed_address(G_context.address, signing_text, sizeof(signing_text)));
    assert_string_equal(review->pairs[0].value, signing_text);
    assert_string_not_equal(signing_text, field_text);
    size_t found = 0, used = 0;
    char displayed[sizeof(field_text)];
    for (size_t i = 1; i < review->nbPairs; i++) {
        const nbgl_contentTagValue_t *pair = &review->pairs[i];
        assert_string_not_equal(pair->item, "Sign with");
        if (strcmp(pair->item, "Account") == 0 || strncmp(pair->item, "Account (", 9) == 0) {
            size_t count = strlen(pair->value);
            assert_true(count < sizeof(displayed) - used);
            memcpy(displayed + used, pair->value, count);
            used += count;
            found++;
        }
    }
    displayed[used] = '\0';
    assert_true(found > 0);
    assert_string_equal(displayed, field_text);
    reset_request_context();
}

/* Issuer-signed metadata for the token named by the permit fixtures. */
static void provide_token(typed_data_session_t *session) {
    token_metadata_t *metadata = &session->token_metadata;
    memset(metadata, 0, sizeof(*metadata));
    metadata->chain_id[sizeof(metadata->chain_id) - 1] = 1;
    memset(metadata->contract, 0x22, sizeof(metadata->contract));
    metadata->decimals = 6;
    memcpy(metadata->symbol, "TKN", 4);
    metadata->verified = true;
}

static void start_permit(const char *name, bool with_token) {
    reset_request_context();
    review = NULL;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD];
    size_t length = vector(name, bytes);
    typed_data_session_t *session = &G_context.typed_data;
    assert_true(typed_data_session_init(session, length));
    if (with_token) provide_token(session);
    assert_true(typed_data_session_feed(session, bytes, length));
    assert_true(typed_data_session_finish(session, page_length()));
    G_context.req_type = CONFIRM_TYPED_DATA;
    G_context.state = STATE_PARSED;
}

/* Join the fragments of one labelled value, returning how many rows it used. */
static size_t joined_value(size_t first, const char *label, char *out, size_t size) {
    size_t used = 0, count = 0, label_length = strlen(label);
    for (size_t i = first; i < review->nbPairs; i++) {
        const nbgl_contentTagValue_t *pair = &review->pairs[i];
        if (strncmp(pair->item, label, label_length) != 0 ||
            (pair->item[label_length] != '\0' && pair->item[label_length] != ' '))
            break;
        size_t length = strlen(pair->value);
        assert_true(length < size - used);
        memcpy(out + used, pair->value, length);
        used += length;
        count++;
    }
    out[used] = '\0';
    return count;
}

static void test_permit_review(void **state) {
    (void) state;
    static const struct {
        const char *name, *title, *finish, *limit;
        bool own;
    } cases[] = {
        {"permit", "Review token spending permit", "Sign token\nspending permit", "TKN 25", true},
        {"permit_revoke",
         "Review token permit revocation",
         "Sign token\npermit revocation",
         "TKN 0",
         true},
        {"permit_other",
         "Review unlimited spending permit",
         "Sign unlimited\nspending permit",
         "TKN Unlimited",
         false},
    };
    char text[1 + 2 * ADDRESS_SIZE + 1], expected[sizeof(text)];
    uint8_t address[ADDRESS_SIZE];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        start_permit(cases[i].name, true);
        expected_title = cases[i].title;
        expected_finish = cases[i].finish;
        assert_int_equal(ui_display_typed_data(), 0);
        assert_non_null(review);
        assert_string_equal(review->pairs[0].item, "Sign with");
        assert_true(format_checksummed_address(G_context.address, expected, sizeof(expected)));
        assert_string_equal(review->pairs[0].value, expected);

        /* The owner is shown only when it is not the signing account. */
        size_t next = 1 + joined_value(1, "Token owner", text, sizeof(text));
        if (cases[i].own) {
            assert_int_equal(next, 1);
        } else {
            memset(address, 0x44, sizeof(address));
            assert_true(format_checksummed_address(address, expected, sizeof(expected)));
            assert_true(next > 1);
            assert_string_equal(text, expected);
        }
        assert_string_equal(review->pairs[next].item, "Spending limit");
        assert_string_equal(review->pairs[next++].value, cases[i].limit);
        memset(address, 0x11, sizeof(address));
        assert_true(format_checksummed_address(address, expected, sizeof(expected)));
        size_t rows = joined_value(next, "Spender", text, sizeof(text));
        assert_true(rows > 0);
        assert_string_equal(text, expected);
        next += rows;
        memset(address, 0x22, sizeof(address));
        assert_true(format_checksummed_address(address, expected, sizeof(expected)));
#ifdef SCREEN_SIZE_WALLET
        rows = joined_value(next, "Token contract", text, sizeof(text));
#else
        rows = joined_value(next, "Contract", text, sizeof(text));  // fits a Nano title
#endif
        assert_true(rows > 0);
        assert_string_equal(text, expected);
        next += rows;
        assert_string_equal(review->pairs[next].item, "Chain ID");
        assert_string_equal(review->pairs[next++].value, "1");
        assert_string_equal(review->pairs[next].item, "Valid until");
        assert_string_equal(review->pairs[next++].value, "2033-05-18 03:33:20 UTC");
        assert_string_equal(review->pairs[next].item, "Permit nonce");
        assert_string_equal(review->pairs[next++].value, "7");
        assert_int_equal(next, review->nbPairs);
        for (size_t pair = 0; pair < review->nbPairs; pair++) {
            assert_string_not_equal(review->pairs[pair].item, "Primary type");
            assert_true(strlen(review->pairs[pair].value) <= MOCK_MAX_FRAGMENT_LEN || pair == 0);
        }
    }
    expected_title = "Review typed data";
    expected_finish = "Sign message";
    reset_request_context();
}

static void test_permit_without_token_is_generic(void **state) {
    (void) state;
    start_permit("permit", false);
    assert_int_equal(G_context.typed_data.permit_kind, PERMIT_NONE);
    assert_int_equal(ui_display_typed_data(), 0);
    assert_string_equal(review->pairs[1].item, "Primary type");
    assert_string_equal(review->pairs[1].value, "Permit");

    /* Unauthenticated metadata is the same as none. */
    reset_request_context();
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD];
    size_t length = vector("permit", bytes);
    typed_data_session_t *session = &G_context.typed_data;
    assert_true(typed_data_session_init(session, length));
    provide_token(session);
    session->token_metadata.verified = false;
    assert_true(typed_data_session_feed(session, bytes, length));
    assert_true(typed_data_session_finish(session, page_length()));
    assert_int_equal(session->permit_kind, PERMIT_NONE);
    reset_request_context();
}

static void test_permit_review_rejects_inconsistent_session(void **state) {
    (void) state;
    for (int corruption = 0; corruption < 2; corruption++) {
        start_permit("permit", true);
        typed_data_session_t *session = &G_context.typed_data;
        assert_int_equal(session->permit_kind, PERMIT_LIMITED);
        if (corruption == 0)
            session->permit_owner_pairs = (uint8_t) (session->pair_count + 1);
        else
            session->permit_owner = TYPED_DATA_REVIEW_BYTES - ADDRESS_SIZE + 1;
        menu_calls = 0;
        expected_error = SW_BAD_STATE;
        response = 0;
        assert_int_equal(ui_display_typed_data(), 0);
        assert_int_equal(response, SW_BAD_STATE);
        assert_null(review);
    }
}

static void test_label_length_boundary(void **state) {
    (void) state;
    /* 39 bytes plus " (64/64)" and NUL exactly fills the 48-byte title. */
    char label[41], text[] = "hello";
    memset(label, 'A', sizeof(label));
    label[39] = '\0';
    assert_int_equal(ui_typed_data_page_length(label, text), strlen(text));
    unsigned previous_calls = font_calls;
    label[39] = 'A';
    label[40] = '\0';
    assert_int_equal(ui_typed_data_page_length(label, text), 0);
    assert_int_equal(font_calls, previous_calls);
    assert_string_equal(text, "hello");
}

static void test_preparation_errors_restore_menu(void **state) {
    (void) state;
    for (unsigned failure = 0; failure < 6; failure++) {
        derive_failure = format_failure = store_failure = false;
        reset_request_context();
        review = NULL;
        menu_calls = 0;
        spinner_active = false;
        response = 0;
        uint8_t bytes[TYPED_DATA_MAX_PAYLOAD];
        size_t length = vector("permission", bytes);
        typed_data_session_t *session = &G_context.typed_data;
        assert_true(typed_data_session_init(session, length));
        assert_true(typed_data_session_feed(session, bytes, length));
        assert_true(typed_data_session_finish(session, page_length()));
        G_context.req_type = CONFIRM_TYPED_DATA;
        G_context.state = STATE_PARSED;
        reset_calls = 0;
        expected_error = SW_BAD_STATE;
        switch (failure) {
            case 0:
                G_context.req_type = CONFIRM_TRANSACTION;
                break;
            case 1:
                G_context.state = STATE_RECEIVING;
                break;
            case 2:
                session->finished = false;
                break;
            case 3:
                derive_failure = true;
                expected_error = SW_DISPLAY_ADDRESS_FAIL;
                break;
            case 4:
                format_failure = true;
                expected_error = SW_DISPLAY_ADDRESS_FAIL;
                break;
            case 5:
                store_failure = true;
                break;
        }
        assert_int_equal(ui_display_typed_data(), 0);
        assert_int_equal(response, expected_error);
        assert_int_equal(reset_calls, 1);
        assert_null(review);
    }
    derive_failure = format_failure = store_failure = false;
    expected_error = 0;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_review_roundtrip),
        cmocka_unit_test(test_layout_rejection_restores_text),
        cmocka_unit_test(test_schema_account_is_distinct_from_signer),
        cmocka_unit_test(test_permit_review),
        cmocka_unit_test(test_permit_without_token_is_generic),
        cmocka_unit_test(test_permit_review_rejects_inconsistent_session),
        cmocka_unit_test(test_label_length_boundary),
        cmocka_unit_test(test_preparation_errors_restore_menu),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
