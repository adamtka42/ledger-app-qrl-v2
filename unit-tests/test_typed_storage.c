#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "typed_data_storage.h"

static uint8_t *payload_region;
static size_t writes;
static uint8_t *marker;
static void *last_write;
static bool interrupt_erase;
static jmp_buf erase_interruption;

void *test_pic(const void *address) {
    return (void *) address;
}

void nvm_write(void *dst, const void *src, size_t length) {
    writes++;
    last_write = dst;
    if (length == 1 && src != NULL && *(const uint8_t *) src == 1) marker = dst;
    if (length > 128 && src != NULL) payload_region = dst;
    if (src != NULL)
        memmove(dst, src, length);
    else
        memset(dst, 0, length);
    if (interrupt_erase && length == 128) {
        interrupt_erase = false;
        longjmp(erase_interruption, 1);
    }
}

static bool zero(const void *ptr, size_t length) {
    const uint8_t *bytes = ptr;
    for (size_t i = 0; i < length; i++)
        if (bytes[i] != 0) return false;
    return true;
}

static size_t load(uint8_t out[TYPED_DATA_MAX_PAYLOAD], uint8_t digest[32]) {
    FILE *file = fopen(TYPED_DATA_VECTOR_FILE, "r");
    assert_non_null(file);
    char name[32], hash[65], payload[TYPED_DATA_MAX_PAYLOAD * 2 + 1];
    assert_int_equal(fscanf(file, "%31s %64s %8192s", name, hash, payload), 3);
    fclose(file);
    for (size_t i = 0; i < 32; i++) {
        unsigned value;
        assert_int_equal(sscanf(hash + i * 2, "%2x", &value), 1);
        digest[i] = value;
    }
    size_t length = strlen(payload) / 2;
    for (size_t i = 0; i < length; i++) {
        unsigned value;
        assert_int_equal(sscanf(payload + i * 2, "%2x", &value), 1);
        out[i] = value;
    }
    return length;
}

static void test_stage_parse_erase(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = load(bytes, digest);
    typed_data_session_t session;
    assert_true(typed_data_session_init(&session, length));
    assert_true(typed_data_session_feed(&session, bytes, length));
    uint8_t *raw = payload_region;
    assert_memory_equal(raw, bytes, length);
    assert_true(typed_data_session_finish(&session));
    assert_memory_equal(session.digest, digest, 32);
    assert_string_equal(session.primary_type, "WideValues");
    assert_true(zero(raw, TYPED_DATA_MAX_PAYLOAD));
    const char *review = typed_data_review();
    assert_false(zero(review, TYPED_DATA_REVIEW_BYTES));
    assert_true(session.pair_count > 0);
    uint8_t ui[256];
    memset(ui, 0x5a, sizeof(ui));
    assert_false(typed_data_store_ui(NULL, sizeof(ui)));
    assert_false(typed_data_store_ui(ui, TYPED_DATA_UI_BYTES + 1));
    assert_true(typed_data_store_ui(ui, sizeof(ui)));
    assert_memory_equal(typed_data_ui(), ui, sizeof(ui));
    assert_false(typed_data_session_feed(&session, bytes, 1));
    assert_false(typed_data_session_finish(&session));
    typed_data_storage_clear();
    assert_true(zero(review, TYPED_DATA_REVIEW_BYTES));
    assert_true(zero(typed_data_ui(), TYPED_DATA_UI_BYTES));
    assert_ptr_equal(last_write, marker);
    writes = 0;
    typed_data_storage_clear();
    assert_int_equal(writes, 0);  // Native requests do not cause idle NVM writes.
}

static void test_restart_and_replacement(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = load(bytes, digest);
    typed_data_session_t first, second;
    assert_true(typed_data_session_init(&first, length));
    assert_true(typed_data_session_feed(&first, bytes, length));
    uint8_t *raw = payload_region;
    /* Startup cleanup has no dependency on the lost RAM session. */
    memset(&first, 0, sizeof(first));
    typed_data_storage_clear();
    assert_true(zero(raw, TYPED_DATA_MAX_PAYLOAD));
    assert_true(typed_data_session_init(&first, length));
    assert_true(typed_data_session_feed(&first, bytes, length));
    assert_true(typed_data_session_init(&second, length));
    assert_true(zero(raw, TYPED_DATA_MAX_PAYLOAD));
    assert_false(typed_data_session_feed(&second, NULL, 1));
    assert_false(typed_data_session_feed(&second, bytes, length + 1));
    assert_int_equal(second.received_len, 0);
    assert_false(typed_data_session_finish(&second));
    typed_data_storage_clear();
}

static void test_interrupted_erase_retries(void **state) {
    (void) state;
    uint8_t bytes[TYPED_DATA_MAX_PAYLOAD], digest[32];
    size_t length = load(bytes, digest);
    typed_data_session_t session;
    assert_true(typed_data_session_init(&session, length));
    assert_true(typed_data_session_feed(&session, bytes, length));
    uint8_t *raw = payload_region;
    interrupt_erase = true;
    if (setjmp(erase_interruption) == 0) {
        typed_data_storage_clear();
        fail_msg("Expected simulated power interruption");
    }
    assert_int_equal(*marker, 1);
    typed_data_storage_clear();
    assert_true(zero(raw, TYPED_DATA_MAX_PAYLOAD));
    assert_int_equal(*marker, 0);
    assert_ptr_equal(last_write, marker);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_stage_parse_erase),
        cmocka_unit_test(test_restart_and_replacement),
        cmocka_unit_test(test_interrupted_erase_retries),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
