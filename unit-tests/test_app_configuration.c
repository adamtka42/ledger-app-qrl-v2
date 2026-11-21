#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "os.h"
#include "globals.h"
#include "dispatcher.h"
#include "get_app_configuration.h"
#include "get_app_name.h"
#include "get_public_key.h"
#include "sign_tx.h"
#include "sw.h"

global_ctx_t G_context;
const internal_storage_t N_storage_real = {0};
static internal_storage_t storage, storage_before;
static uint8_t response[16];
static size_t response_len;
static uint16_t response_status;
static unsigned responses;

void *test_pic(const void *address) {
    assert_ptr_equal(address, &N_storage_real);
    return &storage;
}

int io_send_sw(uint16_t status) {
    response_status = status;
    response_len = 0;
    responses++;
    return 0;
}

int io_send_response_pointer(const uint8_t *data, size_t length, uint16_t status) {
    assert_true(length <= sizeof(response));
    memcpy(response, data, length);
    response_len = length;
    response_status = status;
    responses++;
    return 0;
}

int handler_get_app_name(void) {
    fail_msg("Unexpected app name handler");
    return -1;
}

int handler_get_public_key(buffer_t *data, bool display) {
    (void) data;
    (void) display;
    fail_msg("Unexpected key derivation");
    return -1;
}

int handler_get_public_key_chunk(uint8_t index) {
    (void) index;
    fail_msg("Unexpected public key export");
    return -1;
}

int handler_sign_tx(buffer_t *data, uint8_t p1, uint8_t p2) {
    (void) data;
    (void) p1;
    (void) p2;
    fail_msg("Unexpected signing");
    return -1;
}

static command_t configuration_command(void) {
    // Pin the public wire opcode independently of the dispatcher's enum.
    command_t cmd = {.cla = CLA, .ins = 0x0E};
    return cmd;
}

static void test_settings_and_request_are_read_only(void **unused) {
    (void) unused;
    const state_e states[] = {STATE_NONE, STATE_RECEIVING, STATE_PARSED, STATE_APPROVED};
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
        for (unsigned flags = 0; flags < 8; flags++) {
            memset(&G_context, 0xa5, sizeof(G_context));
            G_context.state = states[i];
            const global_ctx_t context_before = G_context;
            memset(&storage, 0x5a, sizeof(storage));
            // Nonzero NVM bytes represent enabled settings, as in the UI/handler.
            storage.enable_blind_signing = flags & 1 ? 0xff : 0;
            storage.display_nonce = flags & 2 ? 2 : 0;
            storage.display_tx_hash = flags & 4 ? 1 : 0;
            storage_before = storage;
            command_t cmd = configuration_command();
            responses = 0;
            assert_int_equal(apdu_dispatcher(&cmd), 0);
            const uint8_t expected[] = {1, (uint8_t) flags, 23, 45, 67};
            assert_int_equal(response_status, SW_OK);
            assert_int_equal(response_len, sizeof(expected));
            assert_memory_equal(response, expected, sizeof(expected));
            assert_int_equal(responses, 1);
            assert_memory_equal(&G_context, &context_before, sizeof(G_context));
            assert_memory_equal(&storage, &storage_before, sizeof(storage));
        }
    }
}

static void test_invalid_commands_preserve_request(void **unused) {
    (void) unused;
    const struct {
        uint8_t cla, p1, p2, lc;
        uint16_t status;
    } cases[] = {{CLA, 1, 0, 0, SW_WRONG_P1P2},
                 {CLA, 0, 1, 0, SW_WRONG_P1P2},
                 {CLA, 255, 255, 0, SW_WRONG_P1P2},
                 {CLA, 0, 0, 1, SW_WRONG_DATA_LENGTH},
                 {CLA, 0, 0, 255, SW_WRONG_DATA_LENGTH},
                 {0xff, 0, 0, 0, SW_CLA_NOT_SUPPORTED}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        command_t cmd = configuration_command();
        cmd.cla = cases[i].cla;
        cmd.p1 = cases[i].p1;
        cmd.p2 = cases[i].p2;
        cmd.lc = cases[i].lc;
        uint8_t data[255] = {0};
        cmd.data = data;
        const global_ctx_t context_before = G_context;
        storage_before = storage;
        assert_int_equal(apdu_dispatcher(&cmd), 0);
        assert_int_equal(response_status, cases[i].status);
        assert_int_equal(response_len, 0);
        assert_memory_equal(&G_context, &context_before, sizeof(G_context));
        assert_memory_equal(&storage, &storage_before, sizeof(storage));
    }
}

static void test_version_remains_compatible(void **unused) {
    (void) unused;
    command_t cmd = configuration_command();
    cmd.ins = GET_VERSION;
    assert_int_equal(apdu_dispatcher(&cmd), 0);
    const uint8_t expected[] = {23, 45, 67};
    assert_int_equal(response_status, SW_OK);
    assert_int_equal(response_len, sizeof(expected));
    assert_memory_equal(response, expected, sizeof(expected));
}

int main(void) {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_settings_and_request_are_read_only),
                                       cmocka_unit_test(test_invalid_commands_preserve_request),
                                       cmocka_unit_test(test_version_remains_compatible)};
    return cmocka_run_group_tests(tests, NULL, NULL);
}
