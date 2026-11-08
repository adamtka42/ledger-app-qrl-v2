#include "sign_personal_message.h"

#include <string.h>

#include "cx.h"
#include "address.h"
#include "dispatcher.h"
#include "display.h"
#include "globals.h"
#include "request_context.h"
#include "send_response.h"
#include "sw.h"

static int abort_message(uint16_t status) {
    reset_request_context();
    return io_send_sw(status);
}

int handler_sign_personal_message(buffer_t *data, uint8_t p1, uint8_t p2) {
    if (p1 > DATA_LAST || p2 > 17 || (p2 != 0 && p1 != DATA_LAST)) {
        return abort_message(SW_WRONG_P1P2);
    }
    if (p1 == DATA_LAST && p2 != 0) {
        if (G_context.req_type != CONFIRM_MESSAGE || G_context.state != STATE_APPROVED ||
            !N_storage.is_sending_signature)
            return io_send_sw(SW_BAD_STATE);
        if (data->size != data->offset) return abort_message(SW_WRONG_DATA_LENGTH);
        return helper_send_response_sig(p2);
    }
    if (p1 == DATA_FIRST) {
        reset_request_context();
        if (!buffer_read_u8(data, &G_context.bip32_path_len) ||
            !buffer_read_bip32_path(data, G_context.bip32_path, G_context.bip32_path_len) ||
            !is_valid_zond_bip32_path(G_context.bip32_path, G_context.bip32_path_len) ||
            data->size - data->offset != 4)
            return abort_message(SW_WRONG_DATA_LENGTH);
        const uint8_t *length = data->ptr + data->offset;
        uint32_t expected = ((uint32_t) length[0] << 24) | ((uint32_t) length[1] << 16) |
                            ((uint32_t) length[2] << 8) | length[3];
        if (!personal_message_init(&G_context.message_info, expected)) {
            return abort_message(SW_WRONG_DATA_LENGTH);
        }
        G_context.req_type = CONFIRM_MESSAGE;
        G_context.state = STATE_RECEIVING;
        return io_send_sw(SW_OK);
    }
    if (G_context.req_type != CONFIRM_MESSAGE || G_context.state != STATE_RECEIVING) {
        return abort_message(SW_BAD_STATE);
    }
    personal_message_t *message = &G_context.message_info;
    size_t length = data->size - data->offset;
    if (length > message->expected_len - message->received_len ||
        (length == 0 && (p1 == DATA_MORE || message->expected_len != 0))) {
        return abort_message(SW_WRONG_DATA_LENGTH);
    }
    if (!personal_message_feed(message, length ? data->ptr + data->offset : NULL, length)) {
        return abort_message(SW_MESSAGE_INVALID);
    }
    if (p1 == DATA_MORE) {
        if (message->received_len == message->expected_len)
            return abort_message(SW_WRONG_DATA_LENGTH);
        return io_send_sw(SW_OK);
    }
    if (!personal_message_finish(message)) return abort_message(SW_WRONG_DATA_LENGTH);
    G_context.state = STATE_PARSED;
    return ui_display_personal_message();
}
