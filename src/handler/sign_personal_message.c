#include "sign_personal_message.h"

#include "dispatcher.h"
#include "display.h"
#include "globals.h"
#include "request_context.h"
#include "message_session.h"
#include "sw.h"

static int abort_message(uint16_t status) {
    reset_request_context();
    return io_send_sw(status);
}

int handler_sign_personal_message(buffer_t *data, uint8_t p1, uint8_t p2) {
    if (!sign_command_p1p2_valid(p1, p2)) return abort_message(SW_WRONG_P1P2);
    if (p2 != 0) return message_send_signature_chunk(data, CONFIRM_MESSAGE, p2, abort_message);
    if (p1 == DATA_FIRST) {
        reset_request_context();
        uint32_t expected;
        if (!message_read_header(data, &expected) ||
            !personal_message_init(&G_context.message_info, expected)) {
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
