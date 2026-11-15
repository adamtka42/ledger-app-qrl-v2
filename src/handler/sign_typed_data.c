#include "sign_typed_data.h"

#include "dispatcher.h"
#include "display.h"
#include "globals.h"
#include "request_context.h"
#include "message_session.h"
#include "sw.h"

static int abort_typed_data(uint16_t status) {
    reset_request_context();
    return io_send_sw(status);
}

int handler_sign_typed_data(buffer_t *data, uint8_t p1, uint8_t p2) {
    if (!sign_command_p1p2_valid(p1, p2)) return abort_typed_data(SW_WRONG_P1P2);
    if (p2 != 0) {
        return message_send_signature_chunk(data, CONFIRM_TYPED_DATA, p2, abort_typed_data);
    }
    if (p1 == DATA_FIRST) {
        reset_request_context();
        uint32_t expected;
        if (!message_read_header(data, &expected) ||
            !typed_data_session_init(&G_context.typed_data, expected))
            return abort_typed_data(SW_WRONG_DATA_LENGTH);
        G_context.req_type = CONFIRM_TYPED_DATA;
        G_context.state = STATE_RECEIVING;
        return io_send_sw(SW_OK);
    }
    if (G_context.req_type != CONFIRM_TYPED_DATA || G_context.state != STATE_RECEIVING) {
        return abort_typed_data(SW_BAD_STATE);
    }
    typed_data_session_t *session = &G_context.typed_data;
    size_t length = data->size - data->offset;
    if (length == 0 || !typed_data_session_feed(session, data->ptr + data->offset, length)) {
        return abort_typed_data(SW_WRONG_DATA_LENGTH);
    }
    if (p1 == DATA_MORE) {
        if (session->received_len == session->expected_len)
            return abort_typed_data(SW_WRONG_DATA_LENGTH);
        return io_send_sw(SW_OK);
    }
    if (session->received_len != session->expected_len)
        return abort_typed_data(SW_WRONG_DATA_LENGTH);
#ifdef SCREEN_SIZE_WALLET
    typed_data_page_length_t page_length = ui_typed_data_page_length;
#else
    typed_data_page_length_t page_length = NULL;
#endif
    if (!typed_data_session_finish(session, page_length))
        return abort_typed_data(SW_TYPED_DATA_INVALID);
    G_context.state = STATE_PARSED;
    return ui_display_typed_data();
}
