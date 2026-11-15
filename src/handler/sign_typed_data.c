#include "sign_typed_data.h"

#include <string.h>

#include "cx.h"
#include "address.h"
#include "dispatcher.h"
#include "display.h"
#include "globals.h"
#include "request_context.h"
#include "send_response.h"
#include "sw.h"

static int abort_typed_data(uint16_t status) {
    reset_request_context();
    return io_send_sw(status);
}

int handler_sign_typed_data(buffer_t *data, uint8_t p1, uint8_t p2) {
    if (p1 > DATA_LAST || p2 > 17 || (p2 != 0 && p1 != DATA_LAST)) {
        return abort_typed_data(SW_WRONG_P1P2);
    }
    if (p1 == DATA_LAST && p2 != 0) {
        if (G_context.req_type != CONFIRM_TYPED_DATA || G_context.state != STATE_APPROVED ||
            !N_storage.is_sending_signature)
            return io_send_sw(SW_BAD_STATE);
        if (data->size != data->offset) return abort_typed_data(SW_WRONG_DATA_LENGTH);
        return helper_send_response_sig(p2);
    }
    if (p1 == DATA_FIRST) {
        reset_request_context();
        if (!buffer_read_u8(data, &G_context.bip32_path_len) ||
            !buffer_read_bip32_path(data, G_context.bip32_path, G_context.bip32_path_len) ||
            !is_valid_zond_bip32_path(G_context.bip32_path, G_context.bip32_path_len) ||
            data->size - data->offset != 4)
            return abort_typed_data(SW_WRONG_DATA_LENGTH);
        const uint8_t *length = data->ptr + data->offset;
        uint32_t expected = ((uint32_t) length[0] << 24) | ((uint32_t) length[1] << 16) |
                            ((uint32_t) length[2] << 8) | length[3];
        if (!typed_data_session_init(&G_context.typed_data, expected))
            return abort_typed_data(SW_WRONG_DATA_LENGTH);
        G_context.req_type = CONFIRM_TYPED_DATA;
        G_context.state = STATE_RECEIVING;
        return io_send_sw(SW_OK);
    }
    if (G_context.req_type != CONFIRM_TYPED_DATA || G_context.state != STATE_RECEIVING) {
        return abort_typed_data(SW_BAD_STATE);
    }
    typed_data_session_t *message = &G_context.typed_data;
    size_t length = data->size - data->offset;
    if (length == 0 || !typed_data_session_feed(message, data->ptr + data->offset, length)) {
        return abort_typed_data(SW_WRONG_DATA_LENGTH);
    }
    if (p1 == DATA_MORE) {
        if (message->received_len == message->expected_len)
            return abort_typed_data(SW_WRONG_DATA_LENGTH);
        return io_send_sw(SW_OK);
    }
    if (message->received_len != message->expected_len)
        return abort_typed_data(SW_WRONG_DATA_LENGTH);
#ifdef SCREEN_SIZE_WALLET
    typed_data_page_length_t page_length = ui_typed_data_page_length;
#else
    typed_data_page_length_t page_length = NULL;
#endif
    if (!typed_data_session_finish(message, page_length))
        return abort_typed_data(SW_TYPED_DATA_INVALID);
    G_context.state = STATE_PARSED;
    return ui_display_typed_data();
}
