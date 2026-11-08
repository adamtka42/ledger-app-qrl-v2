#include "message_session.h"

#include "address_format.h"
#include "globals.h"
#include "send_response.h"
#include "sw.h"

int message_send_signature_chunk(const buffer_t *data,
                                 request_type_e type,
                                 uint8_t p2,
                                 message_abort_fn abort_request) {
    if (G_context.req_type != type || G_context.state != STATE_APPROVED ||
        !N_storage.is_sending_signature)
        return io_send_sw(SW_BAD_STATE);
    if (data->size != data->offset) return abort_request(SW_WRONG_DATA_LENGTH);
    return helper_send_response_sig(p2);
}

bool message_read_header(buffer_t *data, uint32_t *expected_len) {
    return buffer_read_u8(data, &G_context.bip32_path_len) &&
           buffer_read_bip32_path(data, G_context.bip32_path, G_context.bip32_path_len) &&
           is_valid_zond_bip32_path(G_context.bip32_path, G_context.bip32_path_len) &&
           buffer_read_u32(data, expected_len, BE) && data->offset == data->size;
}
