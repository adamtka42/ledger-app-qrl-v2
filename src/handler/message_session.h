#pragma once

/*
 * APDU steps shared by the message signing commands. P1 and P2 follow
 * sign_command_p1p2_valid() in dispatcher.h.
 */

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"
#include "types.h"

typedef int (*message_abort_fn)(uint16_t status);

/* Send signature chunk p2 of the approved session of this type. A request that
 * finds no such session is refused without ending the one in progress. */
int message_send_signature_chunk(const buffer_t *data,
                                 request_type_e type,
                                 uint8_t p2,
                                 message_abort_fn abort_request);

/* Read the first APDU: the BIP32 path into G_context and the 4-byte big-endian
 * message length, which must end the data. */
bool message_read_header(buffer_t *data, uint32_t *expected_len);
