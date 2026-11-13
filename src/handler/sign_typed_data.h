#pragma once

#include "buffer.h"

/** Receive QRL typed data, or export a signature from its approved session. */
int handler_sign_typed_data(buffer_t *data, uint8_t p1, uint8_t p2);
