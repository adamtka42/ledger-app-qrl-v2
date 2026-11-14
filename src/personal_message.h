#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keccak256.h"

#define PERSONAL_MESSAGE_MAX_LEN      1024
#define PERSONAL_MESSAGE_MAX_NEWLINES 32
/* Bounded UI cache; actual page lengths are selected by the device UI. */
#define PERSONAL_MESSAGE_MAX_PARTS 33

typedef size_t (*personal_message_page_length_t)(char *text);

typedef struct {
    // Extra bytes allow in-place NUL separation for review, after hashing completes.
    char text[PERSONAL_MESSAGE_MAX_LEN + PERSONAL_MESSAGE_MAX_PARTS + 1];
    uint32_t expected_len;
    size_t received_len;
    size_t newlines;
    bool finished;
    bool review_prepared;
    keccak256_ctx hash_ctx;
    uint8_t digest[32];
} personal_message_t;

/* Hash the QRL personal-sign prefix and decimal byte length, then receive text. */
bool personal_message_init(personal_message_t *message, uint32_t length);
/* Accept printable ASCII and LF only, without normalization or truncation. */
bool personal_message_feed(personal_message_t *message, const uint8_t *data, size_t length);
/* Finalize only when exactly the declared number of bytes has arrived. */
bool personal_message_finish(personal_message_t *message);
/* Prepare lossless NUL-terminated review fragments after hashing. page_length
 * selects each fragment length; NULL keeps the whole message for NBGL paging.
 * A selector must return a positive length no larger than the remaining text. */
bool personal_message_prepare_review(personal_message_t *message,
                                     uint16_t offsets[PERSONAL_MESSAGE_MAX_PARTS],
                                     size_t *count,
                                     personal_message_page_length_t page_length);
