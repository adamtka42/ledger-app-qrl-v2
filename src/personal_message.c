#include "personal_message.h"

#include <string.h>

bool personal_message_init(personal_message_t *message, uint32_t length) {
    if (message == NULL) return false;
    memset(message, 0, sizeof(*message));
    if (length > PERSONAL_MESSAGE_MAX_LEN) return false;
    message->expected_len = length;
    static const uint8_t prefix[] =
        "\x19"
        "QRL Signed Message:\n";
    char decimal[10];
    size_t pos = sizeof(decimal);
    uint32_t remaining = length;
    do {
        decimal[--pos] = (char) ('0' + remaining % 10);
        remaining /= 10;
    } while (remaining != 0);
    keccak256_init(&message->hash_ctx);
    keccak256_absorb(&message->hash_ctx, prefix, sizeof(prefix) - 1);
    keccak256_absorb(&message->hash_ctx, (const uint8_t *) decimal + pos, sizeof(decimal) - pos);
    return true;
}

bool personal_message_feed(personal_message_t *message, const uint8_t *data, size_t length) {
    if (message == NULL || message->finished || (data == NULL && length != 0) ||
        message->expected_len > PERSONAL_MESSAGE_MAX_LEN ||
        message->received_len > message->expected_len ||
        length > message->expected_len - message->received_len)
        return false;
    size_t newlines = message->newlines;
    for (size_t i = 0; i < length; i++) {
        if (data[i] == '\n')
            newlines++;
        else if (data[i] < 0x20 || data[i] > 0x7e)
            return false;
    }
    if (newlines > PERSONAL_MESSAGE_MAX_NEWLINES) return false;
    if (length != 0) {
        memcpy(message->text + message->received_len, data, length);
        keccak256_absorb(&message->hash_ctx, data, length);
    }
    message->received_len += length;
    message->newlines = newlines;
    return true;
}

bool personal_message_finish(personal_message_t *message) {
    if (message == NULL || message->finished || message->expected_len > PERSONAL_MESSAGE_MAX_LEN ||
        message->received_len != message->expected_len)
        return false;
    keccak256_finalize(&message->hash_ctx);
    keccak256_squeeze(&message->hash_ctx, message->digest);
    keccak256_clear(&message->hash_ctx);
    message->finished = true;
    return true;
}

bool personal_message_prepare_review(personal_message_t *message,
                                     uint16_t offsets[PERSONAL_MESSAGE_MAX_PARTS],
                                     size_t *count,
                                     personal_message_page_length_t page_length) {
    if (count == NULL) return false;
    *count = 0;
    if (message == NULL || offsets == NULL || !message->finished || message->review_prepared ||
        message->expected_len > PERSONAL_MESSAGE_MAX_LEN ||
        message->received_len != message->expected_len)
        return false;
    uint16_t lengths[PERSONAL_MESSAGE_MAX_PARTS];
    size_t pos = 0, parts = 0;
    do {
        if (parts >= PERSONAL_MESSAGE_MAX_PARTS) return false;
        offsets[parts] = (uint16_t) pos;
        size_t length = message->expected_len - pos;
        if (length > 0 && page_length != NULL) {
            length = page_length(message->text + pos);
            if (length == 0 || length > message->expected_len - pos) return false;
        }
        lengths[parts++] = (uint16_t) length;
        pos += length;
    } while (pos < message->expected_len);
    // Move from the end so inserting terminators never overwrites unread text.
    for (size_t i = parts; i-- > 0;) {
        size_t destination = offsets[i] + i;
        memmove(message->text + destination, message->text + offsets[i], lengths[i]);
        message->text[destination + lengths[i]] = '\0';
        offsets[i] = (uint16_t) destination;
    }
    message->review_prepared = true;
    *count = parts;
    return true;
}
