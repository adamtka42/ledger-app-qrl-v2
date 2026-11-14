#pragma once

/*
 * Checks shared by the clear-signing profiles that bind a transaction to a
 * contract on a chain.
 */

#include <string.h>

#include "tx_types.h"

static inline bool all_zero(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0) return false;
    }
    return true;
}

/* A call to tx->to that carries no native value and no access list. */
static inline bool tx_is_plain_call(const zond_tx_t *tx) {
    if (tx->to_len != ADDRESS_LENGTH || tx->has_access_list) return false;
    return tx->value_len <= MAX_FIELD_SIZE && all_zero(tx->value, tx->value_len);
}

/* Signed payloads store the chain ID left-padded to MAX_FIELD_SIZE bytes. */
static inline bool chain_id_matches(const zond_tx_t *tx, const uint8_t padded[MAX_FIELD_SIZE]) {
    if (tx->chain_id_len == 0 || tx->chain_id_len > MAX_FIELD_SIZE) return false;
    const size_t pad = MAX_FIELD_SIZE - tx->chain_id_len;
    return all_zero(padded, pad) && memcmp(padded + pad, tx->chain_id, tx->chain_id_len) == 0;
}
