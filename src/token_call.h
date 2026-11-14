#pragma once

#include "tx_types.h"

#define TOKEN_CALL_CALLDATA_LEN (4 + 2 * ADDRESS_LENGTH)

#define TOKEN_SYMBOL_MAX         12
#define TOKEN_NATIVE_TICKER      "QRL" /* reserved: a token may never display as QRL */
#define TOKEN_DECIMALS_MAX       77
#define TOKEN_METADATA_DOMAIN    "QRL-TOKEN-METADATA-V1"
#define TOKEN_METADATA_FIXED_LEN (1 + MAX_FIELD_SIZE + ADDRESS_LENGTH + 1 + 1)

typedef struct {
    uint8_t chain_id[MAX_FIELD_SIZE];
    uint8_t contract[ADDRESS_LENGTH];
    uint8_t decimals;
    char symbol[TOKEN_SYMBOL_MAX + 1];
    bool verified;
} token_metadata_t;

typedef struct {
    uint8_t target[ADDRESS_LENGTH];  // token recipient
    uint8_t amount[MAX_FIELD_SIZE];
    bool enabled;
} token_call_t;

/* Parse the versioned payload, returning the signed body length. The remaining
 * bytes are a DER ECDSA signature. Parsing alone never authenticates metadata. */
bool token_metadata_parse(const uint8_t *data, size_t len, token_metadata_t *out, size_t *body_len);

/* Match the complete transaction against verified, session-local metadata.
 * Unsupported calls remain eligible only for the ordinary blind-signing flow. */
bool token_call_prepare(const zond_tx_t *tx, const token_metadata_t *metadata, token_call_t *out);
