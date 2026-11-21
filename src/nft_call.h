#pragma once

#include "tx_types.h"

/* Collection names are attested by the metadata issuer, never read from the
 * contract or supplied unsigned by the host. */
#define NFT_NAME_MAX           32
#define NFT_METADATA_DOMAIN    "QRL-NFT-METADATA-V1"
#define NFT_METADATA_FIXED_LEN (1 + MAX_FIELD_SIZE + ADDRESS_LENGTH + 1)
#define NFT_METADATA_BODY_MAX  (NFT_METADATA_FIXED_LEN + NFT_NAME_MAX)

/* Longest supported call: single-token transfer of a multi-token collection,
 * i.e. the selector, five head words and the length word of an empty `bytes`. */
#define NFT_CALL_CALLDATA_MAX (4 + 6 * ADDRESS_LENGTH)

typedef struct {
    uint8_t chain_id[MAX_FIELD_SIZE];
    uint8_t contract[ADDRESS_LENGTH];
    char name[NFT_NAME_MAX + 1];
    bool verified;
} nft_metadata_t;

typedef enum {
    NFT_CALL_NONE = 0,
    NFT_CALL_TRANSFER,     // one token ID, optionally with a quantity
    NFT_CALL_APPROVE,      // one token ID; a zero spender clears the approval
    NFT_CALL_APPROVE_ALL,  // operator for the whole collection, granted or revoked
} nft_call_kind_e;

typedef struct {
    uint8_t owner[ADDRESS_LENGTH];     // transfer only: the `from` argument
    uint8_t target[ADDRESS_LENGTH];    // recipient, spender or operator
    uint8_t token_id[MAX_FIELD_SIZE];  // unused for NFT_CALL_APPROVE_ALL
    uint8_t quantity[MAX_FIELD_SIZE];  // valid only when has_quantity
    nft_call_kind_e kind;
    bool has_quantity;  // multi-token transfer
    bool approved;      // NFT_CALL_APPROVE_ALL: grant (true) or revoke (false)
} nft_call_t;

/* Parse the versioned payload, returning the signed body length. The remaining
 * bytes are a DER ECDSA signature. Parsing alone never authenticates metadata. */
bool nft_metadata_parse(const uint8_t *data, size_t len, nft_metadata_t *out, size_t *body_len);

/* Match the complete transaction against verified, session-local metadata.
 * Unsupported calls remain eligible only for the ordinary blind-signing flow. */
bool nft_call_prepare(const zond_tx_t *tx, const nft_metadata_t *metadata, nft_call_t *out);

/* Return true only for a single-token approval of the zero address. */
bool nft_call_is_approval_revocation(const nft_call_t *call);
