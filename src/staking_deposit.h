#pragma once
#include "tx_types.h"

#define STAKING_CALLDATA_LEN  8004u
#define STAKING_PUBKEY_LEN    2592u
#define STAKING_SIGNATURE_LEN 4627u
#define STAKING_MIN_SHOR      UINT64_C(2000000000000)

typedef bool (*staking_hash_fn)(const uint8_t *data, size_t len, uint8_t out[32]);

/* One reusable Merkle frontier; neither the key nor signature is retained. */
typedef struct {
    uint8_t frontier[8][32];
    uint8_t leaf[32];
    uint8_t pubkey_root[32];
    uint8_t withdrawal[ADDRESS_LENGTH];
    uint8_t randao[32];
    uint8_t expected_root[32];
    uint8_t signature_root[32];
    staking_hash_fn hash;
    uint32_t position;
    uint16_t leaves;
    uint8_t leaf_len;
    bool selected;
    bool ignored;
    bool failed;
} staking_deposit_t;

void staking_deposit_init(staking_deposit_t *s, staking_hash_fn hash);
/* Feed complete calldata in order. Failures are sticky; selected remains true
 * after recognizing deposit(), even if the remaining data is malformed. */
void staking_deposit_feed(staking_deposit_t *s,
                          uint32_t offset,
                          uint32_t total,
                          const uint8_t *data,
                          size_t len);
bool staking_deposit_validate(const staking_deposit_t *s, const zond_tx_t *tx);
bool staking_deposit_amount(const zond_tx_t *tx, uint64_t *shor);
/* Only explicitly configured chain/contract pairs can obtain staking review. */
bool staking_deposit_is_target(const zond_tx_t *tx);
