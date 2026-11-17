#include "staking_deposit.h"
#include <string.h>

#ifdef STAKING_DEPOSIT_TEST_PROFILE
static const uint8_t CHAIN[32] = {[31] = 1};
static const uint8_t CONTRACT[64] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
#elif defined(STAKING_DEPOSIT_PROFILE_BYTES)
static const uint8_t PROFILE[] = {STAKING_DEPOSIT_PROFILE_BYTES};
_Static_assert(sizeof(PROFILE) == 96, "staking profile must bind full chain and address");
#define CHAIN    PROFILE
#define CONTRACT (PROFILE + 32)
#endif

bool staking_deposit_is_target(const zond_tx_t *tx) {
#if defined(STAKING_DEPOSIT_TEST_PROFILE) || defined(STAKING_DEPOSIT_PROFILE_BYTES)
    if (tx == NULL || tx->chain_id_len == 0 || tx->chain_id_len > 32 || tx->to_len != 64)
        return false;
    for (size_t i = 0; i < 32u - tx->chain_id_len; i++)
        if (CHAIN[i] != 0) return false;
    return memcmp(tx->chain_id, CHAIN + 32 - tx->chain_id_len, tx->chain_id_len) == 0 &&
           memcmp(tx->to, CONTRACT, 64) == 0;
#else
    (void) tx;
    return false;
#endif
}
