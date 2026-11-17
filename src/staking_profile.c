#include "staking_deposit.h"
#include <string.h>

#include "call_checks.h"

#ifdef STAKING_DEPOSIT_TEST_PROFILE
static const uint8_t CHAIN[MAX_FIELD_SIZE] = {[MAX_FIELD_SIZE - 1] = 1};
static const uint8_t CONTRACT[ADDRESS_LENGTH] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
#elif defined(STAKING_DEPOSIT_PROFILE_BYTES)
static const uint8_t PROFILE[] = {STAKING_DEPOSIT_PROFILE_BYTES};
_Static_assert(sizeof(PROFILE) == MAX_FIELD_SIZE + ADDRESS_LENGTH,
               "staking profile must bind full chain and address");
#define CHAIN    PROFILE
#define CONTRACT (PROFILE + MAX_FIELD_SIZE)
#endif

bool staking_deposit_is_target(const zond_tx_t *tx) {
#if defined(STAKING_DEPOSIT_TEST_PROFILE) || defined(STAKING_DEPOSIT_PROFILE_BYTES)
    return tx != NULL && tx->to_len == ADDRESS_LENGTH && chain_id_matches(tx, CHAIN) &&
           memcmp(tx->to, CONTRACT, ADDRESS_LENGTH) == 0;
#else
    (void) tx;
    return false;
#endif
}
