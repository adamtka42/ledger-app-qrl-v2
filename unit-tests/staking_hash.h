#pragma once
#include <openssl/sha.h>
#include "staking_deposit.h"
static bool test_staking_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    return SHA256(data, len, out) != NULL;
}
