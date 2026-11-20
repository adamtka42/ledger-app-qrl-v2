#pragma once

#include <stddef.h>
#include <stdint.h>

/** Longest network display name, excluding the terminating NUL. */
#define NETWORK_NAME_MAX_LEN 16

/**
 * Look up the display name of a network from the transaction's chain ID.
 *
 * @param[in] chain_id      Big-endian chain ID as carried by the transaction.
 * @param[in] chain_id_len  Length of chain_id in bytes.
 *
 * @return the name from networks.def, or NULL when the chain ID is not listed.
 */
const char *network_name(const uint8_t *chain_id, size_t chain_id_len);
