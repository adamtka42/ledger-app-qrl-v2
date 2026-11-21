#include "network.h"

#include <stdbool.h>

typedef struct {
    uint64_t chain_id;
    char name[NETWORK_NAME_MAX_LEN + 1];
} network_t;

/* Known QRL v2.0 networks, by chain ID.
 *
 * The review screen shows "Network: <name> (<chain ID>)" for a chain ID listed
 * here and the bare "Chain ID" for any other. Names are compiled into the app:
 * the host can never supply or override them. To add or rename a network, edit
 * this table and rebuild. Chain IDs must be unique, and a name is 1 to
 * NETWORK_NAME_MAX_LEN characters; unit-tests/test_network.c checks both.
 *
 * Values follow go-qrl params/config.go (MainnetChainConfig, TestnetChainConfig,
 * BetaNetChainConfig). */
static const network_t NETWORKS[] = {
    {.chain_id = 1, .name = "Mainnet"},
    {.chain_id = 1337, .name = "Testnet"},
    {.chain_id = 32382, .name = "BetaNet"},
};

#define NETWORK_COUNT (sizeof(NETWORKS) / sizeof(NETWORKS[0]))

/* A big-endian chain ID with any number of leading zero bytes, if it fits 64 bits. */
static bool chain_id_to_u64(const uint8_t *chain_id, size_t chain_id_len, uint64_t *value) {
    while (chain_id_len > 0 && *chain_id == 0) {
        chain_id++;
        chain_id_len--;
    }
    if (chain_id_len > sizeof(*value)) return false;
    *value = 0;
    for (size_t i = 0; i < chain_id_len; i++) *value = (*value << 8) | chain_id[i];
    return true;
}

const char *network_name(const uint8_t *chain_id, size_t chain_id_len) {
    uint64_t value;
    if (chain_id == NULL || !chain_id_to_u64(chain_id, chain_id_len, &value)) return NULL;
    for (size_t i = 0; i < NETWORK_COUNT; i++) {
        if (NETWORKS[i].chain_id == value) return NETWORKS[i].name;
    }
    return NULL;
}
