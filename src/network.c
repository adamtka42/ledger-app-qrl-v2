#include "network.h"

typedef struct {
    uint64_t chain_id;
    char name[NETWORK_NAME_MAX_LEN + 1];
} network_t;

#define NETWORK(id, text) \
    _Static_assert(sizeof(text) > 1 && sizeof(text) <= NETWORK_NAME_MAX_LEN + 1, "bad name: " text);
#include "networks.def"
#undef NETWORK

static const network_t NETWORKS[] = {
#define NETWORK(id, text) {UINT64_C(id), text},
#include "networks.def"
#undef NETWORK
};

const char *network_name(const uint8_t *chain_id, size_t chain_id_len) {
    if (chain_id == NULL) return NULL;
    while (chain_id_len > 0 && *chain_id == 0) {
        chain_id++;
        chain_id_len--;
    }
    if (chain_id_len > sizeof(uint64_t)) return NULL;
    uint64_t value = 0;
    for (size_t i = 0; i < chain_id_len; i++) value = (value << 8) | chain_id[i];
    for (size_t i = 0; i < sizeof(NETWORKS) / sizeof(NETWORKS[0]); i++) {
        if (NETWORKS[i].chain_id == value) return NETWORKS[i].name;
    }
    return NULL;
}
