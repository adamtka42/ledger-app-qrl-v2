#include "staking_deposit.h"
#include <string.h>

_Static_assert(sizeof(staking_deposit_t) <= 512, "staking workspace exceeds RAM budget");

static bool pair(staking_hash_fn hash,
                 const uint8_t left[32],
                 const uint8_t right[32],
                 uint8_t out[32]) {
    uint8_t message[64];
    memcpy(message, left, 32);
    memcpy(message + 32, right, 32);
    return hash != NULL && hash(message, sizeof(message), out);
}

void staking_deposit_init(staking_deposit_t *s, staking_hash_fn hash) {
    memset(s, 0, sizeof(*s));
    s->hash = hash;
}

static bool push(staking_deposit_t *s, const uint8_t leaf[32], unsigned depth, uint8_t root[32]) {
    uint8_t node[32];
    memcpy(node, leaf, 32);
    unsigned count = s->leaves, level = 0;
    if (depth > 8 || count >= (1u << depth)) return false;
    while (count & 1) {
        if (level >= 8 || !pair(s->hash, s->frontier[level], node, node)) return false;
        level++;
        count >>= 1;
    }
    if (level == depth)
        memcpy(root, node, 32);
    else if (level < 8)
        memcpy(s->frontier[level], node, 32);
    else
        return false;
    s->leaves++;
    return true;
}

static bool byte(staking_deposit_t *s, uint8_t b, unsigned depth, uint8_t root[32]) {
    s->leaf[s->leaf_len++] = b;
    if (s->leaf_len != 32) return true;
    s->leaf_len = 0;
    return push(s, s->leaf, depth, root);
}

static bool finish_vector(staking_deposit_t *s, unsigned depth, uint8_t root[32]) {
    const uint8_t zero[32] = {0};
    if (s->leaf_len != 0) {
        memset(s->leaf + s->leaf_len, 0, 32 - s->leaf_len);
        if (!push(s, s->leaf, depth, root)) return false;
    }
    while (s->leaves < (1u << depth)) {
        if (!push(s, zero, depth, root)) return false;
    }
    s->leaves = 0;
    s->leaf_len = 0;
    return true;
}

static uint8_t word_byte(uint32_t value, uint32_t index) {
    return index < 60 ? 0 : (uint8_t) (value >> ((63 - index) * 8));
}

static bool consume(staking_deposit_t *s, uint32_t p, uint8_t b) {
    if (p < 260) {
        static const uint32_t offsets[] = {320, 3008, 3136, 3264};
        return b == word_byte(offsets[(p - 4) / 64], (p - 4) % 64);
    }
    if (p < 292) {
        s->expected_root[p - 260] = b;
        return true;
    }
    if (p < 324) return b == 0;
    if (p < 388) return b == word_byte(STAKING_PUBKEY_LEN, p - 324);
    if (p < 2980) {
        if (!byte(s, b, 7, s->pubkey_root)) return false;
        return p != 2979 || finish_vector(s, 7, s->pubkey_root);
    }
    if (p < 3012) return b == 0;
    if (p < 3076) return b == word_byte(64, p - 3012);
    if (p < 3140) {
        s->withdrawal[p - 3076] = b;
        return true;
    }
    if (p < 3204) return b == word_byte(32, p - 3140);
    if (p < 3236) {
        s->randao[p - 3204] = b;
        return true;
    }
    if (p < 3268) return b == 0;
    if (p < 3332) return b == word_byte(STAKING_SIGNATURE_LEN, p - 3268);
    if (p < 7959) {
        if (!byte(s, b, 8, s->signature_root)) return false;
        return p != 7958 || finish_vector(s, 8, s->signature_root);
    }
    return b == 0;
}

void staking_deposit_feed(staking_deposit_t *s,
                          uint32_t offset,
                          uint32_t total,
                          const uint8_t *data,
                          size_t len) {
    static const uint8_t selector[4] = {0xc1, 0xda, 0x06, 0xe2};
    if (s == NULL || s->failed || s->ignored) return;
    if (data == NULL || offset != s->position || offset > STAKING_CALLDATA_LEN) {
        s->failed = true;
        return;
    }
    for (size_t i = 0; i < len; i++) {
        if (s->position >= STAKING_CALLDATA_LEN) {
            s->failed = true;
            return;
        }
        const uint32_t p = s->position++;
        if (p < 4) {
            if (data[i] != selector[p]) {
                s->ignored = true;
                return;
            }
            if (p == 3) {
                s->selected = true;
                if (total != STAKING_CALLDATA_LEN || s->hash == NULL) {
                    s->failed = true;
                    return;
                }
            }
        } else if (!consume(s, p, data[i])) {
            s->failed = true;
            return;
        }
    }
}

bool staking_deposit_amount(const zond_tx_t *tx, uint64_t *shor) {
    if (tx == NULL || shor == NULL || tx->value_len > MAX_FIELD_SIZE) return false;
    uint64_t result = 0, remainder = 0;
    for (size_t i = 0; i < tx->value_len; i++) {
        remainder = remainder * 256 + tx->value[i];
        const uint64_t digit = remainder / UINT64_C(1000000000);
        remainder %= UINT64_C(1000000000);
        if (result > (UINT64_MAX - digit) / 256) return false;
        result = result * 256 + digit;
    }
    if (remainder != 0 || result < STAKING_MIN_SHOR) return false;
    *shor = result;
    return true;
}

bool staking_deposit_validate(const staking_deposit_t *s, const zond_tx_t *tx) {
    uint64_t shor;
    if (s == NULL || tx == NULL || !s->selected || s->ignored || s->failed ||
        s->position != STAKING_CALLDATA_LEN || tx->data_len != STAKING_CALLDATA_LEN ||
        !tx->has_data || tx->has_access_list || !staking_deposit_amount(tx, &shor))
        return false;
    uint8_t nodes[8][32] = {0};
    memcpy(nodes[0], s->pubkey_root, 32);
    if (s->hash == NULL || !s->hash(s->withdrawal, ADDRESS_LENGTH, nodes[1])) return false;
    for (size_t i = 0; i < 8; i++) nodes[2][i] = (uint8_t) (shor >> (i * 8));
    memcpy(nodes[3], s->randao, 32);
    memcpy(nodes[4], s->signature_root, 32);
    for (size_t width = 8; width > 1; width /= 2) {
        for (size_t i = 0; i < width / 2; i++) {
            if (!pair(s->hash, nodes[2 * i], nodes[2 * i + 1], nodes[i])) return false;
        }
    }
    return memcmp(nodes[0], s->expected_root, 32) == 0;
}
