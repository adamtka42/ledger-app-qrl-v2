#include "staking_deposit.h"
#include <string.h>

#include "qrvm_abi.h"

_Static_assert(sizeof(staking_deposit_t) <= 512, "staking workspace exceeds RAM budget");

/* SSZ roots of the key and the signature: 2^7 and 2^8 chunks of STAKING_HASH_LEN
 * bytes, the smallest trees that hold them. */
#define PUBKEY_TREE_DEPTH    7u
#define SIGNATURE_TREE_DEPTH 8u
_Static_assert((1u << PUBKEY_TREE_DEPTH) * STAKING_HASH_LEN >= STAKING_PUBKEY_LEN &&
                   (1u << (PUBKEY_TREE_DEPTH - 1)) * STAKING_HASH_LEN < STAKING_PUBKEY_LEN,
               "public key tree depth");
_Static_assert((1u << SIGNATURE_TREE_DEPTH) * STAKING_HASH_LEN >= STAKING_SIGNATURE_LEN &&
                   (1u << (SIGNATURE_TREE_DEPTH - 1)) * STAKING_HASH_LEN < STAKING_SIGNATURE_LEN,
               "signature tree depth");
_Static_assert(PUBKEY_TREE_DEPTH <= STAKING_TREE_MAX_DEPTH &&
                   SIGNATURE_TREE_DEPTH <= STAKING_TREE_MAX_DEPTH,
               "frontier too small");

/* QRVM ABI layout of deposit(bytes pubkey, bytes withdrawal_credentials, bytes randao,
 * bytes signature, bytes32 deposit_data_root): the selector, a head of four offsets
 * and the root, then each byte string as a length word and its data, zero-padded to
 * whole words. */
#define ABI_PADDED(n) (((n) + ABI_WORD_LEN - 1) / ABI_WORD_LEN * ABI_WORD_LEN)
enum {
    OFF_HEAD = ABI_SELECTOR_LEN,
    OFF_ROOT = OFF_HEAD + 4 * ABI_WORD_LEN,
    OFF_PUBKEY_LEN = OFF_ROOT + ABI_WORD_LEN,
    OFF_PUBKEY = OFF_PUBKEY_LEN + ABI_WORD_LEN,
    OFF_WITHDRAWAL_LEN = OFF_PUBKEY + ABI_PADDED(STAKING_PUBKEY_LEN),
    OFF_WITHDRAWAL = OFF_WITHDRAWAL_LEN + ABI_WORD_LEN,
    OFF_RANDAO_LEN = OFF_WITHDRAWAL + ABI_PADDED(ADDRESS_LENGTH),
    OFF_RANDAO = OFF_RANDAO_LEN + ABI_WORD_LEN,
    OFF_SIGNATURE_LEN = OFF_RANDAO + ABI_PADDED(STAKING_RANDAO_LEN),
    OFF_SIGNATURE = OFF_SIGNATURE_LEN + ABI_WORD_LEN,
    OFF_END = OFF_SIGNATURE + ABI_PADDED(STAKING_SIGNATURE_LEN),
};
_Static_assert(OFF_END == STAKING_CALLDATA_LEN, "deposit calldata layout");

static bool pair(staking_hash_fn hash,
                 const uint8_t left[STAKING_HASH_LEN],
                 const uint8_t right[STAKING_HASH_LEN],
                 uint8_t out[STAKING_HASH_LEN]) {
    uint8_t message[2 * STAKING_HASH_LEN];
    memcpy(message, left, STAKING_HASH_LEN);
    memcpy(message + STAKING_HASH_LEN, right, STAKING_HASH_LEN);
    return hash != NULL && hash(message, sizeof(message), out);
}

void staking_deposit_init(staking_deposit_t *s, staking_hash_fn hash) {
    memset(s, 0, sizeof(*s));
    s->hash = hash;
}

static bool push(staking_deposit_t *s,
                 const uint8_t leaf[STAKING_HASH_LEN],
                 unsigned depth,
                 uint8_t root[STAKING_HASH_LEN]) {
    uint8_t node[STAKING_HASH_LEN];
    memcpy(node, leaf, STAKING_HASH_LEN);
    unsigned count = s->leaves, level = 0;
    if (depth > STAKING_TREE_MAX_DEPTH || count >= (1u << depth)) return false;
    while (count & 1) {
        if (level >= STAKING_TREE_MAX_DEPTH || !pair(s->hash, s->frontier[level], node, node))
            return false;
        level++;
        count >>= 1;
    }
    if (level == depth)
        memcpy(root, node, STAKING_HASH_LEN);
    else if (level < STAKING_TREE_MAX_DEPTH)
        memcpy(s->frontier[level], node, STAKING_HASH_LEN);
    else
        return false;
    s->leaves++;
    return true;
}

static bool byte(staking_deposit_t *s, uint8_t b, unsigned depth, uint8_t root[STAKING_HASH_LEN]) {
    s->leaf[s->leaf_len++] = b;
    if (s->leaf_len != STAKING_HASH_LEN) return true;
    s->leaf_len = 0;
    return push(s, s->leaf, depth, root);
}

static bool finish_vector(staking_deposit_t *s, unsigned depth, uint8_t root[STAKING_HASH_LEN]) {
    const uint8_t zero[STAKING_HASH_LEN] = {0};
    if (s->leaf_len != 0) {
        memset(s->leaf + s->leaf_len, 0, STAKING_HASH_LEN - s->leaf_len);
        if (!push(s, s->leaf, depth, root)) return false;
    }
    while (s->leaves < (1u << depth)) {
        if (!push(s, zero, depth, root)) return false;
    }
    s->leaves = 0;
    s->leaf_len = 0;
    return true;
}

/* Byte index of an ABI word that holds value as a big-endian integer. */
static uint8_t word_byte(uint32_t value, uint32_t index) {
    const uint32_t first = ABI_WORD_LEN - sizeof(value);
    return index < first ? 0 : (uint8_t) (value >> ((ABI_WORD_LEN - 1 - index) * 8));
}

/* Check or record the calldata byte at offset p, past the selector. */
static bool consume(staking_deposit_t *s, uint32_t p, uint8_t b) {
    if (p < OFF_ROOT) {
        /* Head offsets point at each length word and count from the head. */
        static const uint32_t offsets[] = {
            OFF_PUBKEY_LEN - OFF_HEAD,
            OFF_WITHDRAWAL_LEN - OFF_HEAD,
            OFF_RANDAO_LEN - OFF_HEAD,
            OFF_SIGNATURE_LEN - OFF_HEAD,
        };
        return b ==
               word_byte(offsets[(p - OFF_HEAD) / ABI_WORD_LEN], (p - OFF_HEAD) % ABI_WORD_LEN);
    }
    if (p < OFF_ROOT + STAKING_HASH_LEN) {
        s->expected_root[p - OFF_ROOT] = b;
        return true;
    }
    if (p < OFF_PUBKEY_LEN) return b == 0;
    if (p < OFF_PUBKEY) return b == word_byte(STAKING_PUBKEY_LEN, p - OFF_PUBKEY_LEN);
    if (p < OFF_PUBKEY + STAKING_PUBKEY_LEN) {
        if (!byte(s, b, PUBKEY_TREE_DEPTH, s->pubkey_root)) return false;
        return p != OFF_PUBKEY + STAKING_PUBKEY_LEN - 1 ||
               finish_vector(s, PUBKEY_TREE_DEPTH, s->pubkey_root);
    }
    if (p < OFF_WITHDRAWAL_LEN) return b == 0;
    if (p < OFF_WITHDRAWAL) return b == word_byte(ADDRESS_LENGTH, p - OFF_WITHDRAWAL_LEN);
    if (p < OFF_WITHDRAWAL + ADDRESS_LENGTH) {
        s->withdrawal[p - OFF_WITHDRAWAL] = b;
        return true;
    }
    if (p < OFF_RANDAO_LEN) return b == 0;
    if (p < OFF_RANDAO) return b == word_byte(STAKING_RANDAO_LEN, p - OFF_RANDAO_LEN);
    if (p < OFF_RANDAO + STAKING_RANDAO_LEN) {
        s->randao[p - OFF_RANDAO] = b;
        return true;
    }
    if (p < OFF_SIGNATURE_LEN) return b == 0;
    if (p < OFF_SIGNATURE) return b == word_byte(STAKING_SIGNATURE_LEN, p - OFF_SIGNATURE_LEN);
    if (p < OFF_SIGNATURE + STAKING_SIGNATURE_LEN) {
        if (!byte(s, b, SIGNATURE_TREE_DEPTH, s->signature_root)) return false;
        return p != OFF_SIGNATURE + STAKING_SIGNATURE_LEN - 1 ||
               finish_vector(s, SIGNATURE_TREE_DEPTH, s->signature_root);
    }
    return b == 0;
}

void staking_deposit_feed(staking_deposit_t *s,
                          uint32_t offset,
                          uint32_t total,
                          const uint8_t *data,
                          size_t len) {
    static const uint8_t selector[ABI_SELECTOR_LEN] = {0xc1, 0xda, 0x06, 0xe2};
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
        if (p < ABI_SELECTOR_LEN) {
            if (data[i] != selector[p]) {
                s->ignored = true;
                return;
            }
            if (p == ABI_SELECTOR_LEN - 1) {
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

/* Every calldata byte of a deposit() call passed consume(). */
static bool feed_complete(const staking_deposit_t *s) {
    return s->selected && !s->ignored && !s->failed && s->position == STAKING_CALLDATA_LEN;
}

static bool tx_has_deposit_shape(const zond_tx_t *tx) {
    return tx->has_data && tx->data_len == STAKING_CALLDATA_LEN && !tx->has_access_list;
}

bool staking_deposit_validate(const staking_deposit_t *s, const zond_tx_t *tx) {
    uint64_t shor;
    if (s == NULL || tx == NULL || !feed_complete(s) || !tx_has_deposit_shape(tx) ||
        !staking_deposit_amount(tx, &shor))
        return false;
    /* DepositData fields in SSZ order, as leaves of a tree padded to eight. */
    enum { NODE_PUBKEY, NODE_WITHDRAWAL, NODE_AMOUNT, NODE_RANDAO, NODE_SIGNATURE, NODE_COUNT = 8 };
    uint8_t nodes[NODE_COUNT][STAKING_HASH_LEN] = {0};
    memcpy(nodes[NODE_PUBKEY], s->pubkey_root, STAKING_HASH_LEN);
    if (s->hash == NULL || !s->hash(s->withdrawal, ADDRESS_LENGTH, nodes[NODE_WITHDRAWAL]))
        return false;
    for (size_t i = 0; i < sizeof(shor); i++) nodes[NODE_AMOUNT][i] = (uint8_t) (shor >> (i * 8));
    memcpy(nodes[NODE_RANDAO], s->randao, STAKING_RANDAO_LEN);
    memcpy(nodes[NODE_SIGNATURE], s->signature_root, STAKING_HASH_LEN);
    for (size_t width = NODE_COUNT; width > 1; width /= 2) {
        for (size_t i = 0; i < width / 2; i++) {
            if (!pair(s->hash, nodes[2 * i], nodes[2 * i + 1], nodes[i])) return false;
        }
    }
    return memcmp(nodes[0], s->expected_root, STAKING_HASH_LEN) == 0;
}
