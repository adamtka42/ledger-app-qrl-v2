#include "nft_call.h"

#include <string.h>

_Static_assert(NFT_CALL_CALLDATA_MAX <= TX_CALLDATA_MAX_LEN,
               "NFT calldata must fit in the retained transaction prefix");

#define WORD ADDRESS_LENGTH

typedef enum {
    ARG_ADDRESS,      // full word
    ARG_UINT256,      // low 32 bytes, upper half zero
    ARG_BOOL,         // 0 or 1
    ARG_EMPTY_BYTES,  // offset to the end of the head, followed by a zero length
} arg_e;

#define MAX_ARGS 5

typedef struct {
    uint8_t selector[4];
    uint8_t kind;  // nft_call_kind_e
    uint8_t arg_count;
    uint8_t args[MAX_ARGS];  // arg_e
} profile_t;

/* Same signatures as the ERC-721 and ERC-1155 calls they correspond to. */
static const profile_t PROFILES[] = {
    // transferFrom(address,address,uint256)
    {{0x23, 0xb8, 0x72, 0xdd}, NFT_CALL_TRANSFER, 3, {ARG_ADDRESS, ARG_ADDRESS, ARG_UINT256}},
    // safeTransferFrom(address,address,uint256)
    {{0x42, 0x84, 0x2e, 0x0e}, NFT_CALL_TRANSFER, 3, {ARG_ADDRESS, ARG_ADDRESS, ARG_UINT256}},
    // safeTransferFrom(address,address,uint256,bytes)
    {{0xb8, 0x8d, 0x4f, 0xde},
     NFT_CALL_TRANSFER,
     4,
     {ARG_ADDRESS, ARG_ADDRESS, ARG_UINT256, ARG_EMPTY_BYTES}},
    // safeTransferFrom(address,address,uint256,uint256,bytes)
    {{0xf2, 0x42, 0x43, 0x2a},
     NFT_CALL_TRANSFER,
     5,
     {ARG_ADDRESS, ARG_ADDRESS, ARG_UINT256, ARG_UINT256, ARG_EMPTY_BYTES}},
    // approve(address,uint256)
    {{0x09, 0x5e, 0xa7, 0xb3}, NFT_CALL_APPROVE, 2, {ARG_ADDRESS, ARG_UINT256}},
    // setApprovalForAll(address,bool)
    {{0xa2, 0x2c, 0xb4, 0x65}, NFT_CALL_APPROVE_ALL, 2, {ARG_ADDRESS, ARG_BOOL}},
};

static bool all_zero(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0) return false;
    }
    return true;
}

static bool name_char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

bool nft_metadata_parse(const uint8_t *data, size_t len, nft_metadata_t *out, size_t *body_len) {
    if (out == NULL || body_len == NULL) return false;
    memset(out, 0, sizeof(*out));
    *body_len = 0;
    if (data == NULL || len < NFT_METADATA_FIXED_LEN + 1 + 8 || data[0] != 1) return false;

    const size_t name_len = data[NFT_METADATA_FIXED_LEN - 1];
    const size_t signed_len = NFT_METADATA_FIXED_LEN + name_len;
    if (name_len == 0 || name_len > NFT_NAME_MAX || len < signed_len + 8 || len > signed_len + 72)
        return false;

    memcpy(out->chain_id, data + 1, MAX_FIELD_SIZE);
    memcpy(out->contract, data + 1 + MAX_FIELD_SIZE, ADDRESS_LENGTH);
    if (all_zero(out->chain_id, sizeof(out->chain_id)) ||
        all_zero(out->contract, sizeof(out->contract)))
        return false;

    /* Printable and unambiguous on every screen: no leading, trailing or
     * repeated separators, so a name cannot be padded to look like another. */
    const uint8_t *name = data + NFT_METADATA_FIXED_LEN;
    if (!name_char(name[0]) || !name_char(name[name_len - 1])) return false;
    for (size_t i = 0; i < name_len; i++) {
        const uint8_t c = name[i];
        const bool separator = (c == ' ' || c == '.' || c == '-' || c == '_');
        if (!name_char(c) && !(separator && name_char(name[i - 1]))) return false;
        out->name[i] = (char) c;
    }

    /* Require one complete DER sequence; reject unsigned/trailing payloads. */
    const uint8_t *sig = data + signed_len;
    const size_t sig_len = len - signed_len;
    if (sig[0] != 0x30 || (size_t) sig[1] + 2 != sig_len) return false;
    *body_len = signed_len;
    return true;
}

/* Full calldata length of a profile: the selector, one head word per argument
 * and the length word of the trailing empty `bytes`, if any. */
static uint32_t profile_len(const profile_t *p) {
    const bool has_bytes = p->args[p->arg_count - 1] == ARG_EMPTY_BYTES;
    return 4u + (uint32_t) WORD * (p->arg_count + (has_bytes ? 1u : 0u));
}

static bool arg_is_canonical(const profile_t *p, size_t index, const uint8_t *args) {
    const uint8_t *word = args + WORD * index;
    switch (p->args[index]) {
        case ARG_ADDRESS:
            return true;
        case ARG_UINT256:
            return all_zero(word, WORD - MAX_FIELD_SIZE);
        case ARG_BOOL:
            return all_zero(word, WORD - 1) && word[WORD - 1] <= 1;
        case ARG_EMPTY_BYTES: {
            /* The only accepted layout places the (empty) tail directly after
             * the head. Attached data is never hidden behind a clear review. */
            const size_t head = (size_t) WORD * p->arg_count;
            return index == (size_t) p->arg_count - 1 && all_zero(word, WORD - 2) &&
                   word[WORD - 2] == (uint8_t) (head >> 8) &&
                   word[WORD - 1] == (uint8_t) (head & 0xff) && all_zero(args + head, WORD);
        }
        default:
            return false;
    }
}

/* A call that only carries calldata: it moves no native coins and has no
 * access list, so everything it does is described by the decoded arguments. */
static bool tx_is_plain_call(const zond_tx_t *tx) {
    if (tx->to_len != ADDRESS_LENGTH || tx->has_access_list) return false;
    if (!tx->has_data || tx->data_len < 4 || tx->data_len > NFT_CALL_CALLDATA_MAX) return false;
    return tx->value_len <= MAX_FIELD_SIZE && all_zero(tx->value, tx->value_len);
}

/* The transaction's minimal big-endian chain ID equals the metadata's
 * zero-padded 32-byte one. */
static bool chain_id_matches(const zond_tx_t *tx, const nft_metadata_t *metadata) {
    if (tx->chain_id_len == 0 || tx->chain_id_len > MAX_FIELD_SIZE) return false;
    const size_t padding = MAX_FIELD_SIZE - tx->chain_id_len;
    return all_zero(metadata->chain_id, padding) &&
           memcmp(tx->chain_id, metadata->chain_id + padding, tx->chain_id_len) == 0;
}

bool nft_call_prepare(const zond_tx_t *tx, const nft_metadata_t *metadata, nft_call_t *out) {
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    if (tx == NULL || metadata == NULL || !metadata->verified) return false;
    if (!tx_is_plain_call(tx) || !chain_id_matches(tx, metadata)) return false;
    if (memcmp(tx->to, metadata->contract, ADDRESS_LENGTH) != 0) return false;

    const profile_t *profile = NULL;
    for (size_t i = 0; i < sizeof(PROFILES) / sizeof(PROFILES[0]); i++) {
        if (memcmp(tx->data, PROFILES[i].selector, 4) == 0) {
            profile = &PROFILES[i];
            break;
        }
    }
    if (profile == NULL || tx->data_len != profile_len(profile)) return false;

    const uint8_t *args = tx->data + 4;
    for (size_t i = 0; i < profile->arg_count; i++) {
        if (!arg_is_canonical(profile, i, args)) return false;
    }

    /* Low 32 bytes of the uint256 word at the given argument position. */
#define UINT256_AT(index) (args + WORD * (index) + WORD - MAX_FIELD_SIZE)
    switch (profile->kind) {
        case NFT_CALL_TRANSFER:
            if (profile->arg_count > 3 && profile->args[3] == ARG_UINT256) {
                // Moving nothing is not a transfer worth presenting as one.
                if (all_zero(UINT256_AT(3), MAX_FIELD_SIZE)) return false;
                memcpy(out->quantity, UINT256_AT(3), MAX_FIELD_SIZE);
                out->has_quantity = true;
            }
            memcpy(out->owner, args, ADDRESS_LENGTH);
            memcpy(out->target, args + WORD, ADDRESS_LENGTH);
            memcpy(out->token_id, UINT256_AT(2), MAX_FIELD_SIZE);
            break;
        case NFT_CALL_APPROVE:
            memcpy(out->target, args, ADDRESS_LENGTH);
            memcpy(out->token_id, UINT256_AT(1), MAX_FIELD_SIZE);
            break;
        case NFT_CALL_APPROVE_ALL:
            // An operator for the whole collection is always a real account.
            if (all_zero(args, ADDRESS_LENGTH)) return false;
            memcpy(out->target, args, ADDRESS_LENGTH);
            out->approved = args[WORD + WORD - 1] == 1;
            break;
        default:
            return false;
    }
#undef UINT256_AT
    out->kind = (nft_call_kind_e) profile->kind;
    return true;
}

bool nft_call_is_approval_revocation(const nft_call_t *call) {
    return call != NULL && call->kind == NFT_CALL_APPROVE &&
           all_zero(call->target, sizeof(call->target));
}
