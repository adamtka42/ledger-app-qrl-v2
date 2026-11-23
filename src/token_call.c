#include "token_call.h"

#include <string.h>

#include "call_checks.h"
#include "signed_payload.h"

_Static_assert(TOKEN_CALL_TRANSFER_FROM_CALLDATA_LEN <= TX_CALLDATA_MAX_LEN,
               "token calldata must fit in the retained transaction prefix");

/* Case-insensitive match against the native ticker, without ctype. */
static bool is_native_ticker(const char *symbol, size_t len) {
    static const char native[] = TOKEN_NATIVE_TICKER;
    if (len != sizeof(native) - 1) return false;
    for (size_t i = 0; i < len; i++) {
        char c = symbol[i];
        if (c >= 'a' && c <= 'z') c = (char) (c - 'a' + 'A');
        if (c != native[i]) return false;
    }
    return true;
}

bool token_metadata_parse(const uint8_t *data,
                          size_t len,
                          token_metadata_t *out,
                          size_t *body_len) {
    if (out == NULL || body_len == NULL) return false;
    memset(out, 0, sizeof(*out));
    *body_len = 0;
    if (data == NULL || len < TOKEN_METADATA_FIXED_LEN + 1 + DER_ECDSA_SIG_MIN_LEN ||
        data[0] != SIGNED_PAYLOAD_VERSION)
        return false;

    const size_t symbol_len = data[TOKEN_METADATA_SYMBOL_LEN_OFFSET];
    const size_t signed_len = TOKEN_METADATA_FIXED_LEN + symbol_len;
    if (symbol_len == 0 || symbol_len > TOKEN_SYMBOL_MAX ||
        len < signed_len + DER_ECDSA_SIG_MIN_LEN)
        return false;

    memcpy(out->chain_id, data + TOKEN_METADATA_CHAIN_ID_OFFSET, MAX_FIELD_SIZE);
    memcpy(out->contract, data + TOKEN_METADATA_CONTRACT_OFFSET, ADDRESS_LENGTH);
    out->decimals = data[TOKEN_METADATA_DECIMALS_OFFSET];
    if (out->decimals > TOKEN_DECIMALS_MAX || all_zero(out->chain_id, sizeof(out->chain_id)) ||
        all_zero(out->contract, sizeof(out->contract)))
        return false;
    for (size_t i = 0; i < symbol_len; i++) {
        const uint8_t c = data[TOKEN_METADATA_FIXED_LEN + i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == '_'))
            return false;
        out->symbol[i] = (char) c;
    }
    /* A token symbol equal to the native ticker would render a token
     * transfer's Amount row exactly like a native QRL transfer. */
    if (is_native_ticker(out->symbol, symbol_len)) return false;
    if (!der_signature_is_well_formed(data + signed_len, len - signed_len)) return false;
    *body_len = signed_len;
    return true;
}

/* The metadata was signed for this contract on this chain. */
static bool metadata_matches_tx(const token_metadata_t *metadata, const zond_tx_t *tx) {
    return metadata->verified && chain_id_matches(tx, metadata->chain_id) &&
           memcmp(tx->to, metadata->contract, ADDRESS_LENGTH) == 0;
}

/* The calls token metadata can clear-sign. The amount is the word after the
 * target and ends the calldata. */
typedef struct {
    uint8_t selector[ABI_SELECTOR_LEN];
    token_call_kind_e kind;
    uint8_t target_arg;
} token_profile_t;

static const token_profile_t PROFILES[] = {
    {{0xa9, 0x05, 0x9c, 0xbb}, TOKEN_CALL_TRANSFER, 0},
    {{0x09, 0x5e, 0xa7, 0xb3}, TOKEN_CALL_APPROVE, 0},
    // The same selector is used by ERC-721. Only issuer-authenticated fungible-token
    // metadata permits interpreting the last word as an amount.
    {{0x23, 0xb8, 0x72, 0xdd}, TOKEN_CALL_TRANSFER_FROM, 1},
};

static const token_profile_t *find_profile(const uint8_t *calldata) {
    for (size_t i = 0; i < sizeof(PROFILES) / sizeof(PROFILES[0]); i++) {
        if (memcmp(calldata, PROFILES[i].selector, ABI_SELECTOR_LEN) == 0) return &PROFILES[i];
    }
    return NULL;
}

bool token_call_prepare(const zond_tx_t *tx, const token_metadata_t *metadata, token_call_t *out) {
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    if (tx == NULL || metadata == NULL) return false;
    if (!tx_is_plain_call(tx) || !metadata_matches_tx(metadata, tx)) return false;

    const token_profile_t *profile = find_profile(tx->data);
    if (profile == NULL) return false;
    // A zero spender is outside the approval profile; it never means "revoke all".
    // Transfer recipients retain the existing literal-address display policy.
    if (profile->kind == TOKEN_CALL_APPROVE && all_zero(abi_arg(tx->data, 0), ADDRESS_LENGTH))
        return false;
    const size_t amount_arg = profile->target_arg + 1u;
    if (tx->data_len != ABI_CALLDATA_LEN(amount_arg + 1u)) return false;
    /* The amount is a uint256, so the upper half of its word must be zero. */
    const uint8_t *amount = abi_arg(tx->data, amount_arg);
    if (!all_zero(amount, ABI_UINT256_OFFSET)) return false;

    if (profile->kind == TOKEN_CALL_TRANSFER_FROM)
        memcpy(out->source, abi_arg(tx->data, 0), ADDRESS_LENGTH);
    memcpy(out->target, abi_arg(tx->data, profile->target_arg), ADDRESS_LENGTH);
    memcpy(out->amount, amount + ABI_UINT256_OFFSET, MAX_FIELD_SIZE);
    out->kind = profile->kind;
    return true;
}

bool token_call_is_unlimited_approval(const token_call_t *call) {
    return call != NULL && call->kind == TOKEN_CALL_APPROVE &&
           all_bytes_equal(call->amount, sizeof(call->amount), 0xff);
}

bool token_call_is_approval_revocation(const token_call_t *call) {
    return call != NULL && call->kind == TOKEN_CALL_APPROVE &&
           all_zero(call->amount, sizeof(call->amount));
}
