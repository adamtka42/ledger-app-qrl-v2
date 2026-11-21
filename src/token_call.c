#include "token_call.h"

#include <string.h>

_Static_assert(TOKEN_CALL_CALLDATA_LEN <= TX_CALLDATA_MAX_LEN,
               "token calldata must fit in the retained transaction prefix");

static bool all_zero(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0) return false;
    }
    return true;
}

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
    if (data == NULL || len < TOKEN_METADATA_FIXED_LEN + 1 + 8 || data[0] != 1) return false;

    const size_t symbol_len = data[TOKEN_METADATA_FIXED_LEN - 1];
    const size_t signed_len = TOKEN_METADATA_FIXED_LEN + symbol_len;
    if (symbol_len == 0 || symbol_len > TOKEN_SYMBOL_MAX || len < signed_len + 8 ||
        len > signed_len + 72)
        return false;

    memcpy(out->chain_id, data + 1, MAX_FIELD_SIZE);
    memcpy(out->contract, data + 1 + MAX_FIELD_SIZE, ADDRESS_LENGTH);
    out->decimals = data[TOKEN_METADATA_FIXED_LEN - 2];
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
    /* Require one complete DER sequence; reject unsigned/trailing payloads. */
    const uint8_t *sig = data + signed_len;
    const size_t sig_len = len - signed_len;
    if (sig[0] != 0x30 || (size_t) sig[1] + 2 != sig_len) return false;
    *body_len = signed_len;
    return true;
}

bool token_call_prepare(const zond_tx_t *tx, const token_metadata_t *metadata, token_call_t *out) {
    static const uint8_t transfer_selector[] = {0xa9, 0x05, 0x9c, 0xbb};
    static const uint8_t approve_selector[] = {0x09, 0x5e, 0xa7, 0xb3};
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    if (tx == NULL || metadata == NULL || !metadata->verified || tx->chain_id_len == 0 ||
        tx->chain_id_len > MAX_FIELD_SIZE || tx->to_len != ADDRESS_LENGTH ||
        tx->value_len > MAX_FIELD_SIZE || tx->data_len != TOKEN_CALL_CALLDATA_LEN ||
        tx->has_access_list || !all_zero(tx->value, tx->value_len) ||
        memcmp(tx->to, metadata->contract, ADDRESS_LENGTH) != 0 ||
        !all_zero(metadata->chain_id, MAX_FIELD_SIZE - tx->chain_id_len) ||
        memcmp(tx->chain_id,
               metadata->chain_id + MAX_FIELD_SIZE - tx->chain_id_len,
               tx->chain_id_len) != 0 ||
        !all_zero(tx->data + 4 + ADDRESS_LENGTH, MAX_FIELD_SIZE))
        return false;

    token_call_kind_e kind;
    if (memcmp(tx->data, transfer_selector, sizeof(transfer_selector)) == 0) {
        kind = TOKEN_CALL_TRANSFER;
    } else if (memcmp(tx->data, approve_selector, sizeof(approve_selector)) == 0) {
        // A zero spender is outside the approval profile; it never means "revoke all".
        // Transfer recipients retain the existing literal-address display policy.
        if (all_zero(tx->data + 4, ADDRESS_LENGTH)) return false;
        kind = TOKEN_CALL_APPROVE;
    } else {
        return false;
    }

    /* QRVM ABI: four-byte selector followed by two 64-byte words. uint256
     * occupies the low 32 bytes of its word; its upper half must be zero. */
    memcpy(out->target, tx->data + 4, ADDRESS_LENGTH);
    memcpy(out->amount, tx->data + 4 + ADDRESS_LENGTH + MAX_FIELD_SIZE, MAX_FIELD_SIZE);
    out->kind = kind;
    return true;
}

bool token_call_is_unlimited_approval(const token_call_t *call) {
    if (call == NULL || call->kind != TOKEN_CALL_APPROVE) return false;
    for (size_t i = 0; i < sizeof(call->amount); i++) {
        if (call->amount[i] != 0xff) return false;
    }
    return true;
}

bool token_call_is_approval_revocation(const token_call_t *call) {
    return call != NULL && call->kind == TOKEN_CALL_APPROVE &&
           all_zero(call->amount, sizeof(call->amount));
}
