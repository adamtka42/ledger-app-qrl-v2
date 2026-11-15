#include "contract_call.h"

#include <string.h>

#include "call_checks.h"
#include "signed_payload.h"

_Static_assert(ABI_CALLDATA_LEN(CONTRACT_CALL_MAX_FIELDS) <= TX_CALLDATA_MAX_LEN,
               "complete contract calldata must fit in retained prefix");
_Static_assert(CONTRACT_DESCRIPTOR_BODY_MAX + DER_ECDSA_SIG_MAX_LEN <= CONTRACT_DESCRIPTOR_MAX_LEN,
               "signed descriptor must fit in one short APDU");

static bool letter(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static bool read_text(const uint8_t *data, size_t len, size_t *pos, char *out, size_t maximum) {
    if (*pos >= len) return false;
    const size_t n = data[(*pos)++];
    if (n == 0 || n > maximum || n > len - *pos || !letter(data[*pos]) || data[*pos + n - 1] == ' ')
        return false;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = data[*pos + i];
        if (!(letter(c) || (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '_'))
            return false;
    }
    memcpy(out, data + *pos, n);
    *pos += n;
    return true;
}

bool contract_descriptor_parse(const uint8_t *data,
                               size_t len,
                               contract_descriptor_t *out,
                               size_t *body_len) {
    if (out == NULL || body_len == NULL) return false;
    memset(out, 0, sizeof(*out));
    *body_len = 0;
    if (data == NULL || len < CONTRACT_DESCRIPTOR_MIN_BODY_LEN + DER_ECDSA_SIG_MIN_LEN ||
        len > CONTRACT_DESCRIPTOR_MAX_LEN || data[0] != SIGNED_PAYLOAD_VERSION)
        return false;
    memcpy(out->chain_id, data + CONTRACT_DESCRIPTOR_CHAIN_ID_OFFSET, MAX_FIELD_SIZE);
    memcpy(out->contract, data + CONTRACT_DESCRIPTOR_CONTRACT_OFFSET, ADDRESS_LENGTH);
    memcpy(out->selector, data + CONTRACT_DESCRIPTOR_SELECTOR_OFFSET, ABI_SELECTOR_LEN);
    if (all_zero(out->chain_id, MAX_FIELD_SIZE) || all_zero(out->contract, ADDRESS_LENGTH))
        return false;
    size_t pos = CONTRACT_DESCRIPTOR_FIXED_LEN;
    if (!read_text(data, len, &pos, out->operation, CONTRACT_CALL_TITLE_MAX) || pos >= len)
        return false;
    out->field_count = data[pos++];
    if (out->field_count == 0 || out->field_count > CONTRACT_CALL_MAX_FIELDS) return false;
    for (size_t i = 0; i < out->field_count; i++) {
        if (pos >= len) return false;
        contract_field_t *field = &out->fields[i];
        field->kind = data[pos++];
        if (field->kind < CONTRACT_FIELD_ADDRESS || field->kind > CONTRACT_FIELD_BOOL ||
            !read_text(data, len, &pos, field->label, CONTRACT_CALL_LABEL_MAX))
            return false;
    }
    if (pos > CONTRACT_DESCRIPTOR_BODY_MAX || !der_signature_is_well_formed(data + pos, len - pos))
        return false;
    *body_len = pos;
    return true;
}

bool contract_call_matches(const zond_tx_t *tx, const contract_descriptor_t *d) {
    if (tx == NULL || d == NULL || !d->verified) return false;
    if (d->field_count == 0 || d->field_count > CONTRACT_CALL_MAX_FIELDS) return false;
    if (!tx_is_plain_call(tx) || !tx->has_data ||
        tx->data_len != ABI_CALLDATA_LEN((uint32_t) d->field_count))
        return false;
    if (!chain_id_matches(tx, d->chain_id) || memcmp(tx->to, d->contract, ADDRESS_LENGTH) != 0)
        return false;
    if (memcmp(tx->data, d->selector, ABI_SELECTOR_LEN) != 0) return false;
    for (size_t i = 0; i < d->field_count; i++) {
        const uint8_t *word = abi_arg(tx->data, i);
        switch (d->fields[i].kind) {
            case CONTRACT_FIELD_ADDRESS:
                break;
            case CONTRACT_FIELD_UINT256:
                if (!all_zero(word, ABI_UINT256_OFFSET)) return false;
                break;
            case CONTRACT_FIELD_BOOL:
                if (!all_zero(word, ABI_WORD_LEN - 1) || word[ABI_WORD_LEN - 1] > 1) return false;
                break;
            default:
                return false;
        }
    }
    return true;
}
