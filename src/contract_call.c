#include "contract_call.h"

#include <string.h>

_Static_assert(4 + ADDRESS_LENGTH * CONTRACT_CALL_MAX_FIELDS <= TX_CALLDATA_MAX_LEN,
               "complete contract calldata must fit in retained prefix");
_Static_assert(CONTRACT_DESCRIPTOR_BODY_MAX + 72 <= 255,
               "signed descriptor must fit in one short APDU");

static bool zero(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0) return false;
    }
    return true;
}

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
    if (data == NULL || len < CONTRACT_DESCRIPTOR_FIXED_LEN + 2 + 1 + 3 + 8 || len > 255 ||
        data[0] != 1)
        return false;
    memcpy(out->chain_id, data + 1, 32);
    memcpy(out->contract, data + 33, ADDRESS_LENGTH);
    memcpy(out->selector, data + 33 + ADDRESS_LENGTH, 4);
    if (zero(out->chain_id, 32) || zero(out->contract, ADDRESS_LENGTH)) return false;
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
    if (pos > CONTRACT_DESCRIPTOR_BODY_MAX || len - pos < 8 || len - pos > 72 ||
        data[pos] != 0x30 || (size_t) data[pos + 1] + 2 != len - pos)
        return false;
    *body_len = pos;
    return true;
}

bool contract_call_matches(const zond_tx_t *tx, const contract_descriptor_t *d) {
    if (tx == NULL || d == NULL || !d->verified || d->field_count == 0 ||
        d->field_count > CONTRACT_CALL_MAX_FIELDS || tx->chain_id_len == 0 ||
        tx->chain_id_len > MAX_FIELD_SIZE || tx->to_len != ADDRESS_LENGTH ||
        tx->value_len > MAX_FIELD_SIZE || !zero(tx->value, tx->value_len) || tx->has_access_list ||
        !tx->has_data || tx->data_len != 4u + (uint32_t) ADDRESS_LENGTH * d->field_count ||
        !zero(d->chain_id, MAX_FIELD_SIZE - tx->chain_id_len) ||
        memcmp(tx->chain_id, d->chain_id + MAX_FIELD_SIZE - tx->chain_id_len, tx->chain_id_len) !=
            0 ||
        memcmp(tx->to, d->contract, ADDRESS_LENGTH) != 0 || memcmp(tx->data, d->selector, 4) != 0)
        return false;
    for (size_t i = 0; i < d->field_count; i++) {
        const uint8_t *word = tx->data + 4 + ADDRESS_LENGTH * i;
        switch (d->fields[i].kind) {
            case CONTRACT_FIELD_ADDRESS:
                break;
            case CONTRACT_FIELD_UINT256:
                if (!zero(word, ADDRESS_LENGTH - MAX_FIELD_SIZE)) return false;
                break;
            case CONTRACT_FIELD_BOOL:
                if (!zero(word, ADDRESS_LENGTH - 1) || word[ADDRESS_LENGTH - 1] > 1) return false;
                break;
            default:
                return false;
        }
    }
    return true;
}
