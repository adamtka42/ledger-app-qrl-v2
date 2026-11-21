#include "permit.h"

#include <string.h>

#include "address_format.h"
#include "tx_format.h"

#define WORD        64
#define UINT256_LEN 32
#define FIELD_COUNT 5

enum { FIELD_OWNER, FIELD_SPENDER, FIELD_VALUE, FIELD_NONCE, FIELD_DEADLINE };

/* Inline arrays avoid unrelocated pointers in the Ledger PIC address space. */
static const char FIELD_NAMES[FIELD_COUNT][9] = {"owner", "spender", "value", "nonce", "deadline"};
static const char FIELD_TYPES[FIELD_COUNT][8] = {"address",
                                                 "address",
                                                 "uint256",
                                                 "uint256",
                                                 "uint256"};

static bool span_is(const typed_data_t *data, typed_span_t span, const char *text) {
    return span.length == strlen(text) &&
           memcmp(data->payload + span.offset, text, span.length) == 0;
}

static bool all_bytes(const uint8_t *bytes, size_t length, uint8_t value) {
    uint8_t diff = 0;
    for (size_t i = 0; i < length; i++) diff |= bytes[i] ^ value;
    return diff == 0;
}

/* Exactly the standard five fields, in the order fixed by the permit type hash. */
static bool is_permit_schema(const typed_data_t *data) {
    const typed_type_t *primary = &data->types[data->primary_type];
    if (data->type_count != 2 || primary->field_count != FIELD_COUNT ||
        !span_is(data, primary->name, "Permit"))
        return false;
    for (size_t i = 0; i < FIELD_COUNT; i++) {
        const typed_field_t *field = &data->fields[primary->first_field + i];
        if (field->array || !span_is(data, field->name, FIELD_NAMES[i]) ||
            !span_is(data, field->type_name, FIELD_TYPES[i]))
            return false;
    }
    return true;
}

/* The domain must name the token and its network, and nothing the review
 * would have to hide: a salt keeps the message on the generic review. */
static bool domain_is_token(const typed_data_t *data, const token_metadata_t *metadata) {
    const typed_type_t *domain = &data->types[data->domain_type];
    const uint8_t *chain_id = NULL, *contract = NULL;
    for (size_t i = 0; i < domain->field_count; i++) {
        const typed_field_t *field = &data->fields[domain->first_field + i];
        const uint8_t *value = data->payload + data->value_offset[domain->first_field + i];
        if (span_is(data, field->name, "salt")) return false;
        if (span_is(data, field->name, "chainId")) chain_id = value;
        if (span_is(data, field->name, "verifyingContract")) contract = value;
    }
    return chain_id != NULL && contract != NULL &&
           memcmp(chain_id + WORD - UINT256_LEN, metadata->chain_id, UINT256_LEN) == 0 &&
           memcmp(contract, metadata->contract, ADDRESS_LENGTH) == 0;
}

static void two_digits(char *out, unsigned value) {
    out[0] = (char) ('0' + value / 10);
    out[1] = (char) ('0' + value % 10);
}

bool permit_format_deadline(const uint8_t word[64], char *out, size_t size) {
    static const char never[] = "No expiry date";
    /* 9999-12-31 23:59:59 UTC is 253402300799 = 0x3AFFF4417F. */
    static const uint8_t last[5] = {0x3a, 0xff, 0xf4, 0x41, 0x7f};
    if (word == NULL || out == NULL || size < PERMIT_DEADLINE_MAX_LEN) return false;
    const uint8_t *value = word + WORD - sizeof(last);
    if (!all_bytes(word, WORD - sizeof(last), 0) || memcmp(value, last, sizeof(last)) > 0) {
        memcpy(out, never, sizeof(never));
        return true;
    }
    /* Long division by one day keeps every intermediate value within 32 bits. */
    uint32_t days = 0, seconds = 0;
    for (size_t i = 0; i < sizeof(last); i++) {
        const uint32_t part = (seconds << 8) | value[i];
        days = (days << 8) | (part / 86400u);
        seconds = part % 86400u;
    }
    /* Civil date from days since 1970-01-01 (proleptic Gregorian calendar). */
    const uint32_t shifted = days + 719468u;
    const uint32_t era = shifted / 146097u;
    const uint32_t day_of_era = shifted - era * 146097u;
    const uint32_t year_of_era =
        (day_of_era - day_of_era / 1460u + day_of_era / 36524u - day_of_era / 146096u) / 365u;
    const uint32_t day_of_year =
        day_of_era - (365u * year_of_era + year_of_era / 4u - year_of_era / 100u);
    const uint32_t month_index = (5u * day_of_year + 2u) / 153u;
    const uint32_t day = day_of_year - (153u * month_index + 2u) / 5u + 1u;
    const uint32_t month = month_index < 10u ? month_index + 3u : month_index - 9u;
    const uint32_t year = year_of_era + era * 400u + (month <= 2u ? 1u : 0u);

    memcpy(out, "0000-00-00 00:00:00 UTC", PERMIT_DEADLINE_MAX_LEN);
    two_digits(out, year / 100u);
    two_digits(out + 2, year % 100u);
    two_digits(out + 5, month);
    two_digits(out + 8, day);
    two_digits(out + 11, seconds / 3600u);
    two_digits(out + 14, seconds / 60u % 60u);
    two_digits(out + 17, seconds % 60u);
    return true;
}

static bool format_limit(const uint8_t *value,
                         const token_metadata_t *metadata,
                         permit_kind_e kind,
                         char *out,
                         size_t size) {
    char integer[TX_FORMAT_MAX_DECIMAL_DIGITS + 1], amount[TX_FORMAT_MAX_AMOUNT_LEN];
    const size_t symbol_len = strlen(metadata->symbol);
    if (kind == PERMIT_UNLIMITED) {
        memcpy(amount, "Unlimited", sizeof("Unlimited"));
    } else if (!uint8_array_to_decimal(value, UINT256_LEN, integer, sizeof(integer)) ||
               !format_with_decimals(integer, metadata->decimals, amount, sizeof(amount))) {
        return false;
    }
    const size_t amount_len = strlen(amount);
    if (symbol_len + 1 + amount_len + 1 > size) return false;
    memcpy(out, metadata->symbol, symbol_len);
    out[symbol_len] = ' ';
    memcpy(out + symbol_len + 1, amount, amount_len + 1);
    return true;
}

bool permit_prepare(typed_data_t *data, const token_metadata_t *metadata) {
    if (data == NULL || !data->finished) return false;
    data->permit_kind = PERMIT_NONE;
    if (metadata == NULL || !metadata->verified || !is_permit_schema(data) ||
        !domain_is_token(data, metadata))
        return true;

    const uint8_t first = data->types[data->primary_type].first_field;
    const uint8_t *words[FIELD_COUNT];
    for (size_t i = 0; i < FIELD_COUNT; i++)
        words[i] = data->payload + data->value_offset[first + i];
    const uint8_t *value = words[FIELD_VALUE] + WORD - UINT256_LEN;
    const permit_kind_e kind = all_bytes(value, UINT256_LEN, 0)      ? PERMIT_REVOKE
                               : all_bytes(value, UINT256_LEN, 0xff) ? PERMIT_UNLIMITED
                                                                     : PERMIT_LIMITED;

    /* Format everything before touching the generic review. */
    char owner[2 * ADDRESS_LENGTH + 2], spender[2 * ADDRESS_LENGTH + 2];
    char contract[2 * ADDRESS_LENGTH + 2];
    char limit[TX_FORMAT_MAX_AMOUNT_LEN + TOKEN_SYMBOL_MAX + 2];
    char chain_id[TX_FORMAT_MAX_DECIMAL_DIGITS + 1], nonce[TX_FORMAT_MAX_DECIMAL_DIGITS + 1];
    char deadline[PERMIT_DEADLINE_MAX_LEN];
    if (!format_checksummed_address(words[FIELD_OWNER], owner, sizeof(owner)) ||
        !format_checksummed_address(words[FIELD_SPENDER], spender, sizeof(spender)) ||
        !format_checksummed_address(metadata->contract, contract, sizeof(contract)) ||
        !format_limit(value, metadata, kind, limit, sizeof(limit)) ||
        !uint8_array_to_decimal(metadata->chain_id, UINT256_LEN, chain_id, sizeof(chain_id)) ||
        !uint8_array_to_decimal(words[FIELD_NONCE] + WORD - UINT256_LEN,
                                UINT256_LEN,
                                nonce,
                                sizeof(nonce)) ||
        !permit_format_deadline(words[FIELD_DEADLINE], deadline, sizeof(deadline)))
        return false;
    uint8_t owner_bytes[ADDRESS_LENGTH];
    memcpy(owner_bytes, words[FIELD_OWNER], sizeof(owner_bytes));

    /* The owner comes first so the review can leave it out when it is the
     * signing account, which is already shown. */
    typed_data_review_reset(data);
    if (!typed_data_review_blob(data, owner_bytes, sizeof(owner_bytes), &data->permit_owner) ||
        !typed_data_review_add(data, "Token owner", owner))
        return false;
    data->permit_owner_pairs = data->pair_count;
    if (!typed_data_review_add(data, "Spending limit", limit) ||
        !typed_data_review_add(data, "Spender", spender) ||
        !typed_data_review_add(data, "Token contract", contract) ||
        !typed_data_review_add(data, "Chain ID", chain_id) ||
        !typed_data_review_add(data, "Valid until", deadline) ||
        !typed_data_review_add(data, "Permit nonce", nonce))
        return false;
    data->permit_kind = (uint8_t) kind;
    return true;
}
