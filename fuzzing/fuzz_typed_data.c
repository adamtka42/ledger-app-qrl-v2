/* Contract checks are part of this harness even in release builds. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "permit.h"
#include "typed_data.h"

/* Exercise the bounded-fragment path without depending on SDK font/layout code.
 * Device tests cover the actual NBGL page measurements. */
static size_t page_length(const char *label, char *text) {
    assert(label != NULL);
    size_t length = strlen(text);
    return length < 80 ? length : 80;
}

static void check_review(const typed_data_t *parsed) {
    assert(parsed->finished);
    assert(parsed->cursor == parsed->expected_len);
    assert(parsed->review_used > 0 && parsed->review_used <= sizeof(parsed->review));
    assert(parsed->pair_count > 0 && parsed->pair_count <= TYPED_DATA_MAX_PAIRS);
    for (size_t i = 0; i < parsed->pair_count; i++) {
        const typed_review_pair_t *pair = &parsed->pairs[i];
        assert(pair->label < parsed->review_used);
        assert(pair->value < parsed->review_used);
        assert(memchr(parsed->review + pair->label, '\0', parsed->review_used - pair->label) !=
               NULL);
        assert(memchr(parsed->review + pair->value, '\0', parsed->review_used - pair->value) !=
               NULL);
        assert(strlen(parsed->review + pair->label) < 48);
        assert(strlen(parsed->review + pair->value) <= 2 * TYPED_DATA_MAX_VALUE + 2);
    }
}

/* Token metadata naming the message's own domain, so permits are reachable.
 * Bit 1 of the control byte withholds authentication instead. */
static token_metadata_t token_for(const typed_data_t *parsed, uint8_t control) {
    token_metadata_t metadata = {.decimals = (uint8_t) (control % (TOKEN_DECIMALS_MAX + 1)),
                                 .symbol = "TKN",
                                 .verified = (control & 2) == 0};
    const typed_type_t *domain = &parsed->types[parsed->domain_type];
    for (size_t i = 0; i < domain->field_count; i++) {
        const typed_field_t *field = &parsed->fields[domain->first_field + i];
        const uint8_t *value = parsed->payload + parsed->value_offset[domain->first_field + i];
        char name[TYPED_DATA_MAX_NAME + 1];
        assert(typed_data_name(parsed, field->name, name, sizeof(name)));
        if (strcmp(name, "chainId") == 0)
            memcpy(metadata.chain_id, value + 32, sizeof(metadata.chain_id));
        else if (strcmp(name, "verifyingContract") == 0)
            memcpy(metadata.contract, value, sizeof(metadata.contract));
    }
    return metadata;
}

/* A recognised permit replaces the review; anything else leaves it untouched.
 * Either way the signed digest is the one computed from the payload. */
static void check_permit(typed_data_t *whole, typed_data_t *streamed, uint8_t control) {
    static typed_data_t before;
    memcpy(&before, whole, sizeof(before));
    const token_metadata_t metadata = token_for(whole, control);
    const bool prepared = permit_prepare(whole, &metadata);
    assert(permit_prepare(streamed, &metadata) == prepared);
    if (!prepared) return;
    assert(whole->permit_kind == streamed->permit_kind);
    assert(memcmp(whole->digest, before.digest, sizeof(before.digest)) == 0);
    if (whole->permit_kind == PERMIT_NONE) {
        assert(whole->review_used == before.review_used);
        assert(whole->pair_count == before.pair_count);
        assert(memcmp(whole->review, before.review, sizeof(before.review)) == 0);
        return;
    }
    assert(metadata.verified);
    assert(whole->permit_kind <= PERMIT_UNLIMITED);
    check_review(whole);
    check_review(streamed);
    assert(whole->permit_owner_pairs > 0 && whole->permit_owner_pairs < whole->pair_count);
    assert((size_t) whole->permit_owner + 64 < whole->review_used);
    assert(whole->review_used == streamed->review_used);
    assert(whole->pair_count == streamed->pair_count);
    assert(memcmp(whole->review, streamed->review, whole->review_used) == 0);
}

/* The first byte selects chunk size (1..255); its low bit also selects whole
 * values or bounded review fragments. Remaining bytes are the wire payload. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size - 1 > TYPED_DATA_MAX_PAYLOAD) return 0;
    uint8_t control = *data++;
    size--;
    size_t chunk = (size_t) (control % 255) + 1;
    typed_data_page_length_t paginate = (control & 1) ? page_length : NULL;
    static typed_data_t whole, streamed;
    bool initialized = typed_data_init(&whole, (uint32_t) size);
    assert(typed_data_init(&streamed, (uint32_t) size) == initialized);
    if (!initialized) return 0;
    assert(typed_data_feed(&whole, data, size));
    for (size_t offset = 0; offset < size;) {
        size_t count = size - offset;
        if (count > chunk) count = chunk;
        assert(typed_data_feed(&streamed, data + offset, count));
        offset += count;
    }
    assert(whole.received_len == size && streamed.received_len == size);
    assert(memcmp(whole.payload, streamed.payload, size) == 0);
    bool accepted = typed_data_finish(&whole, paginate);
    assert(typed_data_finish(&streamed, paginate) == accepted);
    if (!accepted) {
        assert(!whole.finished && !streamed.finished);
        return 0;
    }
    check_review(&whole);
    check_review(&streamed);
    assert(whole.review_used == streamed.review_used);
    assert(whole.pair_count == streamed.pair_count);
    assert(whole.has_chain_id == streamed.has_chain_id);
    assert(whole.has_verifying_contract == streamed.has_verifying_contract);
    assert(memcmp(whole.digest, streamed.digest, sizeof(whole.digest)) == 0);
    assert(memcmp(whole.review, streamed.review, whole.review_used) == 0);
    assert(memcmp(whole.pairs, streamed.pairs, whole.pair_count * sizeof(whole.pairs[0])) == 0);
    check_permit(&whole, &streamed, control);
    assert(!typed_data_finish(&streamed, paginate));
    assert(!typed_data_feed(&streamed, data, 1));
    return 0;
}
