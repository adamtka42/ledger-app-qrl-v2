#include "typed_data_storage.h"

#include <string.h>

#include "os_nvm.h"
#include "os_pic.h"
#include "permit.h"

typedef struct {
    uint8_t active[64];
    uint8_t payload[TYPED_DATA_MAX_PAYLOAD];
    char review[TYPED_DATA_REVIEW_BYTES];
    uint8_t ui[TYPED_DATA_UI_BYTES];
} typed_storage_t;

#ifdef TEST
static typed_storage_t N_typed_data_real;
#else
/* The SDK linker collects .rodata.N_* in its writable NVM data section. */
const typed_storage_t N_typed_data_real __attribute__((aligned(64))) = {0};
#endif
#define N_typed (*(volatile typed_storage_t *) PIC(&N_typed_data_real))

static void zero_nvm(volatile void *destination, size_t length) {
    static const uint8_t zeros[128] = {0};
    volatile uint8_t *out = destination;
    for (size_t offset = 0; offset < length; offset += sizeof(zeros)) {
        size_t count = length - offset;
        if (count > sizeof(zeros)) count = sizeof(zeros);
        bool dirty = false;
        for (size_t i = 0; i < count; i++) dirty |= out[offset + i] != 0;
        /* The SDK takes void * for its read-only source buffer. */
        if (dirty) nvm_write((void *) (out + offset), (void *) zeros, count);
    }
}

void typed_data_storage_clear(void) {
    if (N_typed.active[0] == 0) return;
    zero_nvm(N_typed.payload, sizeof(N_typed.payload));
    zero_nvm(N_typed.review, sizeof(N_typed.review));
    zero_nvm(N_typed.ui, sizeof(N_typed.ui));
    /* Clear the marker last: a power loss during erasure retries on app startup. */
    zero_nvm(N_typed.active, sizeof(N_typed.active));
}

const char *typed_data_review(void) {
    return (const char *) N_typed.review;
}

bool typed_data_store_ui(const void *bytes, size_t length) {
    if (N_typed.active[0] != 1 || bytes == NULL || length > sizeof(N_typed.ui)) return false;
    nvm_write((void *) N_typed.ui, (void *) bytes, length);
    return true;
}

const void *typed_data_ui(void) {
    return (const void *) N_typed.ui;
}

bool typed_data_session_init(typed_data_session_t *session, uint32_t length) {
    if (session == NULL || length < 3 || length > TYPED_DATA_MAX_PAYLOAD) return false;
    typed_data_storage_clear();
    memset(session, 0, sizeof(*session));
    session->expected_len = length;
    uint8_t active = 1;
    nvm_write((void *) N_typed.active, &active, 1);
    return true;
}

bool typed_data_session_feed(typed_data_session_t *session, const uint8_t *bytes, size_t length) {
    if (session == NULL || session->finished || N_typed.active[0] != 1 ||
        session->expected_len < 3 || session->expected_len > TYPED_DATA_MAX_PAYLOAD ||
        session->received_len > session->expected_len ||
        length > session->expected_len - session->received_len || bytes == NULL || length == 0)
        return false;
    nvm_write((void *) (N_typed.payload + session->received_len), (void *) bytes, length);
    session->received_len += length;
    return true;
}

/* This function must return before address derivation/signing: the crypto engine
 * needs ~20 KiB of stack. Do not inline its temporary parser into the handler. */
__attribute__((noinline)) bool typed_data_session_finish(typed_data_session_t *session,
                                                         typed_data_page_length_t page_length) {
    if (session == NULL || session->finished || N_typed.active[0] != 1 ||
        session->received_len != session->expected_len)
        return false;
    typed_data_t parsed;
    bool result = false;
    if (!typed_data_init(&parsed, session->expected_len) ||
        !typed_data_feed(&parsed, (const uint8_t *) N_typed.payload, session->received_len))
        goto cleanup;
    zero_nvm(N_typed.payload, sizeof(N_typed.payload));
    if (!typed_data_finish(&parsed, page_length) ||
        !typed_data_name(&parsed,
                         parsed.types[parsed.primary_type].name,
                         session->primary_type,
                         sizeof(session->primary_type)) ||
        !permit_prepare(&parsed, &session->token_metadata))
        goto cleanup;
    nvm_write((void *) N_typed.review, parsed.review, parsed.review_used);
    memcpy(session->digest, parsed.digest, sizeof(session->digest));
    memcpy(session->pairs, parsed.pairs, sizeof(session->pairs));
    session->pair_count = parsed.pair_count;
    session->has_chain_id = parsed.has_chain_id;
    session->has_verifying_contract = parsed.has_verifying_contract;
    session->permit_kind = parsed.permit_kind;
    session->permit_owner_pairs = parsed.permit_owner_pairs;
    session->permit_owner = parsed.permit_owner;
    session->finished = true;
    result = true;
cleanup:
    explicit_bzero(&parsed, sizeof(parsed));
    return result;
}
