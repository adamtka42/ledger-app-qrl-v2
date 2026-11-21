#pragma once

#include "token_call.h"
#include "typed_data.h"

#define TYPED_DATA_UI_BYTES 2048

/* Only this small session is resident while ML-DSA uses the application stack. */
typedef struct {
    uint8_t digest[32];
    char primary_type[TYPED_DATA_MAX_NAME + 1];
    typed_review_pair_t pairs[TYPED_DATA_MAX_PAIRS];
    uint32_t expected_len;
    size_t received_len;
    uint8_t pair_count;
    bool has_chain_id;
    bool has_verifying_contract;
    bool finished;
    /* Optional issuer-signed token metadata, accepted before any payload byte. */
    token_metadata_t token_metadata;
    /* permit_kind_e; when not PERMIT_NONE the review holds token permit rows,
     * led by permit_owner_pairs rows for the owner whose bytes are at permit_owner. */
    uint8_t permit_kind;
    uint8_t permit_owner_pairs;
    uint16_t permit_owner;
} typed_data_session_t;

_Static_assert(sizeof(typed_data_session_t) <= 512,
               "typed-data session must preserve ML-DSA stack space");

/** Start an isolated temporary NVM payload. Its marker survives interrupted erasure. */
bool typed_data_session_init(typed_data_session_t *session, uint32_t length);
bool typed_data_session_feed(typed_data_session_t *session, const uint8_t *bytes, size_t length);
/** Parse using a temporary stack workspace, release it before UI/crypto is called. */
bool typed_data_session_finish(typed_data_session_t *session, typed_data_page_length_t page_length);
/** Return the immutable prepared review while a typed-data session is active. */
const char *typed_data_review(void);
/** Store immutable NBGL descriptors without keeping a large pair array in RAM. */
bool typed_data_store_ui(const void *bytes, size_t length);
const void *typed_data_ui(void);
/** Erase staged payload/review, including leftovers from a prior app interruption. */
void typed_data_storage_clear(void);
