#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* QRL Typed Structured Data v1, using 64-byte VM words and Keccak-256. */
#define TYPED_DATA_MAX_PAYLOAD  4096
#define TYPED_DATA_MAX_TYPES    8
#define TYPED_DATA_MAX_FIELDS   32
#define TYPED_DATA_MAX_DEPTH    4
#define TYPED_DATA_MAX_ARRAY    8
#define TYPED_DATA_MAX_VALUE    256
#define TYPED_DATA_MAX_NAME     24
#define TYPED_DATA_MAX_PATH     128
#define TYPED_DATA_REVIEW_BYTES 4096
#define TYPED_DATA_MAX_PAIRS    64

/* Return a positive prefix length fitting one mandatory review page. A callback
 * may temporarily terminate text for layout measurement, but must restore it. */
typedef size_t (*typed_data_page_length_t)(const char *label, char *text);

typedef struct {
    uint16_t offset;
    uint16_t length;
} typed_span_t;

typedef enum {
    TYPED_ADDRESS,
    TYPED_BOOL,
    TYPED_STRING,
    TYPED_BYTES,
    TYPED_FIXED_BYTES,
    TYPED_UINT,
    TYPED_INT,
    TYPED_STRUCT
} typed_kind_t;

typedef struct {
    typed_span_t name;
    typed_span_t type_name;
    typed_kind_t kind;
    uint16_t width;
    uint8_t reference;
    bool array;
} typed_field_t;

typedef struct {
    typed_span_t name;
    uint8_t first_field;
    uint8_t field_count;
    uint8_t hash[32];
} typed_type_t;

typedef struct {
    uint16_t label;
    uint16_t value;
} typed_review_pair_t;

typedef struct {
    uint8_t payload[TYPED_DATA_MAX_PAYLOAD];
    char review[TYPED_DATA_REVIEW_BYTES];
    typed_type_t types[TYPED_DATA_MAX_TYPES];
    typed_field_t fields[TYPED_DATA_MAX_FIELDS];
    typed_review_pair_t pairs[TYPED_DATA_MAX_PAIRS];
    uint8_t digest[32];
    uint32_t expected_len;
    size_t received_len;
    size_t cursor;
    size_t review_used;
    uint8_t type_count;
    uint8_t field_count;
    uint8_t pair_count;
    uint8_t value_count;
    uint8_t primary_type;
    uint8_t domain_type;
    bool has_chain_id;
    bool has_verifying_contract;
    bool finished;
    typed_data_page_length_t review_page_length;
} typed_data_t;

/* Only the temporary workspace is bounded here; recursive hash/layout frames
 * need additional stack. Reassess this cap and APP_STACK_MIN_SIZE when raising
 * parser limits, especially TYPED_DATA_MAX_DEPTH. */
#define TYPED_DATA_MAX_WORKSPACE_BYTES (10 * 1024)
_Static_assert(sizeof(typed_data_t) <= TYPED_DATA_MAX_WORKSPACE_BYTES,
               "typed-data parser workspace exceeds stack budget; remeasure before raising limits");

/** Start a bounded, versioned schema-and-values payload; no host digest is accepted. */
bool typed_data_init(typed_data_t *data, uint32_t length);
/** Receive an exact fragment of the declared payload. */
bool typed_data_feed(typed_data_t *data, const uint8_t *bytes, size_t length);
/** Validate/hash and build the review. NULL leaves whole values for Nano NBGL;
 * otherwise page_length bounds every fragment without changing the signed data. */
bool typed_data_finish(typed_data_t *data, typed_data_page_length_t page_length);
/** Copy a schema identifier into a NUL-terminated output buffer. */
bool typed_data_name(const typed_data_t *data, typed_span_t name, char *out, size_t size);
