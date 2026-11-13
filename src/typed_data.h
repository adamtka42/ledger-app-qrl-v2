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
#define TYPED_DATA_WORD_LEN     64 /* one QRVM word */
#define TYPED_DATA_HEADER_LEN   3  /* version, type count, primary type index */
#define TYPED_DATA_MAX_NEWLINES 16
#define TYPED_DATA_REVIEW_PART  64

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
} typed_data_t;

/** Start a bounded, versioned schema-and-values payload; no host digest is accepted. */
bool typed_data_init(typed_data_t *data, uint32_t length);
/** Receive an exact fragment of the declared payload. */
bool typed_data_feed(typed_data_t *data, const uint8_t *bytes, size_t length);
/** Validate schema/values, build a complete review and compute the QRL digest. */
bool typed_data_finish(typed_data_t *data);
/** Copy a schema identifier into a NUL-terminated output buffer. */
bool typed_data_name(const typed_data_t *data, typed_span_t name, char *out, size_t size);
