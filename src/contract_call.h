#pragma once

#include "tx_types.h"

/* V1 describes every argument, in order, as a static 64-byte QRVM ABI word.
 * No offsets, omitted words, dynamic values, native value or access lists. */
#define CONTRACT_CALL_MAX_FIELDS      3
#define CONTRACT_CALL_TITLE_MAX       24
#define CONTRACT_CALL_LABEL_MAX       12
#define CONTRACT_DESCRIPTOR_DOMAIN    "QRL-CONTRACT-DESCRIPTOR-V1"
#define CONTRACT_DESCRIPTOR_FIXED_LEN (1 + MAX_FIELD_SIZE + ADDRESS_LENGTH + 4)
#define CONTRACT_DESCRIPTOR_BODY_MAX                                 \
    (1 + 32 + ADDRESS_LENGTH + 4 + 1 + CONTRACT_CALL_TITLE_MAX + 1 + \
     CONTRACT_CALL_MAX_FIELDS * (2 + CONTRACT_CALL_LABEL_MAX))

typedef enum {
    CONTRACT_FIELD_ADDRESS = 1,
    CONTRACT_FIELD_UINT256 = 2,
    CONTRACT_FIELD_BOOL = 3,
} contract_field_kind_e;

typedef struct {
    uint8_t kind;
    char label[CONTRACT_CALL_LABEL_MAX + 1];
} contract_field_t;

typedef struct {
    uint8_t chain_id[MAX_FIELD_SIZE];
    uint8_t contract[ADDRESS_LENGTH];
    uint8_t selector[4];
    char operation[CONTRACT_CALL_TITLE_MAX + 1];
    contract_field_t fields[CONTRACT_CALL_MAX_FIELDS];
    uint8_t field_count;
    bool verified;
} contract_descriptor_t;

/* Decode an untrusted descriptor plus DER signature. Never sets verified. */
bool contract_descriptor_parse(const uint8_t *data,
                               size_t len,
                               contract_descriptor_t *out,
                               size_t *body_len);

/* Require an authenticated descriptor and a complete, canonical supported call. */
bool contract_call_matches(const zond_tx_t *tx, const contract_descriptor_t *descriptor);
