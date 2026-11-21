#pragma once

#include "token_call.h"
#include "typed_data.h"

/* Token spending permit: an off-chain signature with the effect of approve().
 *
 *   Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)
 *
 * It is clear-signed only when the domain's chain ID and verifying contract are
 * the ones named by issuer-signed token metadata. */
typedef enum {
    PERMIT_NONE = 0,
    PERMIT_LIMITED,
    PERMIT_REVOKE,
    PERMIT_UNLIMITED,
} permit_kind_e;

/* Deadlines after 9999-12-31 23:59:59 UTC are shown as having no expiry. */
#define PERMIT_DEADLINE_MAX_LEN sizeof("9999-12-31 23:59:59 UTC")

/* Format a 64-byte unsigned deadline (Unix seconds) for review. */
bool permit_format_deadline(const uint8_t word[64], char *out, size_t size);

/* Replace the generic review of a finished message with token-approval rows
 * when it is a supported Permit for the verified token. Any other message, or
 * absent metadata, keeps its generic review and PERMIT_NONE. Returns false only
 * if a recognised permit cannot be presented in full. */
bool permit_prepare(typed_data_t *data, const token_metadata_t *metadata);
