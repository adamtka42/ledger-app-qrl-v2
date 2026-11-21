#pragma once

/* QRVM ABI calldata: a four-byte selector followed by 64-byte argument words. */

#include <stddef.h>
#include <stdint.h>

#include "tx_types.h"

#define ABI_SELECTOR_LEN 4
#define ABI_WORD_LEN     64

/* Length of a selector followed by n argument words. */
#define ABI_CALLDATA_LEN(n) (ABI_SELECTOR_LEN + (n) * ABI_WORD_LEN)

/* A uint256 fills the low MAX_FIELD_SIZE bytes of its word. */
#define ABI_UINT256_OFFSET (ABI_WORD_LEN - MAX_FIELD_SIZE)

_Static_assert(ABI_WORD_LEN == ADDRESS_LENGTH, "an address fills one ABI word");

/* Argument word i of calldata that starts with a selector. */
static inline const uint8_t *abi_arg(const uint8_t *calldata, size_t i) {
    return calldata + ABI_SELECTOR_LEN + i * ABI_WORD_LEN;
}
