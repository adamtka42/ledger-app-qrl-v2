#ifndef RLP_DECODE_H
#define RLP_DECODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "tx_types.h"  // zond_tx_t

int decode_ledger_tx(const uint8_t *rlp, size_t rlp_len, zond_tx_t *tx);

#endif
