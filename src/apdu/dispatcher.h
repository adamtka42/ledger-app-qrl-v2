#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "constant.h"
#include "parser.h"
#include "types.h"

#define DATA_FIRST 0x00

#define DATA_MORE 0x01

#define DATA_LAST 0x02

/* Signing commands send their data in DATA_FIRST, DATA_MORE and DATA_LAST parts. A
 * non-zero P2, only with DATA_LAST, asks for that chunk of the signature. */
static inline bool sign_command_p1p2_valid(uint8_t p1, uint8_t p2) {
    if (p1 != DATA_FIRST && p1 != DATA_MORE && p1 != DATA_LAST) return false;
    if (p2 > SIGNATURE_LAST_CHUNK_INDEX) return false;
    return p2 == 0 || p1 == DATA_LAST;
}

/**
 * Dispatch APDU command received to the right handler.
 *
 * @param[in] cmd
 *   Structured APDU command (CLA, INS, P1, P2, Lc, Command data).
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int apdu_dispatcher(const command_t *cmd);
