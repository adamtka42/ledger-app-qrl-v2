#pragma once

/* Issuer-signed payloads: a version byte, the signed body and a DER-encoded
 * ECDSA P-256 signature over the domain-separated body. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SIGNED_PAYLOAD_VERSION 1

/* SEQUENCE { INTEGER r, INTEGER s }, each integer one to 33 bytes long. */
#define DER_SEQUENCE_TAG      0x30
#define DER_ECDSA_SIG_MIN_LEN 8
#define DER_ECDSA_SIG_MAX_LEN 72

/* Exactly one DER sequence of an ECDSA signature's length; trailing bytes are rejected. */
static inline bool der_signature_is_well_formed(const uint8_t *sig, size_t len) {
    return len >= DER_ECDSA_SIG_MIN_LEN && len <= DER_ECDSA_SIG_MAX_LEN &&
           sig[0] == DER_SEQUENCE_TAG && (size_t) sig[1] + 2 == len;
}
