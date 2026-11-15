#pragma once

#include <stdbool.h>
#include "../cx.h"

#define CX_CURVE_SECP256R1 0x22u
/* Opaque test representation. Tests exercise call wiring and failure handling;
 * actual P-256 signatures are verified by the SDK in device tests. */
typedef struct {
    uint8_t marker;
} cx_ecfp_public_key_t;

size_t cx_hash_sha256(const uint8_t *data, size_t len, uint8_t *digest, size_t digest_len);
cx_err_t cx_ecfp_init_public_key_no_throw(uint32_t curve,
                                          const uint8_t *key,
                                          size_t len,
                                          cx_ecfp_public_key_t *out);
bool cx_ecdsa_verify_no_throw(const cx_ecfp_public_key_t *key,
                              const uint8_t *digest,
                              size_t digest_len,
                              const uint8_t *signature,
                              size_t signature_len);
