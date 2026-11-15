#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounded workspace for the supported metadata profiles. Callers assert that
 * their domain and body limits fit, and retain their own smaller profile limit. */
#define SIGNED_METADATA_MAX_DOMAIN_LEN 32u
#define SIGNED_METADATA_MAX_BODY_LEN   169u
#define SIGNED_METADATA_PUBLIC_KEY_LEN 65u

/* INSECURE public test authority for builds with a *_TEST_KEY option: the P-256
 * generator point, i.e. the private scalar 1. The Makefile only accepts it
 * together with DEBUG=1. */
#define SIGNED_METADATA_TEST_PUBLIC_KEY_BYTES                                                     \
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,     \
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, \
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, \
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, \
        0x68, 0x37, 0xbf, 0x51, 0xf5

/* Verify ECDSA P-256 over SHA-256(domain || data[0:body_len]). The remaining
 * data bytes are the DER signature. Keys and domains come from firmware, never
 * from the host. This function does not parse metadata or authorize a session. */
bool signed_metadata_verify(const uint8_t *issuer_key,
                            size_t issuer_key_len,
                            const char *domain,
                            size_t domain_len,
                            const uint8_t *data,
                            size_t len,
                            size_t body_len);
