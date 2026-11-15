#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounded workspace for the supported metadata profiles. Callers assert that
 * their domain and body limits fit, and retain their own smaller profile limit. */
#define SIGNED_METADATA_MAX_DOMAIN_LEN 32u
#define SIGNED_METADATA_MAX_BODY_LEN   169u
#define SIGNED_METADATA_PUBLIC_KEY_LEN 65u

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
