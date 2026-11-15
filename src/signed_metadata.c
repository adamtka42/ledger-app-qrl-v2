#include "signed_metadata.h"

#include <string.h>
#include "cx.h"

bool signed_metadata_verify(const uint8_t *issuer_key,
                            size_t issuer_key_len,
                            const char *domain,
                            size_t domain_len,
                            const uint8_t *data,
                            size_t len,
                            size_t body_len) {
    if (issuer_key == NULL || issuer_key_len != SIGNED_METADATA_PUBLIC_KEY_LEN || domain == NULL ||
        domain_len == 0 || domain_len > SIGNED_METADATA_MAX_DOMAIN_LEN || data == NULL ||
        body_len == 0 || body_len > SIGNED_METADATA_MAX_BODY_LEN || body_len > len ||
        len - body_len < 8 || len - body_len > 72)
        return false;

    uint8_t message[SIGNED_METADATA_MAX_DOMAIN_LEN + SIGNED_METADATA_MAX_BODY_LEN];
    uint8_t digest[32];
    cx_ecfp_public_key_t public_key;
    memcpy(message, domain, domain_len);
    memcpy(message + domain_len, data, body_len);
    if (cx_hash_sha256(message, domain_len + body_len, digest, sizeof(digest)) != sizeof(digest))
        return false;
    if (cx_ecfp_init_public_key_no_throw(CX_CURVE_SECP256R1,
                                         issuer_key,
                                         issuer_key_len,
                                         &public_key) != CX_OK)
        return false;
    return cx_ecdsa_verify_no_throw(&public_key,
                                    digest,
                                    sizeof(digest),
                                    data + body_len,
                                    len - body_len);
}
