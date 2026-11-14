#include "provide_token_metadata.h"

#include <string.h>

#include "cx.h"
#include "globals.h"
#include "request_context.h"
#include "io.h"
#include "sw.h"
#include "token_call.h"

#if defined(TOKEN_METADATA_TEST_KEY) && defined(TOKEN_METADATA_PUBLIC_KEY_BYTES)
#error "Select either TOKEN_METADATA_PUBLIC_KEY or TOKEN_METADATA_TEST_KEY"
#endif

#ifdef TOKEN_METADATA_TEST_KEY
/* INSECURE public test authority: the P-256 generator point, i.e. the private
 * scalar 1. The Makefile only accepts it together with DEBUG=1. */
static const uint8_t ISSUER_KEY[] = {
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5,
    0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4,
    0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a,
    0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33,
    0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};
#define TOKEN_METADATA_HAVE_ISSUER
#elif defined(TOKEN_METADATA_PUBLIC_KEY_BYTES)
/* Validated and decoded by the Makefile from TOKEN_METADATA_PUBLIC_KEY. */
static const uint8_t ISSUER_KEY[] = {TOKEN_METADATA_PUBLIC_KEY_BYTES};
#define TOKEN_METADATA_HAVE_ISSUER
#endif

#ifdef TOKEN_METADATA_HAVE_ISSUER
_Static_assert(sizeof(ISSUER_KEY) == 65, "issuer key must be an uncompressed SEC1 P-256 point");

static uint16_t verify_metadata(const uint8_t *data, size_t len, size_t body_len) {
    static const char domain[] = TOKEN_METADATA_DOMAIN;
    uint8_t message[sizeof(domain) - 1 + TOKEN_METADATA_FIXED_LEN + TOKEN_SYMBOL_MAX];
    uint8_t digest[32];
    cx_ecfp_public_key_t public_key;
    if (body_len > TOKEN_METADATA_FIXED_LEN + TOKEN_SYMBOL_MAX) return SW_TOKEN_METADATA_UNTRUSTED;
    memcpy(message, domain, sizeof(domain) - 1);
    memcpy(message + sizeof(domain) - 1, data, body_len);
    if (cx_hash_sha256(message, sizeof(domain) - 1 + body_len, digest, sizeof(digest)) !=
        sizeof(digest))
        return SW_TOKEN_METADATA_UNTRUSTED;
    if (cx_ecfp_init_public_key_no_throw(CX_CURVE_SECP256R1,
                                         ISSUER_KEY,
                                         sizeof(ISSUER_KEY),
                                         &public_key) != CX_OK)
        return SW_TOKEN_METADATA_UNTRUSTED;
    return cx_ecdsa_verify_no_throw(&public_key,
                                    digest,
                                    sizeof(digest),
                                    data + body_len,
                                    len - body_len)
               ? SW_OK
               : SW_TOKEN_METADATA_UNTRUSTED;
}
#else
static uint16_t verify_metadata(const uint8_t *data, size_t len, size_t body_len) {
    (void) data;
    (void) len;
    (void) body_len;
    /* No production authority configured: never accept host-selected keys. */
    return SW_TOKEN_METADATA_NO_ISSUER;
}
#endif

static int abort_metadata(uint16_t sw) {
    reset_request_context();
    return io_send_sw(sw);
}

int handler_provide_token_metadata(const uint8_t *data, size_t len, uint8_t p1, uint8_t p2) {
    if (p1 != 0 || p2 != 0) return abort_metadata(SW_WRONG_P1P2);
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_RECEIVING ||
        G_context.tx_info.stream.total_len != 0)
        return abort_metadata(SW_BAD_STATE);

    token_metadata_t *metadata = &G_context.tx_info.token_metadata;
    size_t body_len;
    if (!token_metadata_parse(data, len, metadata, &body_len)) {
        return abort_metadata(SW_TOKEN_METADATA_INVALID);
    }
    const uint16_t status = verify_metadata(data, len, body_len);
    if (status != SW_OK) {
        return abort_metadata(status);
    }
    metadata->verified = true;
    return io_send_sw(SW_OK);
}
