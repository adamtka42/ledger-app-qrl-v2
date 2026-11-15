#include "provide_token_metadata.h"

#include "signed_metadata.h"
#include "globals.h"
#include "request_context.h"
#include "io.h"
#include "sw.h"
#include "token_call.h"

#if defined(TOKEN_METADATA_TEST_KEY) && defined(TOKEN_METADATA_PUBLIC_KEY_BYTES)
#error "Select either TOKEN_METADATA_PUBLIC_KEY or TOKEN_METADATA_TEST_KEY"
#endif

#ifdef TOKEN_METADATA_TEST_KEY
/* INSECURE public test authority; see signed_metadata.h. */
static const uint8_t ISSUER_KEY[] = {SIGNED_METADATA_TEST_PUBLIC_KEY_BYTES};
#define TOKEN_METADATA_HAVE_ISSUER
#elif defined(TOKEN_METADATA_PUBLIC_KEY_BYTES)
/* Validated and decoded by the Makefile from TOKEN_METADATA_PUBLIC_KEY. */
static const uint8_t ISSUER_KEY[] = {TOKEN_METADATA_PUBLIC_KEY_BYTES};
#define TOKEN_METADATA_HAVE_ISSUER
#endif

#ifdef TOKEN_METADATA_HAVE_ISSUER
_Static_assert(sizeof(ISSUER_KEY) == SIGNED_METADATA_PUBLIC_KEY_LEN,
               "issuer key must be an uncompressed SEC1 P-256 point");

_Static_assert(sizeof(TOKEN_METADATA_DOMAIN) - 1 <= SIGNED_METADATA_MAX_DOMAIN_LEN,
               "metadata domain exceeds verifier workspace");
_Static_assert(TOKEN_METADATA_BODY_MAX <= SIGNED_METADATA_MAX_BODY_LEN,
               "metadata body exceeds verifier workspace");

static uint16_t verify_metadata(const uint8_t *data, size_t len, size_t body_len) {
    static const char domain[] = TOKEN_METADATA_DOMAIN;
    if (body_len > TOKEN_METADATA_BODY_MAX) return SW_TOKEN_METADATA_UNTRUSTED;
    return signed_metadata_verify(ISSUER_KEY,
                                  sizeof(ISSUER_KEY),
                                  domain,
                                  sizeof(domain) - 1,
                                  data,
                                  len,
                                  body_len)
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
        G_context.tx_info.stream.total_len != 0 || G_context.tx_info.contract_descriptor.verified)
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
