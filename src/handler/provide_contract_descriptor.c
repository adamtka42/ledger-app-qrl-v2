#include "provide_contract_descriptor.h"

#include "signed_metadata.h"
#include "globals.h"
#include "request_context.h"
#include "io.h"
#include "sw.h"
#include "contract_call.h"

#if defined(CONTRACT_DESCRIPTOR_TEST_KEY) && defined(CONTRACT_DESCRIPTOR_PUBLIC_KEY_BYTES)
#error "Select either CONTRACT_DESCRIPTOR_PUBLIC_KEY or CONTRACT_DESCRIPTOR_TEST_KEY"
#endif

#ifdef CONTRACT_DESCRIPTOR_TEST_KEY
/* INSECURE public test authority: the P-256 generator point, i.e. the private
 * scalar 1. The Makefile only accepts it together with DEBUG=1. */
static const uint8_t ISSUER_KEY[] = {
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5,
    0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4,
    0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a,
    0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33,
    0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};
#define CONTRACT_DESCRIPTOR_HAVE_ISSUER
#elif defined(CONTRACT_DESCRIPTOR_PUBLIC_KEY_BYTES)
/* Validated and decoded by the Makefile from CONTRACT_DESCRIPTOR_PUBLIC_KEY. */
static const uint8_t ISSUER_KEY[] = {CONTRACT_DESCRIPTOR_PUBLIC_KEY_BYTES};
#define CONTRACT_DESCRIPTOR_HAVE_ISSUER
#endif

#ifdef CONTRACT_DESCRIPTOR_HAVE_ISSUER
_Static_assert(sizeof(ISSUER_KEY) == 65, "issuer key must be an uncompressed SEC1 P-256 point");

_Static_assert(sizeof(CONTRACT_DESCRIPTOR_DOMAIN) - 1 <= SIGNED_METADATA_MAX_DOMAIN_LEN,
               "metadata domain exceeds verifier workspace");
_Static_assert(CONTRACT_DESCRIPTOR_BODY_MAX <= SIGNED_METADATA_MAX_BODY_LEN,
               "metadata body exceeds verifier workspace");

static uint16_t verify_metadata(const uint8_t *data, size_t len, size_t body_len) {
    static const char domain[] = CONTRACT_DESCRIPTOR_DOMAIN;
    if (body_len > CONTRACT_DESCRIPTOR_BODY_MAX) return SW_CONTRACT_DESCRIPTOR_UNTRUSTED;
    return signed_metadata_verify(ISSUER_KEY,
                                  sizeof(ISSUER_KEY),
                                  domain,
                                  sizeof(domain) - 1,
                                  data,
                                  len,
                                  body_len)
               ? SW_OK
               : SW_CONTRACT_DESCRIPTOR_UNTRUSTED;
}
#else
static uint16_t verify_metadata(const uint8_t *data, size_t len, size_t body_len) {
    (void) data;
    (void) len;
    (void) body_len;
    /* No production authority configured: never accept host-selected keys. */
    return SW_CONTRACT_DESCRIPTOR_NO_ISSUER;
}
#endif

static int abort_metadata(uint16_t sw) {
    reset_request_context();
    return io_send_sw(sw);
}

int handler_provide_contract_descriptor(const uint8_t *data, size_t len, uint8_t p1, uint8_t p2) {
    if (p1 != 0 || p2 != 0) return abort_metadata(SW_WRONG_P1P2);
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_RECEIVING ||
        G_context.tx_info.stream.total_len != 0 || G_context.tx_info.token_metadata.verified ||
        G_context.tx_info.nft_metadata.verified || G_context.tx_info.contract_descriptor.verified)
        return abort_metadata(SW_BAD_STATE);

    contract_descriptor_t *metadata = &G_context.tx_info.contract_descriptor;
    size_t body_len;
    if (!contract_descriptor_parse(data, len, metadata, &body_len)) {
        return abort_metadata(SW_CONTRACT_DESCRIPTOR_INVALID);
    }
    const uint16_t status = verify_metadata(data, len, body_len);
    if (status != SW_OK) {
        return abort_metadata(status);
    }
    metadata->verified = true;
    return io_send_sw(SW_OK);
}
