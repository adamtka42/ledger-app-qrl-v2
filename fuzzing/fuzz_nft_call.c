#undef NDEBUG
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "nft_call.h"

/* Input: one length byte, that many bytes of untrusted metadata payload, and
 * the remainder as calldata sent to the described collection. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nft_metadata_t metadata;
    size_t body;
    if (size == 0 || data[0] > size - 1) return 0;
    const size_t payload = data[0];
    data++;
    size--;
    if (!nft_metadata_parse(data, payload, &metadata, &body)) {
        assert(body == 0);
        return 0;
    }
    assert(!metadata.verified && body <= NFT_METADATA_BODY_MAX && body < payload);
    const char *end = memchr(metadata.name, '\0', sizeof(metadata.name));
    assert(end != NULL && end != metadata.name);
    for (const char *c = metadata.name; c < end; c++) assert(*c >= ' ' && *c <= '~');
    assert(metadata.name[0] != ' ' && end[-1] != ' ');

    zond_tx_t tx = {0};
    tx.chain_id_len = MAX_FIELD_SIZE;
    memcpy(tx.chain_id, metadata.chain_id, MAX_FIELD_SIZE);
    tx.to_len = ADDRESS_LENGTH;
    memcpy(tx.to, metadata.contract, ADDRESS_LENGTH);
    const size_t calldata = size - payload;
    tx.has_data = calldata != 0;
    tx.data_len = (uint32_t) calldata;
    memcpy(tx.data, data + payload, calldata < sizeof(tx.data) ? calldata : sizeof(tx.data));

    nft_call_t call;
    const nft_call_t none = {0};
    assert(!nft_call_prepare(&tx, &metadata, &call));  // parsed is not authenticated
    assert(memcmp(&call, &none, sizeof(call)) == 0);
    metadata.verified = true;  // Matcher-only trust; never represents an authenticated issuer.
    if (!nft_call_prepare(&tx, &metadata, &call)) {
        assert(memcmp(&call, &none, sizeof(call)) == 0);
        return 0;
    }
    assert(call.kind != NFT_CALL_NONE && tx.data_len <= NFT_CALL_CALLDATA_MAX);
    assert(!call.has_quantity || call.kind == NFT_CALL_TRANSFER);
    assert(!call.approved || call.kind == NFT_CALL_APPROVE_ALL);
    tx.data_len++;
    assert(!nft_call_prepare(&tx, &metadata, &call));
    return 0;
}
