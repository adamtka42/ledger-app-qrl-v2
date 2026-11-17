#undef NDEBUG
#include <assert.h>
#include <string.h>
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/sha.h>
#include "staking_deposit.h"

static bool hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    // Low-level SHA keeps the static fuzzer independent of EVP provider/compression libraries.
    SHA256_CTX context;
    return SHA256_Init(&context) == 1 && SHA256_Update(&context, data, len) == 1 &&
           SHA256_Final(out, &context) == 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    if (len < 32) return 0;
    zond_tx_t tx = {0};
    tx.has_data = true;
    tx.value_len = 32;
    memcpy(tx.value, data, 32);
    tx.data_len = (uint32_t) (len - 32);
    data += 32;
    len -= 32;
    staking_deposit_t a, b;
    staking_deposit_init(&a, hash);
    staking_deposit_init(&b, hash);
    staking_deposit_feed(&a, 0, (uint32_t) len, data, len);
    for (size_t p = 0; p < len;) {
        size_t n = 1 + data[p] % 255;
        if (n > len - p) n = len - p;
        staking_deposit_feed(&b, (uint32_t) p, (uint32_t) len, data + p, n);
        p += n;
    }
    assert(a.selected == b.selected);
    assert(a.ignored == b.ignored);
    assert(a.failed == b.failed);
    assert(staking_deposit_validate(&a, &tx) == staking_deposit_validate(&b, &tx));
    if (staking_deposit_validate(&a, &tx)) {
        assert(a.position == STAKING_CALLDATA_LEN && !a.failed && a.selected);
        assert(memcmp(a.withdrawal, b.withdrawal, 64) == 0);
        assert(memcmp(a.pubkey_root, b.pubkey_root, 32) == 0);
    }
    return 0;
}
