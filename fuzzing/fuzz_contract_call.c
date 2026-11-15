#undef NDEBUG
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "contract_call.h"

static bool letter(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static void assert_text(const char *text, size_t maximum) {
    const char *end = memchr(text, '\0', maximum + 1);
    assert(end != NULL);
    const size_t len = (size_t) (end - text);
    assert(len > 0 && len <= maximum && letter((unsigned char) text[0]));
    assert(text[len - 1] != ' ');
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char) text[i];
        assert(letter(c) || (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '_');
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    contract_descriptor_t d;
    size_t body;
    if (!contract_descriptor_parse(data, size, &d, &body)) return 0;
    assert(!d.verified && body <= CONTRACT_DESCRIPTOR_BODY_MAX && body < size);
    assert(d.field_count > 0 && d.field_count <= CONTRACT_CALL_MAX_FIELDS);
    assert_text(d.operation, CONTRACT_CALL_TITLE_MAX);
    for (size_t i = 0; i < d.field_count; i++)
        assert_text(d.fields[i].label, CONTRACT_CALL_LABEL_MAX);
    zond_tx_t tx = {0};
    tx.chain_id_len = MAX_FIELD_SIZE;
    memcpy(tx.chain_id, d.chain_id, MAX_FIELD_SIZE);
    tx.to_len = ADDRESS_LENGTH;
    memcpy(tx.to, d.contract, ADDRESS_LENGTH);
    tx.has_data = true;
    tx.data_len = 4 + ADDRESS_LENGTH * d.field_count;
    memcpy(tx.data, d.selector, 4);
    assert(!contract_call_matches(&tx, &d));
    d.verified = true;  // Matcher-only trust; never represents an authenticated issuer.
    assert(contract_call_matches(&tx, &d));
    tx.data_len++;
    assert(!contract_call_matches(&tx, &d));
    tx.data_len--;
    tx.data[0] ^= 1;
    assert(!contract_call_matches(&tx, &d));
    return 0;
}
