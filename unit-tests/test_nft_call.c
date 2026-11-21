#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "nft_call.h"

#define WORD ADDRESS_LENGTH

static const uint8_t TRANSFER_FROM[] = {0x23, 0xb8, 0x72, 0xdd};
static const uint8_t SAFE_TRANSFER[] = {0x42, 0x84, 0x2e, 0x0e};
static const uint8_t SAFE_TRANSFER_DATA[] = {0xb8, 0x8d, 0x4f, 0xde};
static const uint8_t MULTI_TRANSFER[] = {0xf2, 0x42, 0x43, 0x2a};
static const uint8_t APPROVE[] = {0x09, 0x5e, 0xa7, 0xb3};
static const uint8_t APPROVE_ALL[] = {0xa2, 0x2c, 0xb4, 0x65};

static zond_tx_t tx;
static nft_metadata_t metadata;
static nft_call_t call;

static uint8_t *word(size_t index) {
    return tx.data + 4 + WORD * index;
}

/* A verified collection and a call to it with `words` zeroed argument words. */
static void candidate(const uint8_t selector[4], size_t words) {
    memset(&tx, 0, sizeof(tx));
    memset(&metadata, 0, sizeof(metadata));
    tx.chain_id[0] = 1;
    tx.chain_id_len = 1;
    memset(tx.to, 0x22, ADDRESS_LENGTH);
    tx.to_len = ADDRESS_LENGTH;
    tx.has_data = true;
    tx.data_len = 4 + WORD * words;
    memcpy(tx.data, selector, 4);
    metadata.chain_id[MAX_FIELD_SIZE - 1] = 1;
    memcpy(metadata.contract, tx.to, ADDRESS_LENGTH);
    memcpy(metadata.name, "Quantum Cats", sizeof("Quantum Cats"));
    metadata.verified = true;
}

static void single_transfer(const uint8_t selector[4], bool with_data) {
    candidate(selector, with_data ? 5 : 3);
    memset(word(0), 0x33, WORD);
    memset(word(1), 0x11, WORD);
    word(2)[WORD - 1] = 42;
    if (with_data) word(3)[WORD - 2] = 0x01;  // offset 256: directly after four head words
}

static void multi_transfer(void) {
    candidate(MULTI_TRANSFER, 6);
    memset(word(0), 0x33, WORD);
    memset(word(1), 0x11, WORD);
    word(2)[WORD - 1] = 42;
    word(3)[WORD - 1] = 5;
    word(4)[WORD - 2] = 0x01;  // offset 320: directly after five head words
    word(4)[WORD - 1] = 0x40;
}

static void approve(void) {
    candidate(APPROVE, 2);
    memset(word(0), 0x11, WORD);
    word(1)[WORD - 1] = 42;
}

static void approve_all(bool approved) {
    candidate(APPROVE_ALL, 2);
    memset(word(0), 0x11, WORD);
    word(1)[WORD - 1] = approved;
}

static void assert_rejected(void) {
    const nft_call_t none = {0};
    assert_false(nft_call_prepare(&tx, &metadata, &call));
    assert_memory_equal(&call, &none, sizeof(call));
}

static void test_single_token_transfers(void **state) {
    (void) state;
    const struct {
        const uint8_t *selector;
        bool with_data;
    } cases[] = {{TRANSFER_FROM, false}, {SAFE_TRANSFER, false}, {SAFE_TRANSFER_DATA, true}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        single_transfer(cases[i].selector, cases[i].with_data);
        assert_true(nft_call_prepare(&tx, &metadata, &call));
        assert_int_equal(call.kind, NFT_CALL_TRANSFER);
        assert_memory_equal(call.owner, word(0), ADDRESS_LENGTH);
        assert_memory_equal(call.target, word(1), ADDRESS_LENGTH);
        assert_int_equal(call.token_id[MAX_FIELD_SIZE - 1], 42);
        assert_false(call.has_quantity);
        assert_false(nft_call_is_approval_revocation(&call));

        // The full uint256 range is a valid token ID.
        memset(word(2) + WORD - MAX_FIELD_SIZE, 0xff, MAX_FIELD_SIZE);
        assert_true(nft_call_prepare(&tx, &metadata, &call));
        assert_int_equal(call.token_id[0], 0xff);
        word(2)[WORD - MAX_FIELD_SIZE - 1] = 1;
        assert_rejected();
    }
}

static void test_multi_token_transfer(void **state) {
    (void) state;
    multi_transfer();
    assert_true(nft_call_prepare(&tx, &metadata, &call));
    assert_int_equal(call.kind, NFT_CALL_TRANSFER);
    assert_true(call.has_quantity);
    assert_int_equal(call.token_id[MAX_FIELD_SIZE - 1], 42);
    assert_int_equal(call.quantity[MAX_FIELD_SIZE - 1], 5);

    word(3)[WORD - 1] = 0;  // zero quantity
    assert_rejected();
    multi_transfer();
    word(3)[0] = 1;  // quantity above uint256
    assert_rejected();
}

static void test_attached_data_is_never_hidden(void **state) {
    (void) state;
    // Non-empty data: a longer transaction no longer matches the profile.
    single_transfer(SAFE_TRANSFER_DATA, true);
    word(4)[WORD - 1] = 1;
    assert_rejected();
    single_transfer(SAFE_TRANSFER_DATA, true);
    tx.data_len += WORD;
    assert_rejected();
    // Offsets that do not point directly behind the head.
    single_transfer(SAFE_TRANSFER_DATA, true);
    word(3)[WORD - 1] = 1;
    assert_rejected();
    single_transfer(SAFE_TRANSFER_DATA, true);
    word(3)[WORD - 2] = 0;
    assert_rejected();
    single_transfer(SAFE_TRANSFER_DATA, true);
    word(3)[0] = 1;
    assert_rejected();
    multi_transfer();
    word(4)[WORD - 1] = 0;  // the single-token offset is wrong for five head words
    assert_rejected();
    multi_transfer();
    word(5)[0] = 1;
    assert_rejected();
}

static void test_approvals(void **state) {
    (void) state;
    approve();
    assert_true(nft_call_prepare(&tx, &metadata, &call));
    assert_int_equal(call.kind, NFT_CALL_APPROVE);
    assert_memory_equal(call.target, word(0), ADDRESS_LENGTH);
    assert_int_equal(call.token_id[MAX_FIELD_SIZE - 1], 42);
    assert_false(nft_call_is_approval_revocation(&call));

    memset(word(0), 0, WORD);  // the zero address clears a single approval
    assert_true(nft_call_prepare(&tx, &metadata, &call));
    assert_true(nft_call_is_approval_revocation(&call));

    for (int approved = 0; approved < 2; approved++) {
        approve_all(approved);
        assert_true(nft_call_prepare(&tx, &metadata, &call));
        assert_int_equal(call.kind, NFT_CALL_APPROVE_ALL);
        assert_int_equal(call.approved, approved);
        assert_memory_equal(call.target, word(0), ADDRESS_LENGTH);
        assert_false(nft_call_is_approval_revocation(&call));
    }
    approve_all(true);
    word(1)[WORD - 1] = 2;  // not a bool
    assert_rejected();
    approve_all(true);
    word(1)[0] = 1;
    assert_rejected();
    approve_all(true);
    memset(word(0), 0, WORD);  // no operator
    assert_rejected();
    assert_false(nft_call_is_approval_revocation(NULL));
}

static void test_no_false_clear_signing(void **state) {
    (void) state;
    for (int mutation = 0; mutation < 16; mutation++) {
        single_transfer(TRANSFER_FROM, false);
        switch (mutation) {
            case 0:
                metadata.verified = false;
                break;
            case 1:
                metadata.contract[63] ^= 1;
                break;
            case 2:
                metadata.chain_id[0] = 1;  // same low bytes, different network
                break;
            case 3:
                tx.chain_id[0] = 2;
                break;
            case 4:
                tx.chain_id_len = 0;
                break;
            case 5:
                tx.to_len = 0;  // contract creation
                break;
            case 6:
                tx.value[0] = 1;
                tx.value_len = 1;
                break;
            case 7:
                tx.has_access_list = true;
                break;
            case 8:
                tx.data[0] ^= 1;  // unknown selector
                break;
            case 9:
                tx.data_len--;
                break;
            case 10:
                tx.data_len++;
                break;
            case 11:
                tx.data_len = 3;
                break;
            case 12:
                tx.data_len = TX_CALLDATA_MAX_LEN + 1;
                break;
            case 13:
                tx.has_data = false;
                break;
            case 14:
                memcpy(tx.data, (uint8_t[]) {0xa9, 0x05, 0x9c, 0xbb}, 4);  // token transfer
                tx.data_len = 4 + 2 * WORD;
                break;
            case 15:
                memcpy(tx.data, SAFE_TRANSFER_DATA, 4);  // head only, tail missing
                tx.data_len = 4 + 4 * WORD;
                break;
        }
        assert_rejected();
    }
    single_transfer(TRANSFER_FROM, false);
    assert_false(nft_call_prepare(NULL, &metadata, &call));
    assert_false(nft_call_prepare(&tx, NULL, &call));
    assert_false(nft_call_prepare(&tx, &metadata, NULL));

    // A long chain ID must match in full.
    single_transfer(TRANSFER_FROM, false);
    memset(tx.chain_id, 0xab, MAX_FIELD_SIZE);
    tx.chain_id_len = MAX_FIELD_SIZE;
    memset(metadata.chain_id, 0xab, MAX_FIELD_SIZE);
    assert_true(nft_call_prepare(&tx, &metadata, &call));
}

/* version || chain ID || contract || name length || name || DER signature */
static size_t payload(uint8_t *out, const char *name) {
    static const uint8_t signature[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    const size_t name_len = strlen(name);
    size_t n = 0;
    out[n++] = 1;
    memset(out + n, 0, MAX_FIELD_SIZE);
    out[n + MAX_FIELD_SIZE - 1] = 1;
    n += MAX_FIELD_SIZE;
    memset(out + n, 0x22, ADDRESS_LENGTH);
    n += ADDRESS_LENGTH;
    out[n++] = (uint8_t) name_len;
    memcpy(out + n, name, name_len);
    n += name_len;
    memcpy(out + n, signature, sizeof(signature));
    return n + sizeof(signature);
}

static void test_metadata_parse(void **state) {
    (void) state;
    uint8_t data[255];
    nft_metadata_t parsed;
    size_t body_len;

    size_t len = payload(data, "Quantum Cats v2.0");
    assert_true(nft_metadata_parse(data, len, &parsed, &body_len));
    assert_int_equal(body_len, len - 8);
    assert_string_equal(parsed.name, "Quantum Cats v2.0");
    assert_int_equal(parsed.chain_id[MAX_FIELD_SIZE - 1], 1);
    assert_int_equal(parsed.contract[0], 0x22);
    assert_false(parsed.verified);  // parsing never authenticates

    len = payload(data, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");  // longest name
    assert_true(nft_metadata_parse(data, len, &parsed, &body_len));
    assert_int_equal(strlen(parsed.name), NFT_NAME_MAX);

    const char *bad_names[] = {
        "",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",  // too long
        " Cats",
        "Cats ",
        "Quantum  Cats",  // repeated separator
        "Cats.-x",
        "-Cats",
        "Cats\nTo",
        "Cats(1)",
        "C\x7f",
        "C\xc3\xa9",
    };
    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
        len = payload(data, bad_names[i]);
        assert_false(nft_metadata_parse(data, len, &parsed, &body_len));
        assert_int_equal(body_len, 0);
    }

    for (int mutation = 0; mutation < 8; mutation++) {
        len = payload(data, "Cats");
        switch (mutation) {
            case 0:
                data[0] = 2;  // unknown version
                break;
            case 1:
                memset(data + 1, 0, MAX_FIELD_SIZE);  // no chain
                break;
            case 2:
                memset(data + 1 + MAX_FIELD_SIZE, 0, ADDRESS_LENGTH);  // no contract
                break;
            case 3:
                len--;  // truncated signature
                break;
            case 4:
                data[len++] = 0;  // trailing byte
                break;
            case 5:
                data[len - 8] = 0x31;  // not a DER sequence
                break;
            case 6:
                len = NFT_METADATA_FIXED_LEN + 4;  // unsigned
                break;
            case 7:
                len = 0;
                break;
        }
        assert_false(nft_metadata_parse(data, len, &parsed, &body_len));
    }
    assert_false(nft_metadata_parse(NULL, 100, &parsed, &body_len));
    assert_false(nft_metadata_parse(data, len, NULL, &body_len));
    assert_false(nft_metadata_parse(data, len, &parsed, NULL));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_single_token_transfers),
        cmocka_unit_test(test_multi_token_transfer),
        cmocka_unit_test(test_attached_data_is_never_hidden),
        cmocka_unit_test(test_approvals),
        cmocka_unit_test(test_no_false_clear_signing),
        cmocka_unit_test(test_metadata_parse),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
