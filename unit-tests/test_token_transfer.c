#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "token_call.h"
#include "tx_stream.h"
#include "tx_format.h"

static void candidate(zond_tx_t *tx, token_metadata_t *metadata) {
    memset(tx, 0, sizeof(*tx));
    memset(metadata, 0, sizeof(*metadata));
    tx->chain_id[0] = 1;
    tx->chain_id_len = 1;
    memset(tx->to, 0x22, ADDRESS_LENGTH);
    tx->to_len = ADDRESS_LENGTH;
    tx->has_data = true;
    tx->data_len = TOKEN_CALL_CALLDATA_LEN;
    const uint8_t selector[] = {0xa9, 0x05, 0x9c, 0xbb};
    memcpy(tx->data, selector, sizeof(selector));
    memset(tx->data + 4, 0x11, ADDRESS_LENGTH);
    /* Matches the local web3-qrl-abi vector for Q111... and 123456789. */
    const uint8_t value[] = {0x07, 0x5b, 0xcd, 0x15};
    memcpy(tx->data + TOKEN_CALL_CALLDATA_LEN - sizeof(value), value, sizeof(value));
    metadata->chain_id[MAX_FIELD_SIZE - 1] = 1;
    memcpy(metadata->contract, tx->to, ADDRESS_LENGTH);
    metadata->decimals = 6;
    memcpy(metadata->symbol, "TKN", 4);
    metadata->verified = true;
}

static void test_transfer_and_format(void **state) {
    (void) state;
    zond_tx_t tx;
    token_metadata_t metadata;
    token_call_t transfer;
    candidate(&tx, &metadata);
    assert_true(token_call_prepare(&tx, &metadata, &transfer));
    assert_true(transfer.enabled);
    assert_memory_equal(transfer.target, tx.data + 4, ADDRESS_LENGTH);
    char integer[100], amount[100];
    assert_true(
        uint8_array_to_decimal(transfer.amount, sizeof(transfer.amount), integer, sizeof(integer)));
    assert_string_equal(integer, "123456789");
    assert_true(format_with_decimals(integer, metadata.decimals, amount, sizeof(amount)));
    assert_string_equal(amount, "123.456789");

    memset(tx.data + 100, 0, 32);
    assert_true(token_call_prepare(&tx, &metadata, &transfer));
    memset(tx.data + 100, 0xff, 32);
    assert_true(token_call_prepare(&tx, &metadata, &transfer));
    assert_true(uint8_array_to_decimal(transfer.amount, 32, integer, sizeof(integer)));
    assert_string_equal(
        integer,
        "115792089237316195423570985008687907853269984665640564039457584007913129639935");
    assert_true(format_with_decimals(integer, TOKEN_DECIMALS_MAX, amount, sizeof(amount)));
    assert_false(format_with_decimals(integer, TOKEN_DECIMALS_MAX, amount, 10));
}

static void test_no_false_clear_signing(void **state) {
    (void) state;
    zond_tx_t tx;
    token_metadata_t metadata;
    token_call_t transfer;
    for (int mutation = 0; mutation < 14; mutation++) {
        candidate(&tx, &metadata);
        switch (mutation) {
            case 0:
                metadata.verified = false;
                break;
            case 1:
                metadata.contract[63] ^= 1;
                break;
            case 2:
                metadata.chain_id[0] = 1;
                break;  // same low 64 bits, different network
            case 3:
                tx.chain_id[0] = 2;
                break;
            case 4:
                tx.data[0] ^= 1;
                break;
            case 5:
                tx.data[68] = 1;
                break;  // uint256 overflow in a QRVM word
            case 6:
                tx.data_len--;
                break;
            case 7:
                tx.data_len++;
                break;
            case 8:
                tx.value[0] = 1;
                tx.value_len = 1;
                break;
            case 9:
                tx.has_access_list = true;
                break;
            case 10:
                tx.to_len = 0;
                break;
            case 11:
                tx.chain_id_len = 0;
                break;
            case 12:
                tx.data_len = TX_CALLDATA_MAX_LEN;
                break;
            case 13:
                tx.data_len = TX_CALLDATA_MAX_LEN + 1;
                break;
        }
        memset(&transfer, 0xff, sizeof(transfer));
        assert_false(token_call_prepare(&tx, &metadata, &transfer));
        assert_false(transfer.enabled);
        assert_memory_equal(transfer.target, (uint8_t[64]) {0}, 64);
    }
}

static size_t transaction(uint8_t *raw) {
    zond_tx_t tx;
    token_metadata_t metadata;
    candidate(&tx, &metadata);
    size_t n = 0;
    raw[n++] = 2;
    raw[n++] = 0xf8;
    raw[n++] = 214;
    const uint8_t fields[] = {1, 0x80, 0x80, 1, 0x82, 0x52, 0x08, 0xb8, 64};
    memcpy(raw + n, fields, sizeof(fields));
    n += sizeof(fields);
    memcpy(raw + n, tx.to, 64);
    n += 64;
    raw[n++] = 0x80;
    raw[n++] = 0xb8;
    raw[n++] = 132;
    memcpy(raw + n, tx.data, 132);
    n += 132;
    const uint8_t tail[] = {0xc0, 0x83, 1, 0, 0, 0x80};
    memcpy(raw + n, tail, sizeof(tail));
    n += sizeof(tail);
    return n;
}

static void test_stream_every_boundary(void **state) {
    (void) state;
    uint8_t raw[256];
    size_t len = transaction(raw);
    for (size_t boundary = 1; boundary < len; boundary++) {
        tx_stream_t stream;
        zond_tx_t tx, reference;
        token_metadata_t metadata;
        token_call_t transfer;
        candidate(&reference, &metadata);
        tx_stream_init(&stream, &tx);
        assert_int_equal(tx_stream_feed(&stream, &tx, raw, boundary), TX_STREAM_PROCESSING);
        assert_int_equal(tx_stream_feed(&stream, &tx, raw + boundary, len - boundary),
                         TX_STREAM_FINISHED);
        assert_true(token_call_prepare(&tx, &metadata, &transfer));
        assert_memory_equal(tx.data, reference.data, 132);
    }
    tx_stream_t stream;
    zond_tx_t tx;
    tx_stream_init(&stream, &tx);
    for (size_t i = 0; i < len; i++) {
        assert_int_equal(tx_stream_feed(&stream, &tx, raw + i, 1),
                         i + 1 == len ? TX_STREAM_FINISHED : TX_STREAM_PROCESSING);
    }
}

static size_t metadata_payload(uint8_t *raw) {
    memset(raw, 0, 200);
    raw[0] = 1;
    raw[32] = 1;
    memset(raw + 33, 0x22, 64);
    raw[97] = 6;
    raw[98] = 3;
    memcpy(raw + 99, "TKN", 3);
    /* Structurally valid DER only: authentication belongs to the SDK handler. */
    const uint8_t der[] = {0x30, 6, 2, 1, 1, 2, 1, 1};
    memcpy(raw + 102, der, sizeof(der));
    return 110;
}

static void test_metadata_parser(void **state) {
    (void) state;
    uint8_t raw[200];
    size_t len = metadata_payload(raw), body;
    token_metadata_t metadata;
    assert_true(token_metadata_parse(raw, len, &metadata, &body));
    assert_int_equal(body, 102);
    assert_false(metadata.verified);
    assert_string_equal(metadata.symbol, "TKN");
    for (size_t cut = 0; cut < len; cut++) {
        assert_false(token_metadata_parse(raw, cut, &metadata, &body));
    }
    /* Only the exact native ticker is reserved; other 3-char symbols pass. */
    memcpy(raw + 99, "QRX", 3);
    assert_true(token_metadata_parse(raw, len, &metadata, &body));
    assert_string_equal(metadata.symbol, "QRX");
    for (int mutation = 0; mutation < 12; mutation++) {
        len = metadata_payload(raw);
        switch (mutation) {
            case 0:
                raw[0] = 2;
                break;
            case 1:
                raw[98] = 0;
                break;
            case 2:
                raw[98] = TOKEN_SYMBOL_MAX + 1;
                break;
            case 3:
                raw[97] = TOKEN_DECIMALS_MAX + 1;
                break;
            case 4:
                raw[99] = '\n';
                break;
            case 5:
                raw[100] = 0;
                break;
            case 6:
                raw[32] = 0;
                break;
            case 7:
                memset(raw + 33, 0, 64);
                break;
            case 8:
                len++;
                break;
            case 9:
                memcpy(raw + 99, "QRL", 3);
                break;
            case 10:
                memcpy(raw + 99, "qrl", 3);
                break;
            case 11:
                memcpy(raw + 99, "Qrl", 3);
                break;
        }
        assert_false(token_metadata_parse(raw, len, &metadata, &body));
        assert_false(metadata.verified);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_transfer_and_format),
        cmocka_unit_test(test_no_false_clear_signing),
        cmocka_unit_test(test_stream_every_boundary),
        cmocka_unit_test(test_metadata_parser),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
