"""Host-only regression tests for the shared transaction builder (no emulator)."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from application_client.transaction import (
    build_transaction_preimage, rlp_encode_bytes, rlp_encode_uint, rlp_length_prefix,
)


class TransactionBuilderTests(unittest.TestCase):
    def test_native_reference_preimage(self):
        # Existing device-test vector, before the builder was extracted.
        expected = bytes.fromhex(
            "02f86201038477359400850ba43b74008261a8b840"
            "b94f5374fce5edbc8e2a8697c15331677e6ebf0b" + "aa" * 44
            + "88016345785d8a000080c08301000080"
        )
        actual = build_transaction_preimage(
            chain_id=1, nonce=3, gas_tip_cap=2_000_000_000, gas_fee_cap=50_000_000_000,
            gas=25_000, to=bytes.fromhex("b94f5374fce5edbc8e2a8697c15331677e6ebf0b" + "aa" * 44),
            value=100_000_000_000_000_000,
        )
        self.assertEqual(actual, expected)

    def test_token_reference_preimage(self):
        # Existing token-test vector, before the builder was extracted.
        calldata = bytes.fromhex("a9059cbb") + b"\x11" * 64 + (10_000_000).to_bytes(64, "big")
        expected = bytes.fromhex(
            "02f8db0103808497fde980830186a0b840" + "22" * 64
            + "80b884a9059cbb" + "11" * 64 + "00" * 60 + "00989680c08301000080"
        )
        actual = build_transaction_preimage(
            chain_id=1, nonce=3, gas_tip_cap=0, gas_fee_cap=2_550_000_000,
            gas=100_000, to=b"\x22" * 64, value=0, data=calldata,
        )
        self.assertEqual(actual, expected)

    def test_canonical_integer_encoding(self):
        for value, expected in ((0, "80"), (1, "01"), (127, "7f"), (128, "8180"),
                                (255, "81ff"), (256, "820100")):
            with self.subTest(value=value):
                self.assertEqual(rlp_encode_uint(value), bytes.fromhex(expected))
        with self.assertRaises(OverflowError):
            rlp_encode_uint(-1)

    def test_string_length_boundaries(self):
        for length, prefix in ((0, "80"), (1, "8180"), (55, "b7"), (56, "b838"),
                               (255, "b8ff"), (256, "b90100")):
            with self.subTest(length=length):
                value = b"\x80" * length
                expected = bytes.fromhex(prefix) if length == 1 else bytes.fromhex(prefix) + value
                self.assertEqual(rlp_encode_bytes(value), expected)
        self.assertEqual(rlp_encode_bytes(b"\x00"), b"\x00")
        self.assertEqual(rlp_encode_bytes(b"\x7f"), b"\x7f")

    def test_list_length_boundaries(self):
        for length, expected in ((0, "c0"), (55, "f7"), (56, "f838"), (256, "f90100")):
            with self.subTest(length=length):
                self.assertEqual(rlp_length_prefix(0xc0, length), bytes.fromhex(expected))


if __name__ == "__main__":
    unittest.main()
