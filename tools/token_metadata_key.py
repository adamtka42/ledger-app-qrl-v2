#!/usr/bin/env python3
"""Validate an uncompressed P-256 issuer key and emit C initializer bytes."""

import re
import sys


P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def decode_public_key(value):
    if re.fullmatch(r"04[0-9a-fA-F]{128}", value) is None:
        raise ValueError("expected 130 hex characters starting with 04")
    key = bytes.fromhex(value)
    x = int.from_bytes(key[1:33], "big")
    y = int.from_bytes(key[33:], "big")
    # SEC 2 P-256: y^2 = x^3 - 3*x + b over F_p. Its cofactor is 1,
    # so a finite on-curve point needs no additional subgroup check.
    if x >= P256_P or y >= P256_P or (y * y - (x * x * x - 3 * x + P256_B)) % P256_P:
        raise ValueError("coordinates must form a valid P-256 point")
    return key


def main():
    if len(sys.argv) != 2:
        raise ValueError("expected one uncompressed P-256 public key")
    key = decode_public_key(sys.argv[1])
    print(",".join(f"0x{byte:02x}" for byte in key))


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        sys.exit(f"Invalid token metadata issuer key: {exc}")
