#!/usr/bin/env python3
"""Decode an explicitly pinned Chain ID and 64-byte staking contract."""
import re
import sys


def profile(chain, contract):
    if re.fullmatch(r"[0-9]+", chain) is None or not 0 < int(chain) < 2**256:
        raise ValueError("Chain ID must be a positive decimal uint256")
    if re.fullmatch(r"[0-9a-fA-F]{128}", contract) is None or not any(bytes.fromhex(contract)):
        raise ValueError("Contract must be 128 hex digits for a nonzero 64-byte address")
    return int(chain).to_bytes(32, "big") + bytes.fromhex(contract)


if __name__ == "__main__":
    try:
        print(",".join(f"0x{x:02x}" for x in profile(*sys.argv[1:])))
    except (ValueError, TypeError) as error:
        sys.exit(f"Invalid staking profile: {error}")
