#!/usr/bin/env python3
"""Generate NFT metadata and calldata seeds without Crypto or a signing credential."""
from pathlib import Path
import sys
import zipfile

WORD = 64


def word(value):
    return value.to_bytes(WORD, "big")


def main():
    owner, recipient = b"\x33" * WORD, b"\x11" * WORD
    calls = {
        "transfer": bytes.fromhex("23b872dd") + owner + recipient + word(42),
        "safe_transfer": bytes.fromhex("42842e0e") + owner + recipient + word(42),
        "safe_transfer_data": bytes.fromhex("b88d4fde") + owner + recipient + word(42)
                              + word(4 * WORD) + word(0),
        "multi_transfer": bytes.fromhex("f242432a") + owner + recipient + word(42) + word(5)
                          + word(5 * WORD) + word(0),
        "approve": bytes.fromhex("095ea7b3") + recipient + word(42),
        "approve_all": bytes.fromhex("a22cb465") + recipient + word(1),
    }
    name = b"Quantum Cats"
    body = b"\x01" + (1).to_bytes(32, "big") + b"\x22" * 64 + bytes([len(name)]) + name
    # Valid DER structure only; the fuzzer tests parsing, never authentication.
    metadata = body + bytes.fromhex("3006020101020101")
    seed = bytes([len(metadata)]) + metadata  # the harness reads a one-byte payload length
    with zipfile.ZipFile(Path(sys.argv[1]), "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("metadata_only", seed)
        for label, calldata in calls.items():
            archive.writestr(label, seed + calldata)


if __name__ == "__main__":
    main()
