#!/usr/bin/env python3
"""Generate parser seeds without Crypto or a trusted signing credential."""
from pathlib import Path
import sys
import zipfile


def main():
    with zipfile.ZipFile(Path(sys.argv[1]), "w", zipfile.ZIP_DEFLATED) as archive:
        for count in (1, 2, 3):
            for width in (1, 12):
                operation = b"Configure account"
                prefix = b"\x01" + (1).to_bytes(32, "big") + b"\x44" * 64 + b"\x12" * 4
                body = prefix + bytes([len(operation)]) + operation + bytes([count])
                for kind in range(1, count + 1):
                    body += bytes([kind, width]) + b"A" * width
                # Valid DER structure only; the fuzzer tests parsing, never authentication.
                seed = body + bytes.fromhex("3006020101020101")
                archive.writestr(f"fields_{count}_label_{width}", seed)


if __name__ == "__main__":
    main()
