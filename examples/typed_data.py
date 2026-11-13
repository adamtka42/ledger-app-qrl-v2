#!/usr/bin/env python3
"""Review and sign QRL Typed Structured Data v1 in Speculos, without broadcasting."""
import argparse
import json
from pathlib import Path
import sys
import urllib.request

from dilithium_py.ml_dsa import ML_DSA_87
from ragger.bip import pack_derivation_path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from application_client.transaction_helpers import SIGNING_CONTEXT
from application_client.typed_data import PATH, encode_typed_data, permission_example, typed_data_hash, wide_example


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5003")
    parser.add_argument("--path", default=PATH)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--json-file", type=Path, help="QRL types, primaryType, domain and message")
    source.add_argument("--sample", choices=("permission", "wide"), default="permission")
    parser.add_argument("--print-example", action="store_true", help="Print the chosen JSON without sending")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", type=Path, help="Save public signature verification data")
    args = parser.parse_args()
    document = (json.loads(args.json_file.read_text()) if args.json_file else
                wide_example() if args.sample == "wide" else permission_example())
    payload = encode_typed_data(document)
    digest = typed_data_hash(document)
    if args.print_example:
        print(json.dumps(document, indent=2))
        return
    print(json.dumps(document, indent=2))
    print(f"QRL VM64 typed-data hash: {digest.hex()} ({len(payload)} payload bytes)")
    if args.dry_run:
        return

    def exchange(ins, p1=0, p2=0, data=b""):
        apdu = bytes([0xe0, ins, p1, p2, len(data)]) + data
        request = urllib.request.Request(args.url.rstrip("/") + "/apdu",
            data=json.dumps({"data": apdu.hex(), "tick_timeout": 0}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=600) as response:
            reply = bytes.fromhex(json.load(response)["data"])
        if len(reply) < 2 or reply[-2:] != b"\x90\0":
            raise RuntimeError(f"APDU rejected: {reply[-2:].hex()}")
        return reply[:-2]

    path = pack_derivation_path(args.path)
    exchange(5, data=path)
    public_key = b"".join(exchange(5, p2=i) for i in range(1, 12))[:2592]
    exchange(0x0c, data=path + len(payload).to_bytes(4, "big"))
    chunks = [payload[i:i + 255] for i in range(0, len(payload), 255)]
    for chunk in chunks[:-1]:
        exchange(0x0c, p1=1, data=chunk)
    print("Review every domain/message field on the emulator, then approve or reject.", flush=True)
    signature = exchange(0x0c, p1=2, data=chunks[-1])
    signature += b"".join(exchange(0x0c, p1=2, p2=i) for i in range(1, 18))
    if len(signature) != 4627 or not ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT):
        raise RuntimeError("ML-DSA-87 typed-data signature verification failed")
    if args.output:
        args.output.write_text(json.dumps({"typed_data": document, "message_hash": digest.hex(),
            "public_key": public_key.hex(), "signature": signature.hex(),
            "context": SIGNING_CONTEXT.hex(), "descriptor": "010000"}, indent=2) + "\n")
    print("Verified ML-DSA-87 typed-data signature. Nothing was broadcast.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
