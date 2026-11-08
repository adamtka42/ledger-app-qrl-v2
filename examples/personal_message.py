#!/usr/bin/env python3
"""Review and sign QRL text in Speculos; never broadcasts anything."""
import argparse
import json
from pathlib import Path
import sys
import urllib.request

from dilithium_py.ml_dsa import ML_DSA_87
from ragger.bip import pack_derivation_path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from application_client.personal_message import PATH, MAX_MESSAGE_LEN, personal_message_hash
from application_client.transaction_helpers import SIGNING_CONTEXT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5003")
    parser.add_argument("--path", default=PATH)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--message", default=None)
    source.add_argument("--message-file", type=Path, help="Read exact bytes; preserve trailing newlines")
    parser.add_argument("--output", type=Path, help="Save public key, message and signature as JSON")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    message = (args.message_file.read_bytes() if args.message_file else
               (args.message if args.message is not None else "Login to example.app\nNonce: 123456").encode("utf-8"))
    if len(message) > MAX_MESSAGE_LEN or message.count(b"\n") > 32 or any(
            c != 10 and not 0x20 <= c <= 0x7e for c in message):
        raise ValueError("Supported text: up to 1024 bytes, printable ASCII and at most 32 LF newlines")
    digest = personal_message_hash(message)
    print(f"Message ({len(message)} bytes):\n{message.decode('ascii') if message else '<empty message>'}")
    print(f"QRL personal-sign hash: {digest.hex()}")
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
    exchange(8, data=path + len(message).to_bytes(4, "big"))
    chunks = [message[i:i + 255] for i in range(0, len(message), 255)] or [b""]
    for chunk in chunks[:-1]:
        exchange(8, p1=1, data=chunk)
    print("Review every message page and approve or reject on the emulator.", flush=True)
    signature = exchange(8, p1=2, data=chunks[-1])
    signature += b"".join(exchange(8, p1=2, p2=i) for i in range(1, 18))
    if len(signature) != 4627 or not ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT):
        raise RuntimeError("ML-DSA-87 signature verification failed")
    if args.output:
        args.output.write_text(json.dumps({"message_hex": message.hex(), "message_hash": digest.hex(),
            "public_key": public_key.hex(), "signature": signature.hex(),
            "context": SIGNING_CONTEXT.hex(), "descriptor": "010000"}, indent=2) + "\n")
    print("Verified ML-DSA-87 personal-message signature. Nothing was broadcast.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
