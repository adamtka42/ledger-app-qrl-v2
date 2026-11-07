#!/usr/bin/env python3
"""Sign a QRL token transfer in Speculos; never connects to a blockchain node.

Run with the Python environment from tests/requirements.txt. The --test-key
option requires an app built with DEBUG=1 TOKEN_METADATA_TEST_KEY=1.
"""
import argparse
import json
from pathlib import Path
import sys
import urllib.request

from Crypto.Hash import SHA256, keccak
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from dilithium_py.ml_dsa import ML_DSA_87

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from application_client.token_metadata import DOMAIN, metadata_body, transfer_calldata


def rlp(item):
    if isinstance(item, int):
        item = item.to_bytes((item.bit_length() + 7) // 8, "big")
    if isinstance(item, list):
        payload = b"".join(rlp(x) for x in item)
        base = 0xc0
    else:
        payload, base = bytes(item), 0x80
        if len(payload) == 1 and payload[0] < 0x80:
            return payload
    if len(payload) < 56:
        return bytes([base + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(length)]) + length + payload


def address(text):
    raw = bytes.fromhex(text[1:] if text.startswith("Q") else text.removeprefix("0x"))
    if len(raw) != 64:
        raise ValueError("Expected a 64-byte QRL address")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5001")
    issuer = parser.add_mutually_exclusive_group(required=True)
    issuer.add_argument("--test-key", action="store_true", help="Publicly known insecure test issuer")
    issuer.add_argument("--issuer-key", type=Path, help="Issuer P-256 private PEM (kept off-device)")
    parser.add_argument("--chain-id", type=int, default=1)
    parser.add_argument("--nonce", type=int, default=0)
    parser.add_argument("--contract", default="Q" + "22" * 64)
    parser.add_argument("--recipient", default="Q" + "11" * 64)
    parser.add_argument("--symbol", default="TKN")
    parser.add_argument("--decimals", type=int, default=6)
    parser.add_argument("--units", type=int, default=10_000_000, help="Raw token units, before decimals")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    contract, recipient = address(args.contract), address(args.recipient)
    body = metadata_body(args.chain_id, contract, args.symbol, args.decimals)
    key = ECC.construct(curve="P-256", d=1) if args.test_key else ECC.import_key(args.issuer_key.read_bytes())
    signature = DSS.new(key, "deterministic-rfc6979", encoding="der").sign(SHA256.new(DOMAIN + body))
    metadata = body + signature
    tx = b"\x02" + rlp([args.chain_id, args.nonce, 0, 2_550_000_000, 120_000,
                          contract, 0, transfer_calldata(args.units, recipient), [], b"\x01\0\0", b""])
    print(f"Token: {args.symbol}; raw units: {args.units}; decimals: {args.decimals}")
    print(f"Contract: {args.contract}\nRecipient: {args.recipient}\nChain ID: {args.chain_id}")
    if args.dry_run:
        print(f"Built {len(metadata)} metadata bytes and {len(tx)} transaction bytes; no requests sent.")
        return

    def exchange(ins, p1=0, p2=0, data=b""):
        command = bytes([0xe0, ins, p1, p2, len(data)]) + data
        request = urllib.request.Request(args.url.rstrip("/") + "/apdu",
                                         data=json.dumps({"data": command.hex(), "tick_timeout": 0}).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=600) as response:
            reply = bytes.fromhex(json.load(response)["data"])
        if len(reply) < 2 or reply[-2:] != b"\x90\0":
            status = reply[-2:].hex()
            raise RuntimeError(f"APDU rejected: {status}. Check app build, issuer key, and user decision.")
        return reply[:-2]

    path = b"\x05" + b"".join(x.to_bytes(4, "big") for x in [0x8000002c, 0x800000ee, 0x80000000, 0, 0])
    exchange(5, data=path)
    public_key = b"".join(exchange(5, p2=i) for i in range(1, 12))[:2592]
    exchange(6, data=path)
    exchange(0x0a, data=metadata)
    chunks = [tx[i:i+255] for i in range(0, len(tx), 255)]
    for chunk in chunks[:-1]:
        exchange(6, p1=1, data=chunk)
    print("Review and approve/reject the token transfer on the emulator.", flush=True)
    first = exchange(6, p1=2, data=chunks[-1])
    signature = first + b"".join(exchange(6, p1=2, p2=i) for i in range(1, 18))
    digest = keccak.new(digest_bits=256, data=tx).digest()
    if len(signature) != 4627 or not ML_DSA_87.verify(public_key, digest, signature, ctx=bytes.fromhex("5a4f4e4401010000")):
        raise RuntimeError("ML-DSA signature verification failed")
    print("Verified 4627-byte ML-DSA-87 signature. Nothing was broadcast to a blockchain.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
