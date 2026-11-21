#!/usr/bin/env python3
"""Sign a QRL token transfer or approval in Speculos; never connects to a node.

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
from application_client.token_metadata import DOMAIN, metadata_body, transfer_calldata, approval_calldata

from application_client.transaction import build_transaction_preimage


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
    parser.add_argument("--operation", choices=("transfer", "approve"), default="transfer")
    parser.add_argument("--recipient", help="Token recipient, for transfer only")
    parser.add_argument("--spender", help="Authorized spender, for approve only")
    parser.add_argument("--symbol", default="TKN")
    parser.add_argument("--decimals", type=int, default=6)
    limit = parser.add_mutually_exclusive_group()
    limit.add_argument("--units", type=int, default=10_000_000, help="Raw units; approve with 0 to revoke")
    limit.add_argument("--unlimited", action="store_true", help="Approve the maximum uint256 allowance")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.operation == "transfer" and (args.spender is not None or args.unlimited):
        parser.error("--spender and --unlimited require --operation approve")
    if args.operation == "approve" and args.recipient is not None:
        parser.error("Use --spender for approvals")
    target_text = (args.spender if args.operation == "approve" else args.recipient) or "Q" + "11" * 64
    contract, target = address(args.contract), address(target_text)
    units = 2**256 - 1 if args.unlimited else args.units
    calldata = (approval_calldata if args.operation == "approve" else transfer_calldata)(units, target)
    body = metadata_body(args.chain_id, contract, args.symbol, args.decimals)
    key = ECC.construct(curve="P-256", d=1) if args.test_key else ECC.import_key(args.issuer_key.read_bytes())
    signature = DSS.new(key, "deterministic-rfc6979", encoding="der").sign(SHA256.new(DOMAIN + body))
    metadata = body + signature
    tx = build_transaction_preimage(chain_id=args.chain_id, nonce=args.nonce, gas_tip_cap=0,
                                     gas_fee_cap=2_550_000_000, gas=120_000, to=contract,
                                     value=0, data=calldata)
    print(f"Operation: {args.operation}; token: {args.symbol}; raw units: {units}; decimals: {args.decimals}")
    target_label = "Spender" if args.operation == "approve" else "Recipient"
    print(f"Contract: {args.contract}\n{target_label}: {target_text}\nChain ID: {args.chain_id}")
    if args.operation == "approve" and units == 2**256 - 1:
        print("Unlimited approval: the spender may spend all current and future tokens until revoked.")
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
            if status == "6a88":
                raise RuntimeError("No token metadata issuer configured in the app. Check the firmware build flags.")
            if status == "6982":
                raise RuntimeError("Token metadata authentication failed. Check the issuer key and signature.")
            raise RuntimeError(f"APDU rejected: {status}. Check app build and user decision.")
        return reply[:-2]

    path = b"\x05" + b"".join(x.to_bytes(4, "big") for x in [0x8000002c, 0x800000ee, 0x80000000, 0, 0])
    exchange(5, data=path)
    public_key = b"".join(exchange(5, p2=i) for i in range(1, 12))[:2592]
    exchange(6, data=path)
    exchange(0x0a, data=metadata)
    chunks = [tx[i:i+255] for i in range(0, len(tx), 255)]
    for chunk in chunks[:-1]:
        exchange(6, p1=1, data=chunk)
    print(f"Review and approve/reject the token {args.operation} on the emulator.", flush=True)
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
