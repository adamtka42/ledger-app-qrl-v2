#!/usr/bin/env python3
"""Review a synthetic configureAccount(address,uint256,bool) call in Speculos.

Requires DEBUG=1 CONTRACT_DESCRIPTOR_TEST_KEY=1 for --test-key.
No node connection or blockchain broadcast is performed.
"""
import argparse
import json
from pathlib import Path
import sys
import urllib.request

from Crypto.Hash import keccak
from Crypto.PublicKey import ECC
from dilithium_py.ml_dsa import ML_DSA_87

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from application_client.contract_calls import descriptor_body, sign_descriptor, example_calldata
from application_client.transaction import build_transaction_preimage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5003")
    issuer = parser.add_mutually_exclusive_group(required=True)
    issuer.add_argument("--test-key", action="store_true", help="Public, INSECURE demonstration issuer")
    issuer.add_argument("--issuer-key", type=Path, help="Issuer private P-256 PEM (kept off-device)")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--disabled", action="store_true")
    parser.add_argument("--chain-id", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    key = ECC.construct(curve="P-256", d=1) if args.test_key else ECC.import_key(args.issuer_key.read_bytes())
    descriptor = sign_descriptor(descriptor_body(chain_id=args.chain_id), key)
    tx = build_transaction_preimage(chain_id=args.chain_id, nonce=0, gas_tip_cap=0,
                                     gas_fee_cap=2_550_000_000, gas=120_000, to=b"\x44" * 64,
                                     value=0, data=example_calldata(limit=args.limit, enabled=not args.disabled))
    print(f"Configure account: owner Q{'11' * 64}; limit {args.limit}; enabled {not args.disabled}")
    if args.dry_run:
        print(f"Built {len(descriptor)} descriptor bytes and {len(tx)} transaction bytes; no requests sent.")
        return

    def exchange(ins, p1=0, p2=0, data=b""):
        command = bytes([0xe0, ins, p1, p2, len(data)]) + data
        request = urllib.request.Request(args.url.rstrip("/") + "/apdu",
                                         data=json.dumps({"data": command.hex(), "tick_timeout": 0}).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=600) as response:
            reply = bytes.fromhex(json.load(response)["data"])
        status = reply[-2:].hex()
        if len(reply) < 2 or status != "9000":
            errors = {"6a88": "No contract descriptor issuer configured in this firmware",
                      "6982": "Contract descriptor signature authentication failed",
                      "6a89": "Transaction does not match the authenticated descriptor"}
            raise RuntimeError(errors.get(status, f"APDU rejected: {status}"))
        return reply[:-2]

    path = b"\x05" + b"".join(n.to_bytes(4, "big") for n in [0x8000002c, 0x800000ee, 0x80000000, 0, 0])
    exchange(5, data=path)
    public_key = b"".join(exchange(5, p2=i) for i in range(1, 12))[:2592]
    exchange(6, data=path)
    exchange(0x0b, data=descriptor)
    chunks = [tx[i:i + 255] for i in range(0, len(tx), 255)]
    for chunk in chunks[:-1]:
        exchange(6, p1=1, data=chunk)
    print("Review the operation, arguments, contract and fees on the emulator, then approve or reject.", flush=True)
    first = exchange(6, p1=2, data=chunks[-1])
    signature = first + b"".join(exchange(6, p1=2, p2=i) for i in range(1, 18))
    digest = keccak.new(digest_bits=256, data=tx).digest()
    if len(signature) != 4627 or not ML_DSA_87.verify(public_key, digest, signature,
                                                    ctx=bytes.fromhex("5a4f4e4401010000")):
        raise RuntimeError("ML-DSA signature verification failed")
    print("Verified ML-DSA-87 signature. Nothing was broadcast to a blockchain.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
