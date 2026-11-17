#!/usr/bin/env python3
"""Review a Zond staking deposit in Speculos; never broadcast to a node.

Use --synthetic for UI testing with DEBUG=1 STAKING_DEPOSIT_TEST_PROFILE=1,
or --deposit-json for an export from Zond's staking-deposit-cli. The app must
pin the same Chain ID and contract. Ledger signs the funding transaction;
validator registration signature verification belongs to consensus.
"""
import argparse
import json
from pathlib import Path
import sys
import urllib.request

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from application_client.staking import deposit_calldata, deposit_root, synthetic_deposit, merkle_root, MIN_SHOR
from application_client.transaction import build_transaction_preimage


def decode(text):
    return bytes.fromhex(text.removeprefix("0x").removeprefix("Q"))


def deposit_data(args):
    if args.synthetic:
        shor = MIN_SHOR
        data = synthetic_deposit(shor)
        print("SYNTHETIC key/signature: UI test only; these data cannot register a validator.")
    else:
        records = json.loads(args.deposit_json.read_text())
        if isinstance(records, list):
            if not 0 <= args.index < len(records):
                raise ValueError("Deposit index outside the JSON array")
            record = records[args.index]
        else:
            if args.index != 0:
                raise ValueError("A single deposit object requires index 0")
            record = records
        pk, withdrawal = decode(record["pubkey"]), decode(record["withdrawal_recipient"])
        randao, signature = decode(record["randao_commitment"]), decode(record["signature"])
        shor = record["amount"]
        if not isinstance(shor, int) or not MIN_SHOR <= shor < 2**64:
            raise ValueError("Amount must be uint64 shor, at least 2000 QRL")
        root = deposit_root(pk, withdrawal, shor, randao, signature)
        if root != decode(record["deposit_data_root"]):
            raise ValueError("JSON deposit_data_root does not match its fields")
        data = deposit_calldata(pk, withdrawal, shor, randao, signature)
    print(f"Amount: {shor} shor; native funding value: {shor * 10**9} planck")
    print(f"Validator key root: {merkle_root(data[388:2980]).hex()}")
    print(f"Withdraw to: Q{data[3076:3140].hex()}")
    print(f"RANDAO commitment: {data[3204:3236].hex()}")
    print(f"Deposit data root: {data[260:292].hex()}")
    return data, shor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--synthetic", action="store_true")
    source.add_argument("--deposit-json", type=Path)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--url", default="http://127.0.0.1:5003")
    parser.add_argument("--chain-id", type=int, default=1)
    parser.add_argument("--contract", default="Q" + "42" * 64)
    parser.add_argument("--nonce", type=int, default=0)
    parser.add_argument("--gas-limit", type=int, default=500000)
    parser.add_argument("--max-fee-per-gas", type=int, default=2550000000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    data, shor = deposit_data(args)
    contract = decode(args.contract)
    if len(contract) != 64 or not any(contract) or not 0 < args.chain_id < 2**256:
        raise ValueError("Expected nonzero 64-byte contract and positive uint256 Chain ID")
    tx = build_transaction_preimage(chain_id=args.chain_id, nonce=args.nonce, gas_tip_cap=0,
                                     gas_fee_cap=args.max_fee_per_gas, gas=args.gas_limit, to=contract,
                                     value=shor * 10**9, data=data)
    print(f"Chain ID: {args.chain_id}; deposit contract: {args.contract}")
    if args.dry_run:
        print(f"Built {len(data)} calldata bytes and {len(tx)} transaction bytes; no requests sent.")
        return

    def exchange(ins, p1=0, p2=0, payload=b""):
        request = urllib.request.Request(args.url.rstrip("/") + "/apdu",
                                         data=json.dumps({"data": (bytes([0xe0, ins, p1, p2, len(payload)]) +
                                                                   payload).hex(), "tick_timeout": 0}).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=600) as response:
            reply = bytes.fromhex(json.load(response)["data"])
        status = reply[-2:].hex()
        if len(reply) < 2 or status != "9000":
            message = {"6a8a": "Recognized deposit rejected: ABI, amount, root, or access list mismatch",
                       "6985": "Request denied; check the pinned profile and user decision"}
            raise RuntimeError(message.get(status, f"APDU rejected: {status}"))
        return reply[:-2]

    path = b"\x05" + b"".join(n.to_bytes(4, "big") for n in (0x8000002c, 0x800000ee, 0x80000000, 0, 0))
    exchange(5, payload=path)
    public_key = b"".join(exchange(5, p2=i) for i in range(1, 12))[:2592]
    exchange(6, payload=path)
    chunks = [tx[i:i + 255] for i in range(0, len(tx), 255)]
    for chunk in chunks[:-1]:
        exchange(6, p1=1, payload=chunk)
    print("Review the staking deposit on the emulator, then approve or reject.", flush=True)
    signature = exchange(6, p1=2, payload=chunks[-1])
    signature += b"".join(exchange(6, p1=2, p2=i) for i in range(1, 18))
    if len(signature) != 4627 or not ML_DSA_87.verify(public_key, keccak.new(digest_bits=256, data=tx).digest(),
                                                    signature, ctx=bytes.fromhex("5a4f4e4401010000")):
        raise RuntimeError("ML-DSA-87 funding signature verification failed")
    print("Funding signature verified. Nothing was broadcast; no validator was activated.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        sys.exit(str(error))
