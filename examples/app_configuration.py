#!/usr/bin/env python3
"""Read app version and settings from Speculos without changing them."""
import argparse
import json
from pathlib import Path
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from application_client.app_configuration import AppConfiguration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5003")
    args = parser.parse_args()
    request = urllib.request.Request(
        args.url.rstrip("/") + "/apdu",
        data=json.dumps({"data": "e00e000000"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as reply:
        data = bytes.fromhex(json.load(reply)["data"])
    if len(data) < 2 or data[-2:] != b"\x90\x00":
        raise ValueError(f"GET_APP_CONFIGURATION rejected: {data[-2:].hex()}")
    config = AppConfiguration.from_bytes(data[:-2])
    print(f"App version: {'.'.join(map(str, config.version))}")
    print(f"Blind signing: {config.blind_signing_enabled}")
    print(f"Display nonce: {config.display_nonce}")
    print(f"Display transaction hash: {config.display_tx_hash}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(str(error))
