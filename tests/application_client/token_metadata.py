"""QRL metadata wire format and an INSECURE TEST-ONLY issuer.

The scalar 1 below is public test data, never a production signing credential.
Production issuers sign the same domain-separated payload using their own key.
"""
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

DOMAIN = b"QRL-TOKEN-METADATA-V1"
TEST_CONTRACT = bytes.fromhex("22" * 64)
TEST_RECIPIENT = bytes.fromhex("11" * 64)


def metadata_body(chain_id: int, contract: bytes, symbol: str, decimals: int) -> bytes:
    ticker = symbol.encode("ascii")
    if not 0 < chain_id < 2**256 or len(contract) != 64 or not any(contract):
        raise ValueError("Expected a positive Chain ID and nonzero 64-byte contract")
    if not 0 <= decimals <= 77 or not 1 <= len(ticker) <= 12:
        raise ValueError("Unsupported symbol/decimals")
    if any(c not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for c in ticker):
        raise ValueError("Unsupported symbol characters")
    return b"\x01" + chain_id.to_bytes(32, "big") + contract + bytes([decimals, len(ticker)]) + ticker


def make_test_metadata(chain_id: int = 1, contract: bytes = TEST_CONTRACT,
                       symbol: str = "TKN", decimals: int = 6, *, scalar: int = 1) -> bytes:
    body = metadata_body(chain_id, contract, symbol, decimals)
    key = ECC.construct(curve="P-256", d=scalar)
    signature = DSS.new(key, "deterministic-rfc6979", encoding="der").sign(SHA256.new(DOMAIN + body))
    return body + signature


def transfer_calldata(amount: int, recipient: bytes = TEST_RECIPIENT) -> bytes:
    if len(recipient) != 64 or not 0 <= amount < 2**256:
        raise ValueError("Invalid transfer arguments")
    return bytes.fromhex("a9059cbb") + recipient + amount.to_bytes(64, "big")
