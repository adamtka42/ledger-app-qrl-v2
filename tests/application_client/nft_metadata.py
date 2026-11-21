"""QRL NFT collection metadata wire format, calldata builders and an INSECURE TEST-ONLY issuer.

The scalar 1 below is public test data, never a production signing credential.
Production issuers sign the same domain-separated payload using their own key.
"""
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

DOMAIN = b"QRL-NFT-METADATA-V1"
TEST_COLLECTION = bytes.fromhex("22" * 64)
TEST_OWNER = bytes.fromhex("44" * 64)
TEST_RECIPIENT = bytes.fromhex("11" * 64)
WORD = 64

_NAME_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_SEPARATORS = b" .-_"


def nft_metadata_body(chain_id: int, contract: bytes, name: str) -> bytes:
    text = name.encode("ascii")
    if not 0 < chain_id < 2**256 or len(contract) != 64 or not any(contract):
        raise ValueError("Expected a positive Chain ID and nonzero 64-byte contract")
    if not 1 <= len(text) <= 32 or text[0] not in _NAME_CHARS or text[-1] not in _NAME_CHARS:
        raise ValueError("Unsupported collection name")
    for previous, current in zip(text, text[1:]):
        if current not in _NAME_CHARS and (current not in _SEPARATORS or previous not in _NAME_CHARS):
            raise ValueError("Unsupported collection name characters")
    return b"\x01" + chain_id.to_bytes(32, "big") + contract + bytes([len(text)]) + text


def sign_test_body(body: bytes, *, scalar: int = 1, domain: bytes = DOMAIN) -> bytes:
    key = ECC.construct(curve="P-256", d=scalar)
    return DSS.new(key, "deterministic-rfc6979", encoding="der").sign(SHA256.new(domain + body))


def make_test_nft_metadata(chain_id: int = 1, contract: bytes = TEST_COLLECTION,
                           name: str = "Quantum Cats", *, scalar: int = 1) -> bytes:
    body = nft_metadata_body(chain_id, contract, name)
    return body + sign_test_body(body, scalar=scalar)


def _address(value: bytes) -> bytes:
    if len(value) != WORD:
        raise ValueError("Expected a 64-byte address")
    return value


def _uint(value: int) -> bytes:
    if not 0 <= value < 2**256:
        raise ValueError("Expected a uint256")
    return value.to_bytes(WORD, "big")


def _bytes_tail(head_words: int, data: bytes) -> tuple:
    """Offset word and tail of a trailing dynamic `bytes` argument."""
    padding = bytes(-len(data) % WORD)
    return _uint(head_words * WORD), _uint(len(data)) + data + padding


def transfer_from_calldata(token_id: int, owner: bytes = TEST_OWNER,
                           recipient: bytes = TEST_RECIPIENT, *, safe: bool = False) -> bytes:
    selector = "42842e0e" if safe else "23b872dd"
    return bytes.fromhex(selector) + _address(owner) + _address(recipient) + _uint(token_id)


def safe_transfer_data_calldata(token_id: int, owner: bytes = TEST_OWNER,
                                recipient: bytes = TEST_RECIPIENT, data: bytes = b"") -> bytes:
    offset, tail = _bytes_tail(4, data)
    return (bytes.fromhex("b88d4fde") + _address(owner) + _address(recipient) + _uint(token_id)
            + offset + tail)


def multi_transfer_calldata(token_id: int, quantity: int, owner: bytes = TEST_OWNER,
                            recipient: bytes = TEST_RECIPIENT, data: bytes = b"") -> bytes:
    offset, tail = _bytes_tail(5, data)
    return (bytes.fromhex("f242432a") + _address(owner) + _address(recipient) + _uint(token_id)
            + _uint(quantity) + offset + tail)


def nft_approve_calldata(token_id: int, spender: bytes = TEST_RECIPIENT) -> bytes:
    return bytes.fromhex("095ea7b3") + _address(spender) + _uint(token_id)


def approve_all_calldata(approved: bool, operator: bytes = TEST_RECIPIENT) -> bytes:
    return bytes.fromhex("a22cb465") + _address(operator) + _uint(int(approved))
