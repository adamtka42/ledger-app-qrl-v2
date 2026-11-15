"""Signed descriptors for a deliberately restricted static QRVM ABI profile."""
from enum import IntEnum
import re
from typing import Sequence, Tuple, Union

from Crypto.Hash import SHA256, keccak
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

DOMAIN = b"QRL-CONTRACT-DESCRIPTOR-V1"
TEST_CONTRACT = bytes.fromhex("44" * 64)
SELECTOR = keccak.new(digest_bits=256, data=b"configureAccount(address,uint256,bool)").digest()[:4]


class FieldKind(IntEnum):
    ADDRESS = 1
    UINT256 = 2
    BOOL = 3


FIELDS = ((FieldKind.ADDRESS, "Owner"),
          (FieldKind.UINT256, "Limit"), (FieldKind.BOOL, "Enabled"))


def _text(value: str, maximum: int) -> bytes:
    if not 1 <= len(value) <= maximum or re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]*", value) is None:
        raise ValueError("Descriptor text must start with a letter and use safe ASCII characters")
    if value.endswith(" "):
        raise ValueError("Trailing spaces are not supported")
    encoded = value.encode("ascii")
    return bytes([len(encoded)]) + encoded


def descriptor_body(chain_id: int = 1, contract: bytes = TEST_CONTRACT,
                    selector: bytes = SELECTOR, operation: str = "Configure account",
                    fields: Sequence[Tuple[int, str]] = FIELDS) -> bytes:
    if not 0 < chain_id < 2**256 or len(contract) != 64 or not any(contract) or len(selector) != 4:
        raise ValueError("Expected positive Chain ID, nonzero 64-byte contract and four-byte selector")
    if not 1 <= len(fields) <= 3:
        raise ValueError("Expected one to three ordered static fields")
    body = b"\x01" + chain_id.to_bytes(32, "big") + contract + selector + _text(operation, 24)
    body += bytes([len(fields)])
    for kind, label in fields:
        if kind not in (FieldKind.ADDRESS, FieldKind.UINT256, FieldKind.BOOL):
            raise ValueError("Unsupported field type")
        body += bytes([kind]) + _text(label, 12)
    return body


def sign_descriptor(body: bytes, key: ECC.EccKey) -> bytes:
    if not key.has_private() or key.curve != "NIST P-256":
        raise ValueError("Expected an issuer P-256 private key")
    return body + DSS.new(key, "deterministic-rfc6979", encoding="der").sign(SHA256.new(DOMAIN + body))


def make_test_descriptor(*, scalar: int = 1, **kwargs) -> bytes:
    """Use a publicly known INSECURE issuer; production credentials stay off-device."""
    return sign_descriptor(descriptor_body(**kwargs), ECC.construct(curve="P-256", d=scalar))


def encode_calldata(selector: bytes, fields: Sequence[Tuple[int, str]],
                    values: Sequence[Union[bytes, int]]) -> bytes:
    if len(selector) != 4 or not 1 <= len(fields) <= 3 or len(fields) != len(values):
        raise ValueError("Expected a selector and one value per descriptor field")
    words = []
    for (kind, _), value in zip(fields, values):
        if kind == FieldKind.ADDRESS:
            if not isinstance(value, bytes) or len(value) != 64:
                raise ValueError("Expected a 64-byte QRL address")
            word = value
        else:
            maximum = 1 if kind == FieldKind.BOOL else 2**256 - 1
            if kind not in (FieldKind.UINT256, FieldKind.BOOL) or not isinstance(value, int):
                raise ValueError("Expected an integer or boolean field")
            if not 0 <= value <= maximum:
                raise ValueError("Noncanonical numeric argument")
            word = value.to_bytes(64, "big")
        words.append(word)
    return selector + b"".join(words)


def example_calldata(owner: bytes = b"\x11" * 64, limit: int = 100, enabled: bool = True) -> bytes:
    return encode_calldata(SELECTOR, FIELDS, (owner, limit, int(enabled)))
