"""Bounded QRL Typed Structured Data v1 (go-qrl VM64), not Ethereum ABI words."""
import re

from Crypto.Hash import keccak

DOMAIN_TYPE = "QRLTypedDataDomain"
MAX_PAYLOAD = 4096
MAX_TYPES = 8
MAX_FIELDS = 32
MAX_DEPTH = 4
MAX_ARRAY = 8
MAX_VALUE = 256
PATH = "m/44'/238'/0'/0/0"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,23}\Z")
_INTEGER = re.compile(r"(u?int)([1-9][0-9]*)?\Z")
_FIXED = re.compile(r"bytes([1-9][0-9]*)\Z")
_DOMAIN_FIELDS = [("name", "string"), ("version", "string"), ("chainId", "uint256"),
                  ("verifyingContract", "address"), ("salt", "bytes32")]


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def _primitive(type_name):
    if type_name in ("address", "bool", "string", "bytes"):
        return type_name, None
    match = _INTEGER.fullmatch(type_name)
    if match:
        width = int(match[2] or 512)
        if not 8 <= width <= 512 or width % 8:
            raise ValueError("Integer width must be a multiple of 8 up to 512")
        return match[1], width
    match = _FIXED.fullmatch(type_name)
    if match:
        width = int(match[1])
        if not 1 <= width <= 64:
            raise ValueError("Fixed bytes width must be 1..64")
        return "fixed", width
    return None, None


def _binary(value):
    if isinstance(value, str):
        if not value.startswith("0x"):
            raise ValueError("Bytes must have an explicit 0x prefix")
        return bytes.fromhex(value[2:])
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise ValueError("Expected hex bytes")


def _integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("Expected an integer or decimal/hex integer string")
    if isinstance(value, str):
        return int(value, 16 if value.removeprefix("-").startswith("0x") else 10)
    return value


def _bytes_word(kind, width, value):
    if kind == "string":
        if not isinstance(value, str):
            raise ValueError("Expected text")
        raw = value.encode("ascii")
        if len(raw) > MAX_VALUE or raw.count(b"\n") > 16 or any(c != 10 and not 32 <= c <= 126 for c in raw):
            raise ValueError("Text must be printable ASCII/LF, up to 256 bytes and 16 LF")
        return keccak256(raw).ljust(64, b"\0")
    raw = _binary(value)
    if kind == "bytes":
        if len(raw) > MAX_VALUE:
            raise ValueError("Byte value exceeds 256 bytes")
        return keccak256(raw).ljust(64, b"\0")
    if len(raw) != width:
        raise ValueError("Wrong fixed bytes length")
    return raw.ljust(64, b"\0")


def _primitive_word(type_name, value):
    kind, width = _primitive(type_name)
    if kind == "address":
        if isinstance(value, str) and value.startswith("Q"):
            value = "0x" + value[1:]
        raw = _binary(value)
        if len(raw) != 64:
            raise ValueError("Expected a 64-byte QRL address")
        return raw
    if kind == "bool":
        if not isinstance(value, bool):
            raise ValueError("Expected bool")
        return int(value).to_bytes(64, "big")
    if kind in ("string", "bytes", "fixed"):
        return _bytes_word(kind, width, value)
    if kind in ("int", "uint"):
        number = _integer(value)
        low, high = (0, 2**width) if kind == "uint" else (-2**(width - 1), 2**(width - 1))
        if not low <= number < high:
            raise ValueError("Integer out of declared range")
        return (number % 2**512).to_bytes(64, "big")
    raise ValueError(f"Unsupported type: {type_name}")


def _value_word(type_name, value, types, depth):
    if depth > MAX_DEPTH:
        raise ValueError("Typed data nesting is too deep")
    if type_name.endswith("[]"):
        if not isinstance(value, list) or len(value) > MAX_ARRAY:
            raise ValueError("Expected at most 8 array elements")
        return keccak256(b"".join(_value_word(type_name[:-2], v, types, depth) for v in value)).ljust(64, b"\0")
    if type_name in types:
        return _struct_hash(type_name, value, types, depth + 1).ljust(64, b"\0")
    return _primitive_word(type_name, value)


def encode_type(type_name, types):
    found = set()

    def visit(name, active, depth):
        if depth > MAX_DEPTH or name in active:
            raise ValueError("Cyclic/deep type graph")
        if name in found:
            return
        found.add(name)
        for field in types[name]:
            dependency = field["type"].removesuffix("[]")
            if dependency in types:
                visit(dependency, active | {name}, depth + 1)

    visit(type_name, set(), 1)
    order = [type_name] + sorted(found - {type_name})
    return "".join(name + "(" + ",".join(f["type"] + " " + f["name"] for f in types[name]) + ")" for name in order)


def _struct_hash(type_name, value, types, depth=1):
    if not isinstance(value, dict) or set(value) != {f["name"] for f in types[type_name]}:
        raise ValueError("Values must exactly match the schema fields")
    encoded = keccak256(encode_type(type_name, types).encode("ascii")).ljust(64, b"\0")
    encoded += b"".join(_value_word(f["type"], value[f["name"]], types, depth) for f in types[type_name])
    return keccak256(encoded)


def typed_data_hash(document):
    """Independent VM64 hash calculation; full schemas and values are required."""
    return keccak256(b"\x19\x01" + _struct_hash(DOMAIN_TYPE, document["domain"], document["types"]) +
                     _struct_hash(document["primaryType"], document["message"], document["types"]))


def _name_bytes(name):
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError("Identifiers must be ASCII, up to 24 characters")
    raw = name.encode("ascii")
    return bytes([len(raw)]) + raw


def _encode_value(type_name, value, types, depth):
    if depth > MAX_DEPTH:
        raise ValueError("Typed data nesting is too deep")
    if type_name.endswith("[]"):
        if not isinstance(value, list) or len(value) > MAX_ARRAY:
            raise ValueError("Expected at most 8 array elements")
        return bytes([len(value)]) + b"".join(_encode_value(type_name[:-2], v, types, depth) for v in value)
    if type_name in types:
        if not isinstance(value, dict) or set(value) != {f["name"] for f in types[type_name]}:
            raise ValueError("Values must exactly match the schema fields")
        return b"".join(_encode_value(f["type"], value[f["name"]], types, depth + 1) for f in types[type_name])
    word = _value_word(type_name, value, types, depth)
    kind, width = _primitive(type_name)
    if kind in ("string", "bytes"):
        raw = value.encode("ascii") if kind == "string" else _binary(value)
        return len(raw).to_bytes(2, "big") + raw
    if kind == "bool":
        return word[-1:]
    if kind == "fixed":
        return word[:width]
    return word


def encode_typed_data(document):
    """Encode schema + ordered values, without supplying any precomputed hashes."""
    if set(document) != {"types", "primaryType", "domain", "message"}:
        raise ValueError("Expected types, primaryType, domain and message")
    types = document["types"]
    if not isinstance(types, dict) or not 2 <= len(types) <= MAX_TYPES:
        raise ValueError("Expected 2..8 types")
    names = list(types)
    primary = document["primaryType"]
    if DOMAIN_TYPE not in types or primary not in types or primary == DOMAIN_TYPE:
        raise ValueError("Expected QRLTypedDataDomain and a separate primary type")
    if sum(len(fields) for fields in types.values()) > MAX_FIELDS:
        raise ValueError("Too many schema fields")
    domain_fields = [(f["name"], f["type"]) for f in types[DOMAIN_TYPE]]
    if not domain_fields or domain_fields != [f for f in _DOMAIN_FIELDS if f in domain_fields]:
        raise ValueError("Domain fields must use the standard names/types/order")
    if any(document["domain"].get(key) == "" for key in ("name", "version")):
        raise ValueError("Empty domain name/version is not canonical in go-qrl")

    encoded = bytes([1, len(names), names.index(primary)])
    for name, fields in types.items():
        if _primitive(name)[0] is not None:
            raise ValueError("A struct name cannot shadow a primitive")
        encoded += _name_bytes(name) + bytes([len(fields)])
        seen = set()
        for field in fields:
            if set(field) != {"name", "type"} or field["name"] in seen:
                raise ValueError("Invalid or duplicate schema field")
            seen.add(field["name"])
            encoded += _name_bytes(field["name"])
            type_name = field["type"]
            base = type_name.removesuffix("[]")
            _name_bytes(base)
            if base not in types and _primitive(base)[0] is None:
                raise ValueError("Unknown field type")
            raw = type_name.encode("ascii")
            encoded += bytes([len(raw)]) + raw
        encode_type(name, types)

    encoded += _encode_value(DOMAIN_TYPE, document["domain"], types, 0)
    encoded += _encode_value(primary, document["message"], types, 0)
    if len(encoded) > MAX_PAYLOAD:
        raise ValueError("Typed-data payload exceeds 4096 bytes")
    return encoded


def permission_example():
    return {
        "types": {
            DOMAIN_TYPE: [{"name": name, "type": type_name} for name, type_name in _DOMAIN_FIELDS[:4]],
            "SpendingPermission": [
                {"name": "spender", "type": "address"},
                {"name": "limit", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "validUntil", "type": "uint256"},
            ],
        },
        "primaryType": "SpendingPermission",
        "domain": {"name": "Example DEX", "version": "1", "chainId": "1", "verifyingContract": "Q" + "22" * 64},
        "message": {"spender": "Q" + "11" * 64, "limit": "25000000", "nonce": "1", "validUntil": "2000000000"},
    }


def wide_example():
    return {
        "types": {DOMAIN_TYPE: [{"name": "name", "type": "string"}],
                  "WideValues": [{"name": "amount", "type": "uint512"}, {"name": "payload", "type": "bytes64"}]},
        "primaryType": "WideValues", "domain": {"name": "QRL VM64 Golden"},
        "message": {"amount": "0x" + "fedcba9876543210" * 8, "payload": "0x" + "0123456789abcdef" * 8},
    }
