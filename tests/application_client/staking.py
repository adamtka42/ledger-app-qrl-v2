"""Canonical QRVM deposit ABI and fixed-vector SSZ, matching Zond DepositData."""
import hashlib

SELECTOR = bytes.fromhex("c1da06e2")
TEST_CONTRACT = b"\x42" * 64
MIN_SHOR = 2000 * 10**9


def merkle_root(data: bytes) -> bytes:
    nodes = [data[i:i + 32].ljust(32, b"\0") for i in range(0, len(data), 32)]
    if not nodes:
        return bytes(32)
    width = 1 << (len(nodes) - 1).bit_length()
    nodes += [bytes(32)] * (width - len(nodes))
    while len(nodes) > 1:
        nodes = [hashlib.sha256(nodes[i] + nodes[i + 1]).digest() for i in range(0, len(nodes), 2)]
    return nodes[0]


def deposit_root(public_key: bytes, withdrawal: bytes, shor: int, randao: bytes, signature: bytes) -> bytes:
    if (len(public_key), len(withdrawal), len(randao), len(signature)) != (2592, 64, 32, 4627):
        raise ValueError("Invalid Zond deposit field lengths")
    if not 0 <= shor < 2**64:
        raise ValueError("Amount must fit uint64 shor")
    roots = (merkle_root(public_key), merkle_root(withdrawal), shor.to_bytes(8, "little").ljust(32, b"\0"),
             randao, merkle_root(signature))
    return merkle_root(b"".join(roots))


def deposit_calldata(public_key: bytes, withdrawal: bytes, shor: int,
                     randao: bytes, signature: bytes) -> bytes:
    root = deposit_root(public_key, withdrawal, shor, randao, signature)
    arguments = (public_key, withdrawal, randao, signature)
    offset = 5 * 64
    head, tails = [], []
    for argument in arguments:
        head.append(offset.to_bytes(64, "big"))
        tail = len(argument).to_bytes(64, "big") + argument.ljust((len(argument) + 63) // 64 * 64, b"\0")
        tails.append(tail)
        offset += len(tail)
    return SELECTOR + b"".join(head) + root.ljust(64, b"\0") + b"".join(tails)


def synthetic_deposit(shor: int = MIN_SHOR, withdrawal: bytes = b"\x11" * 64) -> bytes:
    """Parser/UI data only: the synthetic key/signature cannot register a validator."""
    return deposit_calldata(bytes(i % 256 for i in range(2592)), withdrawal, shor,
                            b"\x33" * 32, bytes((i + 17) % 256 for i in range(4627)))
