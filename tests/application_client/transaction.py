"""Shared canonical RLP encoding and QRL type-2 signing preimages.

Access lists are supplied as already encoded RLP lists so device tests can also
exercise malformed input. This builder does not validate transaction semantics.
"""


def rlp_length_prefix(base: int, length: int) -> bytes:
    if length < 56:
        return bytes([base + length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(encoded)]) + encoded


def rlp_encode_bytes(value: bytes) -> bytes:
    if len(value) == 1 and value[0] < 0x80:
        return value
    return rlp_length_prefix(0x80, len(value)) + value


def rlp_encode_uint(value: int) -> bytes:
    return rlp_encode_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def build_transaction_preimage(*, chain_id: int, nonce: int, gas_tip_cap: int,
                               gas_fee_cap: int, gas: int, to: bytes, value: int,
                               data: bytes = b"", access_list: bytes = b"\xc0",
                               descriptor: bytes = b"\x01\x00\x00", extra_params: bytes = b"") -> bytes:
    fields = (
        rlp_encode_uint(chain_id),
        rlp_encode_uint(nonce),
        rlp_encode_uint(gas_tip_cap),
        rlp_encode_uint(gas_fee_cap),
        rlp_encode_uint(gas),
        rlp_encode_bytes(to),
        rlp_encode_uint(value),
        rlp_encode_bytes(data),
        access_list,
        rlp_encode_bytes(descriptor),
        rlp_encode_bytes(extra_params),
    )
    payload = b"".join(fields)
    return b"\x02" + rlp_length_prefix(0xc0, len(payload)) + payload
