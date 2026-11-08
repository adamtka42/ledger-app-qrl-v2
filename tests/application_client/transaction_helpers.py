"""Shared signing constants and APDU chunk collection."""
from ragger.backend.interface import BackendInterface
from .boilerplate_command_sender import CLA, InsType

# ML-DSA-87 signing context: "ZOND" || version 0x01 || descriptor 01 00 00
SIGNING_CONTEXT = bytes.fromhex("5a4f4e4401010000")
PK_LEN = 2592
SIG_LEN = 4627


def get_public_key_chunks(backend: BackendInterface) -> bytes:
    """Fetch the 2,592-byte ML-DSA-87 public key via chunked GET_PUBLIC_KEY."""
    pk = b""
    for p2 in range(1, 12):
        r = backend.exchange(cla=CLA, ins=InsType.GET_PUBLIC_KEY, p1=0, p2=p2)
        pk += r.data
    return pk[:PK_LEN]


def get_signature_chunks(backend: BackendInterface, first_chunk: bytes) -> bytes:
    """Collect the remaining signature chunks after the auto-returned first."""
    sig = bytearray(first_chunk)
    for p2 in range(1, 18):
        r = backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=p2)
        sig += r.data
    return bytes(sig)[:SIG_LEN]
