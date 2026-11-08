"""QRL personal-sign framing: raw text bytes, not a host-supplied digest."""
from Crypto.Hash import keccak
from ragger.bip import pack_derivation_path

from .boilerplate_command_sender import CLA, InsType

PATH = "m/44'/238'/0'/0/0"
MAX_MESSAGE_LEN = 1024


def personal_message_hash(message: bytes, prefix=b"\x19QRL Signed Message:\n") -> bytes:
    return keccak.new(digest_bits=256,
                      data=prefix + str(len(message)).encode("ascii") + message).digest()


def start_message(backend, length, path=PATH):
    return backend.exchange(cla=CLA, ins=InsType.SIGN_PERSONAL_MESSAGE, p1=0, p2=0,
                            data=pack_derivation_path(path) + length.to_bytes(4, "big"))


def send_message(backend, data=b"", *, p1=2, p2=0):
    return backend.exchange(cla=CLA, ins=InsType.SIGN_PERSONAL_MESSAGE, p1=p1, p2=p2, data=data)
