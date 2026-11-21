"""Versioned, read-only application configuration response."""
from dataclasses import dataclass
from enum import IntFlag
from typing import Tuple


class ConfigurationFlags(IntFlag):
    BLIND_SIGNING = 1 << 0
    DISPLAY_NONCE = 1 << 1
    DISPLAY_TX_HASH = 1 << 2


@dataclass(frozen=True)
class AppConfiguration:
    flags: int
    version: Tuple[int, int, int]

    @classmethod
    def from_bytes(cls, response: bytes) -> "AppConfiguration":
        if len(response) != 5:
            raise ValueError("Expected a five-byte application configuration")
        if response[0] != 1:
            raise ValueError("Unsupported application configuration format")
        # Preserve unknown bits so callers can ignore future settings flags.
        return cls(response[1], (response[2], response[3], response[4]))

    @property
    def blind_signing_enabled(self) -> bool:
        return bool(self.flags & ConfigurationFlags.BLIND_SIGNING)

    @property
    def display_nonce(self) -> bool:
        return bool(self.flags & ConfigurationFlags.DISPLAY_NONCE)

    @property
    def display_tx_hash(self) -> bool:
        return bool(self.flags & ConfigurationFlags.DISPLAY_TX_HASH)
