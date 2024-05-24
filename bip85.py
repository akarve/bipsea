import binascii
import hashlib
import logging
import re

from bip32 import derive_key as derive_key_bip32, ExtendedKey, hmac_sha512
from const import LOGGER


logger = logging.getLogger(LOGGER)


HMAC_KEY = b"bip-entropy-from-k"
ENTROPY_CODES = {
    "12 words": {"entropy_bits": 128, "code": "12'"},
    "18 words": {"entropy_bits": 192, "code": "18'"},
    "24 words": {"entropy_bits": 256, "code": "24'"},
}
LANGUAGE_CODES = {
    "English": "0'",
    "Japanese": "1'",
    "Korean": "2'",
    "Spanish": "3'",
    "Chinese (Simplified)": "4'",
    "Chinese (Traditional)": "5'",
    "French": "6'",
    "Italian": "7'",
    "Czech": "8'",
}
PURPOSE_CODES = {"BIP-85": "83696968'"}


def to_entropy(data: bytes) -> bytes:
    return hmac_sha512(key=HMAC_KEY, data=data)


def derive(master: ExtendedKey, path: str, private: bool = True):
    if not master.is_private():
        raise ValueError("Derivations should begin with a private master key")
    segments = split_and_validate(path)
    if segments[1:]:
        purpose = segments[1]
        if purpose == PURPOSE_CODES["BIP-85"]:
            if len(segments) < 4 or not any(s.endswith("'") for s in segments[1:]):
                raise ValueError(
                    f"Expected BIP-85 path to have at least four segments and mostly hardened children: {segments}"
                )
            application, *indexes = segments[2:]

            if application == "39'":
                language, words, index = indexes[:3]

    return derive_key_bip32(master, segments, private)


def to_hex_string(data: bytes) -> str:
    return binascii.hexlify(data).decode("utf-8")


class DRNG:
    def __init__(self, seed: bytes):
        if len(seed) != 64:
            raise ValueError("Seed must be exactly 64 bytes long")
        self.shake = hashlib.shake_256(seed)
        self.cursor = 0

    def read(self, n: int) -> bytes:
        start = self.cursor
        self.cursor = stop = start + n

        return self.shake.digest(stop)[start:stop]


def split_and_validate(path: str):
    segments = path.split("/")
    if segments[0] != "m":
        raise ValueError(f"Expected 'm' (xprv) at root of derivation path: {path}")
    pattern = r"^\d+['hH]?$"
    if not all(re.match(pattern, s) for s in segments[1:]):
        raise ValueError(f"Unexpected path segments: {path}")

    return segments
