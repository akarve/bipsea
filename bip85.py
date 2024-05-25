import binascii
from typing import Dict, List, Union
import hashlib
import logging
import re

import base58

from bip32 import derive_key as derive_key_bip32, ExtendedKey, hmac_sha512
from const import LOGGER
from seedwords import entropy_to_words


logger = logging.getLogger(LOGGER)


HMAC_KEY = b"bip-entropy-from-k"
CODE_39_TO_BITS = {
    "12'": 128,
    "18'": 192,
    "21'": 224,
    "24'": 256,
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


def apply_85(derived_key: ExtendedKey, path: str) -> Dict[str, Union[bytes, List[str]]]:
    """returns a dict with 'entropy': bytes and 'application': str"""
    segments = split_and_validate(path)
    purpose = segments[1]
    if purpose != PURPOSE_CODES["BIP-85"]:
        raise ValueError(f"Not a BIP85 path: {path}")
    if len(segments) < 4 or not all(s.endswith("'") for s in segments[1:]):
        raise ValueError(
            f"BIP-85 paths should have 4+ segments and hardened children: {segments}"
        )
    application, *indexes = segments[2:]

    entropy = to_entropy(derived_key.data[1:])
    if application == "39'":
        language, n_words, index = indexes[:3]
        if not language == LANGUAGE_CODES["English"]:
            raise ValueError(f"Only English BIP39 words from BIP85 are supported.")
        if not n_words in CODE_39_TO_BITS:
            raise ValueError(f"Expected word codes {CODE_39_TO_BITS.keys()}")
        n_bytes = CODE_39_TO_BITS[n_words] // 8
        trimmed_entropy = entropy[:n_bytes]
        n_words_int = int(n_words[:-1])  # chop the ' from hardened derivation
        return {
            "entropy": trimmed_entropy,
            "application": entropy_to_words(n_words_int, trimmed_entropy),
        }
    elif application == "2'":
        entropy = entropy[: 256 // 8]
        prefix = b"\x80" if derived_key.get_network() == "mainnet" else b"\xef"
        suffix = b"\x01"  # use with compressed public keys because BIP32
        extended = prefix + entropy + suffix
        hash1 = hashlib.sha256(extended).digest()
        hash2 = hashlib.sha256(hash1).digest()
        checksum = hash2[:4]

        return {
            "entropy": entropy[: 256 // 8],
            "application": base58.b58encode_check(extended),
            "checksum": checksum,
        }

    else:
        raise NotImplementedError


def to_entropy(data: bytes) -> bytes:
    return hmac_sha512(key=HMAC_KEY, data=data)


def derive(master: ExtendedKey, path: str, private: bool = True):
    if not master.is_private():
        raise ValueError("Derivations should begin with a private master key")

    return derive_key_bip32(master, split_and_validate(path), private)


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
