import base64
import hashlib
import logging
import math
import re
from typing import Dict, Union

import base58
from ecdsa import SECP256k1

from .bip32 import VERSIONS, ExtendedKey
from .bip32 import derive_key as derive_key_bip32
from .bip32 import hmac_sha512
from .bip39 import LANGUAGES, N_WORDS_META, entropy_to_words, verify_seed_words
from .util import LOGGER, to_hex_string

logger = logging.getLogger(LOGGER)


APPLICATIONS = {
    "base64": "707764'",
    "base85": "707785'",
    "dice": "89101'",
    "drng": "0'",
    "hex": "128169'",
    "words": "39'",
    "wif": "2'",
    "xprv": "32'",
}

RANGES = {
    "base64": (20, 86),
    "base85": (10, 80),
    "hex": (16, 64),
    "dice": (1, 10_000),
}

PURPOSE_CODES = {"BIP-85": "83696968'"}

HMAC_KEY = b"bip-entropy-from-k"

INDEX_TO_LANGUAGE = {
    "0'": "english",
    "1'": "japanese",
    "2'": "korean",
    "3'": "spanish",
    "4'": "chinese_simplified",
    "5'": "chinese_traditional",
    "6'": "french",
    "7'": "italian",
    "8'": "czech",
    "9'": "portuguese",  # not in BIP-85 but in BIP-39 test vectors
}

assert set(INDEX_TO_LANGUAGE.values()) == set(LANGUAGES.keys())


def apply_85(derived_key: ExtendedKey, path: str) -> Dict[str, Union[bytes, str]]:
    """returns a dict with 'entropy': bytes and 'application': str"""
    segments = split_and_validate(path)
    purpose = segments[1]
    if purpose != PURPOSE_CODES["BIP-85"]:
        raise ValueError(f"Not a BIP85 path: {path}")
    if len(segments) < 4 or not all(s.endswith("'") for s in segments[1:]):
        raise ValueError(
            f"Paths should have 4+ segments, all hardened children: {path}"
        )
    app, *indexes = segments[2:]

    entropy = to_entropy(derived_key.data[1:])

    if app == APPLICATIONS["words"]:
        language_index, n_words = indexes[:2]
        n_words = int(n_words[:-1])  # chop ' from hardened derivation
        if n_words not in N_WORDS_META.keys():
            raise ValueError(f"Unsupported number of words: {n_words}.")
        language = INDEX_TO_LANGUAGE[language_index]
        n_bytes = N_WORDS_META[n_words]["entropy_bits"] // 8
        trimmed_entropy = entropy[:n_bytes]
        words = entropy_to_words(n_words, trimmed_entropy, language)
        assert verify_seed_words(words, language)

        return {
            "entropy": trimmed_entropy,
            "application": " ".join(words),
        }
    elif app == APPLICATIONS["wif"]:
        trimmed_entropy = entropy[: 256 // 8]
        prefix = b"\x80" if derived_key.get_network() == "mainnet" else b"\xef"
        suffix = b"\x01"  # use with compressed public keys because BIP-32
        extended = prefix + trimmed_entropy + suffix

        return {
            "entropy": trimmed_entropy,
            "application": base58.b58encode_check(extended).decode("utf-8"),
        }
    elif app == APPLICATIONS["xprv"]:
        derived_key = ExtendedKey(
            version=VERSIONS["mainnet"]["private"],
            depth=bytes(1),
            finger=bytes(4),
            child_number=bytes(4),
            chain_code=entropy[:32],
            data=bytes(1) + entropy[32:],
        )

        return {
            "entropy": entropy[32:],
            "application": str(derived_key),
        }
    elif app == APPLICATIONS["hex"]:
        num_bytes = int(indexes[0][:-1])
        if not (16 <= num_bytes <= 64):
            raise ValueError(f"Expected num_bytes in [16, 64], got {num_bytes}")

        return {"entropy": entropy, "application": to_hex_string(entropy[:num_bytes])}
    elif app == APPLICATIONS["base64"]:
        pwd_len = int(indexes[0][:-1])
        if not (20 <= pwd_len <= 86):
            raise ValueError(f"Expected pwd_len in [20, 86], got {pwd_len}")

        return {
            "entropy": entropy,
            "application": base64.b64encode(entropy).decode("utf-8")[:pwd_len],
        }
    elif app == APPLICATIONS["base85"]:
        pwd_len = int(indexes[0][:-1])
        if not (10 <= pwd_len <= 80):
            raise ValueError("Expected pwd_len in [10, 80], got {pwd_len}")

        return {
            "entropy": entropy,
            "application": base64.b85encode(entropy).decode("utf-8")[:pwd_len],
        }
    elif app == APPLICATIONS["dice"]:
        sides, rolls, index = (int(s[:-1]) for s in indexes[:3])
        return {
            "entropy": entropy,
            "application": do_rolls(entropy, sides, rolls, index),
        }
    else:
        raise NotImplementedError(f"Unsupported BIP-85 application {app}")


def to_entropy(data: bytes) -> bytes:
    return hmac_sha512(key=HMAC_KEY, data=data)


def derive(master: ExtendedKey, path: str, private: bool = True) -> ExtendedKey:
    if not master.is_private():
        raise ValueError("Derivations should begin with a private master key")

    return derive_key_bip32(master, split_and_validate(path), private)


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


def validate_key(entropy: bytes):
    """per BIP-85 we should hard fail under these conditions"""
    assert len(entropy) == 32
    int_key = int.from_bytes(entropy, "big")
    if not int_key or int_key > SECP256k1.order:
        raise ValueError("Invalid derived key. Try again with next child index.")


def do_rolls(entropy: bytes, sides: int, rolls: int, index: int) -> str:
    """sides > 1, 1 < rolls > 100"""
    max_width = len(str(sides - 1))
    history = []
    bits_per_roll = math.ceil(math.log(sides, 2))
    bytes_per_roll = math.ceil(bits_per_roll / 8)
    drng = DRNG(entropy)
    while len(history) < rolls:
        trial_int = int.from_bytes(drng.read(bytes_per_roll), "big")
        available_bits = 8 * bytes_per_roll
        excess_bits = available_bits - bits_per_roll
        trial_int >>= excess_bits
        if trial_int >= sides:
            continue
        else:
            history.append(f"{trial_int:0{max_width}d}")

    return ",".join(history)
