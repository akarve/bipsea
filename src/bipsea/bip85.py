import base64
import hashlib
import logging
import re
from typing import Dict, Union

import base58

from .bip32 import VERSIONS, ExtendedKey
from .bip32 import derive_key as derive_key_bip32
from .bip32 import hmac_sha512
from .seedwords import entropy_to_words
from .util import LOGGER, to_hex_string

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


def apply_85(derived_key: ExtendedKey, path: str) -> Dict[str, Union[bytes, str]]:
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
    # BIP 39
    if application == "39'":
        language, n_words = indexes[:2]
        if not language == LANGUAGE_CODES["English"]:
            raise ValueError(f"Only English BIP39 words from BIP85 are supported.")
        if not n_words in CODE_39_TO_BITS:
            raise ValueError(f"Expected word codes {CODE_39_TO_BITS.keys()}")
        n_bytes = CODE_39_TO_BITS[n_words] // 8
        trimmed_entropy = entropy[:n_bytes]
        n_words_int = int(n_words[:-1])  # chop the ' from hardened derivation
        return {
            "entropy": trimmed_entropy,
            "application": " ".join(entropy_to_words(n_words_int, trimmed_entropy)),
        }
    # WIF
    elif application == "2'":
        trimmed_entropy = entropy[: 256 // 8]
        prefix = b"\x80" if derived_key.get_network() == "mainnet" else b"\xef"
        suffix = b"\x01"  # use with compressed public keys because BIP32
        extended = prefix + trimmed_entropy + suffix
        hash1 = hashlib.sha256(extended).digest()
        hash2 = hashlib.sha256(hash1).digest()

        return {
            "entropy": trimmed_entropy,
            "application": base58.b58encode_check(extended),
            "checksum": hash2[:4],
        }
    # XPRV
    elif application == "32'":
        derived_key = ExtendedKey(
            # TODO: file against bip85 that there is no provision to specify
            # main vs testnet
            # TODO: file against bip85 that they are inconsistent with
            # hmac entropy order :shrug:
            version=VERSIONS["mainnet"]["private"],
            depth=bytes(1),
            finger=bytes(4),
            child_number=bytes(4),
            chain_code=entropy[:32],
            data=bytes(1) + entropy[32:],
        )

        return {
            # TODO: also file against bip85 that there is no consistency about
            # returned entropy length in test vectors?
            # TODO: this is wrong on multiple levels; first we use
            # 64 bytes from the entropy for this application
            # second this isn't even the chain_code which in some universe
            # might be considered derived entropy :(
            "entropy": entropy[32:],
            "application": str(derived_key),
        }
    # HEX
    elif application == "128169'":
        num_bytes = int(indexes[0][:-1])
        if not (16 <= num_bytes <= 64):
            raise ValueError(f"Expected num_bytes in [16, 64], got {num_bytes}")

        return {"entropy": entropy, "application": to_hex_string(entropy[:num_bytes])}
    # PWD BASE64
    elif application == "707764'":
        pwd_len = int(indexes[0][:-1])
        # TODO file Base64 typo in 85 "encode the all 64 bytes of entropy".
        if not (20 <= pwd_len <= 86):
            raise ValueError(f"Expected pwd_len in [20, 86], got {pwd_len}")

        return {
            "entropy": entropy,
            "application": base64.b64encode(entropy).decode("utf-8")[:pwd_len],
        }
    # PWD BASE85
    elif application == "707785'":
        pwd_len = int(indexes[0][:-1])
        if not (10 <= pwd_len <= 80):
            raise ValueError("Expected pwd_len in [10, 80], got {pwd_len}")

        return {
            "entropy": entropy,
            "application": base64.b85encode(entropy).decode("utf-8")[:pwd_len],
        }
    else:
        raise NotImplementedError(f"Unsupported application: {application}")


def to_entropy(data: bytes) -> bytes:
    return hmac_sha512(key=HMAC_KEY, data=data)


def derive(master: ExtendedKey, path: str, private: bool = True):
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
