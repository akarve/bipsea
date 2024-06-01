"""constants and utilities"""

import binascii
import logging
import math
import string
from collections import Counter
from hashlib import pbkdf2_hmac
from unicodedata import normalize as unicode_normalize

__version__ = "0.2.1"
__app_name__ = "bipsea"

ASCII_INPUTS = set(string.printable.lower())
FORMAT = "utf-8"
NFKD = "NFKD"
LOGGER = __app_name__
MIN_ENTROPY = 256


logger = logging.getLogger(LOGGER)


def to_hex_string(data: bytes) -> str:
    return binascii.hexlify(data).decode("utf-8")


def pbkdf2(
    mnemonic: str, passphrase: str, iterations: int = 2048, hash_name: str = "sha512"
) -> bytes:
    return pbkdf2_hmac(
        hash_name=hash_name,
        password=normalize(mnemonic),
        salt=normalize("mnemonic" + passphrase),
        iterations=iterations,
    )


def normalize(input: str) -> str:
    return unicode_normalize(NFKD, input).encode(FORMAT)


def shannon_entropy(input: str, cardinality: int = len(ASCII_INPUTS)):
    counts = Counter(input)
    probs = {char: count / cardinality for char, count in counts.items()}

    return -sum(prob * math.log(prob, 2) for prob in probs.values())


def relative_entropy(input: str):
    ideal = "".join(ASCII_INPUTS)

    return len(input) * shannon_entropy(ideal)


def validate_input(input: str):
    if not (set(input) <= ASCII_INPUTS):
        raise ValueError(f"Unexpected input character(s): {input}")

    return True
