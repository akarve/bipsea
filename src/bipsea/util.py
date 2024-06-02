"""constants and utilities"""

import binascii
import logging
import math
import random
import string
from collections import Counter
from hashlib import pbkdf2_hmac
from typing import List, Sequence
from unicodedata import normalize as unicode_normalize

__version__ = "0.2.5"
__app_name__ = "bipsea"

LOGGER = __app_name__
MIN_REL_ENTROPY = 0.51  # somewhat magic heuristic

ASCII_INPUTS = set(string.printable.lower())
FORMAT = "utf-8"
NFKD = "NFKD"

CARD_SUITS = ["S", "D", "C", "H"]
CARD_RANKS = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"]


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


def shannon_entropy(input: List[str], cardinality: int) -> float:
    counts = Counter(input)
    probs = {char: count / cardinality for char, count in counts.items()}

    return -sum(prob * math.log(prob, 2) for prob in probs.values())


def relative_entropy(input: List[str], universe: set):
    ideal = math.log(len(universe), 2)
    actual = shannon_entropy(input, len(universe))

    return actual / ideal


def contains_only_ascii(lst: List[str]):
    if not all(e in ASCII_INPUTS for e in lst):
        raise ValueError(f"Unexpected input character(s): {input}")

    return True


def deck_52() -> List:
    """simulate a 52 card deck"""
    deck = [rank + suit for suit in CARD_SUITS for rank in CARD_RANKS]
    for s in CARD_SUITS:
        assert len([x for x in deck if x[-1] == s]) == 13
    for r in CARD_RANKS:
        assert len([x for x in deck if x.startswith(r)]) == 4
    assert len(set(deck)) == 52

    return deck


def shuffle(lst: List[str]) -> List[str]:
    last = len(lst) - 1
    for cursor in range(last, 0, -1):
        choice = random.randint(0, cursor)
        lst[cursor], lst[choice] = lst[choice], lst[cursor]

    return lst
