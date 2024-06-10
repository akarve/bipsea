"""constants and utilities"""

import binascii
import logging
import math
import random
import string
import warnings
from collections import Counter
from typing import List, Sequence

from poetry.factory import Factory

POETRY = Factory().create_poetry()

MIN_REL_ENTROPY = 0.50  # somewhat magic heuristic

LOGGER_NAME = POETRY.package.name

__app_name__ = POETRY.package.name
__version__ = POETRY.package.version

ASCII_INPUTS = set(string.printable.lower())
FORMAT = "utf-8"
NFKD = "NFKD"

CARD_SUITS = ["S", "D", "C", "H"]
CARD_RANKS = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"]


logger = logging.getLogger(LOGGER_NAME)


def to_hex_string(data: bytes) -> str:
    return binascii.hexlify(data).decode("utf-8")


def shannon_entropy(input: List[str]) -> float:
    counts = Counter(input)
    total = sum(counts.values())
    probs = {char: count / total for char, count in counts.items()}

    return -sum(prob * math.log(prob, 2) for prob in probs.values())


def relative_entropy(input: Sequence, universe: set = ASCII_INPUTS) -> float:
    input_set = set(list(input))
    overage = input_set - universe

    ideal = math.log(len(universe), 2)
    actual = shannon_entropy(input)
    ratio = actual / ideal

    if overage:
        warnings.warn(
            f"Some inputs outside universe ({universe}): {overage}, can't estimate entropy"
        )
    else:
        assert 0 <= ratio <= 1.001

    return ratio


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
