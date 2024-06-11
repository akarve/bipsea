import logging
import math

import pytest

from bipsea.util import (
    ASCII_INPUTS,
    LOGGER_NAME,
    contains_only_ascii,
    deck_52,
    relative_entropy,
    shannon_entropy,
    shuffle,
    to_hex_string,
)

logger = logging.getLogger(LOGGER_NAME)


def test_absolute_entropy():
    universe = set(list(ASCII_INPUTS))
    assert math.isclose(shannon_entropy(universe), math.log(len(universe), 2))


def test_relative_entropy():
    deck = deck_52()
    shuffled = shuffle(list(deck))
    # order doesn't matter and the deck's relative entropy is close to 1
    assert math.isclose(relative_entropy(shuffled, set(deck)), 1)
    assert math.isclose(1, relative_entropy(deck, set(deck)))


def test_contains_only_ascii():
    universe = "".join(ASCII_INPUTS)
    assert contains_only_ascii(universe)
    with pytest.raises(ValueError):
        contains_only_ascii(universe + "ñ")


def test_shuffle():
    shuffled = shuffle(deck_52())
    assert shuffled != deck_52()


def test_bad_relatve_entropy():
    with pytest.warns(UserWarning, match="outside"):
        relative_entropy("λ")


def test_to_hex_string():
    data = b"\x00\xff\x10\x20"
    expected = "00ff1020"
    assert to_hex_string(data) == expected
