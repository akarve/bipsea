import logging
import math

import pytest

from bipsea.util import (
    ASCII_INPUTS,
    LOGGER,
    contains_only_ascii,
    deck_52,
    relative_entropy,
    shannon_entropy,
    shuffle,
)

logger = logging.getLogger(LOGGER)


def test_absolute_entropy():
    universe = set(list(ASCII_INPUTS))
    assert math.isclose(
        shannon_entropy(universe, len(universe)), math.log(len(universe), 2)
    )


def test_relative_entropy():
    deck = deck_52()
    shuffled = shuffle(list(deck))
    # order doesn't matter
    assert math.isclose(relative_entropy(shuffled, deck), relative_entropy(deck, deck))
    # cutting universe in half yields a relative entropy of about 1/2
    assert math.isclose(relative_entropy(deck[:26], set(deck)), 0.5)
    assert math.isclose(relative_entropy(deck[:13], set(deck)), 0.25)


def test_contains_only_ascii():
    universe = "".join(ASCII_INPUTS)
    assert contains_only_ascii(universe)
    with pytest.raises(ValueError):
        contains_only_ascii(universe + "ñ")


def test_shuffle():
    shuffled = shuffle(deck_52())
    assert shuffled != deck_52()
