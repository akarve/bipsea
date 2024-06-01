import logging
import math

import pytest

from bipsea.util import (
    ASCII_INPUTS,
    LOGGER,
    relative_entropy,
    shannon_entropy,
    validate_input,
)

logger = logging.getLogger(LOGGER)


def test_absolute_entropy():
    universe = "".join(ASCII_INPUTS)
    assert math.isclose(shannon_entropy(universe), 6.209, rel_tol=0.001)


def test_relative_entropy():
    universe = "".join(ASCII_INPUTS)


def test_validate_input():
    universe = "".join(ASCII_INPUTS)
    assert validate_input(universe)
    with pytest.raises(ValueError):
        validate_input(universe + "ñ")
