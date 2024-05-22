import logging

import pytest

from bip32 import derive_key
from bip32_ext_key import parse_ext_key
from data.bip32_vectors import TEST_VECTORS


logger = logging.getLogger("btcseed")


@pytest.mark.parametrize("number, vector", enumerate(TEST_VECTORS, 1))
def test_vector(number, vector):
    seed = bytes.fromhex(vector["seed_hex"])
    for ch, tests in vector["chain"].items():
        for type_, expected in tests.items():
            assert type_ in {"ext pub", "ext prv"}
            logger.info(f"\nderive {ch} {type_}")
            derived = derive_key(seed, ch, mainnet=True, private=type_ == "ext prv")
            if not str(derived) == expected:
                logger.error("derived:")
                logger.error(repr(derived))
                logger.error("expected:")
                logger.error(repr(parse_ext_key(expected)))
            assert str(derived) == expected
