import logging

import pytest

from bip32 import derive_key, to_master_key
from to_seed import from_hex
from bip32_ext_key import parse_ext_key
from data.bip32_vectors import INVALID_KEYS, TEST_VECTORS


logger = logging.getLogger("btcseed")


@pytest.mark.parametrize(
    "vector",
    TEST_VECTORS,
    ids=[
        f"Vector-{i + 1}-{', '.join(e['chain'].keys())}"
        for i, e in enumerate(TEST_VECTORS)
    ],
)
def test_vectors(vector):
    seed = from_hex(vector["seed_hex"])
    for ch, tests in vector["chain"].items():
        for type_, expected in tests.items():
            assert type_ in {"ext pub", "ext prv"}
            logger.info(f"\nderive {ch} {type_}")
            master = to_master_key(seed, private=True)
            derived = derive_key(master, ch, mainnet=True, private=type_ == "ext prv")
            if not str(derived) == expected:
                logger.error("derived:")
                logger.error(repr(derived))
                logger.error("expected:")
                logger.error(repr(parse_ext_key(expected)))
            assert str(derived) == expected


@pytest.mark.parametrize(
    "key, reason",
    INVALID_KEYS,
    ids=[f"Vector-5-{reason[:32]}-{key[:8]}" for key, reason in INVALID_KEYS],
)
def test_invalid_keys(key, reason):
    with pytest.raises((AssertionError, ValueError)):
        parse_ext_key(key)
