import logging

import pytest
from data.bip32_vectors import INVALID_KEYS, VECTORS

from bipsea.bip32 import to_master_key
from bipsea.bip32types import parse_ext_key
from bipsea.bip85 import derive
from bipsea.util import LOGGER

logger = logging.getLogger(LOGGER)


@pytest.mark.parametrize(
    "vector",
    VECTORS,
    ids=lambda v: f"Vector-{VECTORS.index(v) + 1}-{' '.join(v['chain'].keys())}",
)
def test_vectors_and_parse_ext_key(vector):
    seed = bytes.fromhex(vector["seed_hex"])
    for ch, tests in vector["chain"].items():
        for type_, expected in tests.items():
            assert type_ in ("ext pub", "ext prv")
            master = to_master_key(seed, mainnet=True, private=True)
            derived = derive(master, ch, private=type_ == "ext prv")
            assert str(derived) == expected
        if ch == "m":
            assert expected == str(parse_ext_key(expected))


@pytest.mark.parametrize(
    "key, reason",
    INVALID_KEYS,
    ids=[f"Vector-5-{reason[:32]}-{key[:8]}" for key, reason in INVALID_KEYS],
)
def test_invalid_keys(key, reason):
    with pytest.raises((AssertionError, ValueError)):
        parse_ext_key(key)
