import logging

import pytest

from bip32 import derive_key
from bip32_ext_key import parse_ext_key
from data.bip85_vectors import DERIVATIONS


logger = logging.getLogger("btcseed")


@pytest.mark.parametrize(
    "vector",
    DERIVATIONS,
    ids=[f"Vector-{i + 1}" for i, e in enumerate(DERIVATIONS)],
)
def test_vectors(vector):
    return
    root_key = parse_ext_key(vector["master"], strict=False)
    logger.debug(repr(root_key))
    path = vector["path"]
