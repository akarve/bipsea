import binascii
import logging

import pytest

from data.bip85_vectors import BIP39, EXT_KEY_TO_ENTROPY
from const import LOGGER
from bip32types import parse_ext_key
from bip85 import derive, DRNG, to_entropy, to_hex_string


logger = logging.getLogger(LOGGER)


@pytest.mark.parametrize(
    "vector",
    EXT_KEY_TO_ENTROPY,
    ids=[f"Vector-{i + 1}" for i, e in enumerate(EXT_KEY_TO_ENTROPY)],
)
def test_entropy(vector):
    master = parse_ext_key(vector["master"])
    derived_key = derive(master, vector["path"])
    secret = derived_key.data[1:]  # chop the BIP32 byte prefix
    assert to_hex_string(secret) == vector["derived_key"]
    entropy = to_entropy(secret)
    assert to_hex_string(entropy) == vector["derived_entropy"]
    if "drng" in vector:
        output = DRNG(entropy).read(vector["drng_length"])
        assert to_hex_string(output) == vector["drng"]


@pytest.mark.parametrize("vector", BIP39)
def test_bip39(vector):
    master = parse_ext_key(vector["master"])
    derived_entropy = derive(master, vector["path"])
    assert to_hex_string(derived_entropy) == vector["derived_entropy"]
