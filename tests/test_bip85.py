import binascii
import logging

import pytest

from data.bip85_vectors import BIP39, EXT_KEY_TO_ENTROPY
from const import LOGGER
from bip32types import parse_ext_key
from bip85 import apply_85, derive, DRNG, to_entropy, to_hex_string
from seedwords import entropy_to_words


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
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]
    assert len(output["application"]) == vector["mnemonic_length"]
    assert " ".join(output["application"]) == vector["derived_mnemonic"]
