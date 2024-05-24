import binascii
import logging

import pytest

from data.bip85_vectors import EXT_KEY_TO_ENTROPY
from bip32 import derive_key
from bip32_ext_key import parse_ext_key
from bip85 import DRNG, to_entropy, to_hex_string


logger = logging.getLogger("btcseed")


@pytest.mark.parametrize(
    "vector",
    EXT_KEY_TO_ENTROPY,
    ids=[f"Vector-{i + 1}" for i, e in enumerate(EXT_KEY_TO_ENTROPY)],
)
def test_vectors(vector):
    master = parse_ext_key(vector["master"])
    derived_key = derive_key(master, vector["path"], mainnet=True, private=True)
    secret = derived_key.data[1:]  # chop the BIP32 byte prefix
    assert to_hex_string(secret) == vector["derived_key"]
    entropy = to_entropy(secret)
    assert to_hex_string(entropy) == vector["derived_entropy"]
    if "drng" in vector:
        output = DRNG(entropy).read(vector["drng_length"])
        assert to_hex_string(output) == vector["drng"]
