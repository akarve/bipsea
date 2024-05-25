import binascii
import logging

import pytest

from data.bip85_vectors import BIP39, EXT_KEY_TO_ENTROPY, HEX, PWD_BASE64, PWD_BASE85, XPRV, WIF
from const import LOGGER
from bip32types import parse_ext_key
from bip85 import apply_85, derive, DRNG, to_entropy, to_hex_string


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


@pytest.mark.parametrize("vector", PWD_BASE64)
def test_pwd_base64(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_pwd"] == output["application"]


@pytest.mark.parametrize("vector", PWD_BASE64)
@pytest.mark.xfail(reason="Weird. Correct password but bad entropy.")
def test_pwd_base64_entropy(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_entropy"] == to_hex_string(output["entropy"])


@pytest.mark.parametrize("vector", PWD_BASE85)
def test_pwd_base85(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_pwd"] == output["application"]
    assert vector["derived_entropy"] == to_hex_string(output["entropy"])


@pytest.mark.parametrize("vector", BIP39)
def test_bip39(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]
    assert len(output["application"].split(" ")) == vector["mnemonic_length"]
    assert output["application"] == vector["derived_mnemonic"]


@pytest.mark.parametrize("vector", HEX)
def test_hex(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_entropy"] == output["application"]


@pytest.mark.parametrize("vector", XPRV)
def test_xprv(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_key"] == output["application"]
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]


@pytest.mark.parametrize("vector", WIF)
def test_wif(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]
    # TODO: file against BIP85 poor test case does not include WIF checksum
    assert output["application"].decode("utf-8") == vector["derived_wif"]