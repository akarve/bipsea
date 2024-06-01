import logging
from hashlib import sha256

import base58
import pytest
from data.bip85_vectors import (
    BIP39,
    DICE,
    EXT_KEY_TO_ENTROPY,
    HEX,
    PWD_BASE64,
    PWD_BASE85,
    WIF,
    XPRV,
)

from bipsea.bip32types import parse_ext_key
from bipsea.bip85 import DRNG, apply_85, derive, to_entropy, to_hex_string
from bipsea.util import LOGGER, to_hex_string

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
    # Hardcode what we believe is correct; issue filed to BIP85
    assert (
        to_hex_string(output["entropy"])
        == "74a2e87a9ba0cdd549bdd2f9ea880d554c6c355b08ed25088cfa88f3f1c4f74632b652fd4a8f5fda43074c6f6964a3753b08bb5210c8f5e75c07a4c2a20bf6e9"
    )


@pytest.mark.parametrize("vector", PWD_BASE64)
@pytest.mark.xfail(reason="wut!? correct password, bad entropy; file to BIP-85")
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
def test_rsa_unsupported(vector):
    """currently no support for RSA application.
    path format: m/83696968'/828365'/{key_bits}'/{key_index}'"""
    rsa_path = "m/83696968'/828365'/1024'/0'"
    master = parse_ext_key(vector["master"])
    with pytest.raises(ValueError):
        apply_85(derive(master, rsa_path), rsa_path)


@pytest.mark.parametrize("vector", WIF)
def test_wif(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]
    assert output["application"] == vector["derived_wif"]


@pytest.mark.parametrize("vector", XPRV)
def test_xprv(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_key"] == output["application"]
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]


def test_private_key_to_wif():
    """https://en.bitcoin.it/wiki/Wallet_import_format"""


def test_private_key_to_wif():
    pkey_hex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    pkey = bytes.fromhex(pkey_hex)
    extended = b"\x80" + pkey
    hash1 = sha256(extended).digest()
    hash2 = sha256(hash1).digest()
    checksum = hash2[:4]
    # they say "Base58Check encoding" but that doesn't mean
    # b58encode_check because we already have a checksum apparently
    wif = base58.b58encode(extended + checksum)
    assert wif.decode("utf-8") == "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"


@pytest.mark.parametrize("vector", DICE)
def test_rsa_unsupported(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    rolls = output["application"]
    assert rolls == vector["derived_rolls"]
    rolls_int = [int(r) for r in rolls.split(",")]
    assert len(rolls_int) == 10
    assert all(0 <= r < 10 for r in rolls_int)
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]
