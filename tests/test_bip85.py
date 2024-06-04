import logging
from hashlib import sha256

import base58
import pytest
from data.bip85_vectors import (
    BIP_39,
    DICE,
    EXT_KEY_TO_ENTROPY,
    HEX,
    PWD_BASE64,
    PWD_BASE85,
    WIF,
    XPRV,
)

from bipsea.bip32types import parse_ext_key
from bipsea.bip39 import LANGUAGES, verify_seed_words
from bipsea.bip85 import DRNG, INDEX_TO_LANGUAGE, apply_85, derive, to_entropy
from bipsea.util import LOGGER, to_hex_string

logger = logging.getLogger(LOGGER)


@pytest.mark.parametrize(
    "vector",
    EXT_KEY_TO_ENTROPY,
    ids=[f"ext_ent-{i}" for i in range(len(EXT_KEY_TO_ENTROPY))],
)
def test_entropy(vector):
    master = parse_ext_key(vector["master"])
    derived_key = derive(master, vector["path"])
    secret = derived_key.data[1:]  # chop the BIP-32 1-byte prefix
    assert to_hex_string(secret) == vector["derived_key"]
    entropy = to_entropy(secret)
    assert to_hex_string(entropy) == vector["derived_entropy"]
    if "drng" in vector:
        output = DRNG(entropy).read(vector["drng_length"])
        assert to_hex_string(output) == vector["drng"]


@pytest.mark.parametrize("vector", PWD_BASE64, ids=["PWD_BASE64"])
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


@pytest.mark.parametrize("vector", PWD_BASE64, ids=["PWD_BASE64"])
@pytest.mark.xfail(reason="wut!? correct password, bad entropy; filed to BIP-85")
def test_pwd_base64_entropy(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_entropy"] == to_hex_string(output["entropy"])


@pytest.mark.parametrize("vector", PWD_BASE85, ids=["PWD_BASE85"])
def test_pwd_base85(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_pwd"] == output["application"]
    assert vector["derived_entropy"] == to_hex_string(output["entropy"])


@pytest.mark.parametrize(
    "vector",
    BIP_39,
    ids=[f"BIP_39-{v['mnemonic_length']}" for v in BIP_39],
)
def test_bip39_application(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]
    words = output["application"].split(" ")
    assert len(words) == vector["mnemonic_length"]
    assert output["application"] == vector["derived_mnemonic"]
    assert verify_seed_words(words, "english")


@pytest.mark.filterwarnings("ignore:.*184 bits")
@pytest.mark.parametrize("lang", LANGUAGES, ids=[lang for lang in LANGUAGES])
@pytest.mark.parametrize(
    "vector",
    BIP_39,
    ids=[f"BIP_39-{v['mnemonic_length']}" for v in BIP_39],
)
def test_bip39_application_languages(vector, lang):
    n_words = vector["mnemonic_length"]
    master = parse_ext_key(vector["master"])
    codes = [k for k, v in INDEX_TO_LANGUAGE.items() if v == lang]
    assert len(codes) == 1
    path = f"m/83696968'/39'/{codes[0]}/{n_words}'"
    output = apply_85(derive(master, path), path)
    words = output["application"].split(" ")
    assert verify_seed_words(words, lang)


@pytest.mark.parametrize("vector", HEX, ids=["HEX"])
def test_hex(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_entropy"] == output["application"]


@pytest.mark.parametrize("vector", XPRV, ids=["XPRV"])
@pytest.mark.xfail(reason="RSA application not implemented", raises=NotImplementedError)
def test_rsa_unimplemented(vector):
    """currently no support for RSA application.
    path format: m/83696968'/828365'/{key_bits}'/{key_index}'"""
    rsa_path = "m/83696968'/828365'/1024'/0'"
    master = parse_ext_key(vector["master"])
    apply_85(derive(master, rsa_path), rsa_path)


@pytest.mark.parametrize("vector", WIF, ids=["WIF"])
def test_wif(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]
    assert output["application"] == vector["derived_wif"]


@pytest.mark.parametrize("vector", XPRV, ids=["XPRV"])
def test_xprv(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_key"] == output["application"]
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]


def test_private_key_to_wif():
    """follow the procedure from
    https://en.bitcoin.it/wiki/Wallet_import_format"""
    pkey_hex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    pkey = bytes.fromhex(pkey_hex)
    extended = b"\x80" + pkey
    hash1 = sha256(extended).digest()
    hash2 = sha256(hash1).digest()
    checksum = hash2[:4]

    wif = base58.b58encode(extended + checksum)
    assert wif.decode("utf-8") == "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    # make sure our checksum is the same
    assert wif == base58.b58encode_check(extended)


@pytest.mark.parametrize("vector", DICE, ids=["DICE"])
def test_dice(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    rolls = output["application"]
    assert rolls == vector["derived_rolls"]
    rolls_int = [int(r) for r in rolls.split(",")]
    assert len(rolls_int) == 10
    assert all(0 <= r < 10 for r in rolls_int)
    assert to_hex_string(output["entropy"]) == vector["derived_entropy"]
