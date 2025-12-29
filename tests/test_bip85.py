import logging
import os
from hashlib import sha256

import base58
import pytest
from Crypto.PublicKey import RSA
from data.bip85_vectors import COMMON_XPRV, EXT_KEY_TO_ENTROPY, PWD_BASE64

from bipsea.bip32types import parse_ext_key
from bipsea.bip39 import LANGUAGES, validate_mnemonic_words
from bipsea.bip85 import (
    APPLICATIONS,
    DRNG,
    INDEX_TO_LANGUAGE,
    apply_85,
    derive,
    split_and_validate,
    to_entropy,
)
from bipsea.registry import APPS
from bipsea.util import LOGGER_NAME, to_hex_string

logger = logging.getLogger(LOGGER_NAME)


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
@pytest.mark.xfail(reason="wut!? correct password, bad entropy; filed to BIP-85")
def test_pwd_base64_entropy(vector):
    master = parse_ext_key(vector["master"])
    path = vector["path"]
    output = apply_85(derive(master, path), path)
    assert vector["derived_entropy"] == to_hex_string(output["entropy"])


def _all_app_vectors():
    for app in APPS.values():
        for v in app.vectors:
            yield pytest.param(app, v, id=f"{app.name}-{v.path}")


@pytest.mark.parametrize("app,vector", list(_all_app_vectors()))
def test_app_vectors(app, vector):
    master = parse_ext_key(vector.master)
    path = vector.path
    output = apply_85(derive(master, path), path)
    assert to_hex_string(output["entropy"]) == vector.entropy
    assert output["application"] == vector.output


@pytest.mark.filterwarnings("ignore:.*184 bits")
@pytest.mark.parametrize("lang", LANGUAGES, ids=[lang for lang in LANGUAGES])
@pytest.mark.parametrize("n_words", (12, 18, 24))
def test_mnemonic_languages(n_words, lang):
    master = parse_ext_key(COMMON_XPRV)
    code = next(k for k, v in INDEX_TO_LANGUAGE.items() if v == lang)
    path = f"m/83696968'/39'/{code}/{n_words}'"
    output = apply_85(derive(master, path), path)
    words = output["application"].split(" ")
    assert validate_mnemonic_words(words, lang)


@pytest.mark.slow
@pytest.mark.parametrize("key_bits", [1024])
def test_rsa(key_bits):
    data = []
    for index in (0, 1):
        master = parse_ext_key(COMMON_XPRV)
        derived_key = derive(master, f"m/83696968'/828365'/{key_bits}'/{index}'")
        secret = derived_key.data[1:]  # chop the BIP-32 1-byte prefix
        entropy = to_entropy(secret)
        key = RSA.generate(key_bits, randfunc=DRNG(entropy).read)
        file_name = f"{key_bits}-{index}-public.pem"
        file_path = os.path.join("tests", "data", "rsa", file_name)
        datum = open(file_path, "rb").read()
        assert datum == key.public_key().export_key()
        data.append(datum)
    # keys must be distinct since indexes are distinct
    assert data[0] != data[1]


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


@pytest.mark.parametrize(
    "path, works",
    [
        ("m", True),
        ("x/1'", False),
        ("m/5h/3/4'", True),
        ("m/1/8*", False),
    ],
)
def test_split_and_validate(path, works):
    if works:
        split_and_validate(path)
    else:
        with pytest.raises(ValueError):
            split_and_validate(path)


@pytest.mark.parametrize(
    "path, works",
    [
        ("m/8369696'", False),
        (f"m/83696968'/{APPLICATIONS['hex']}/16'/10000'", True),
        (f"m/83696968'/{APPLICATIONS['hex']}/15'/10000'", False),
        (f"m/83696968'/{APPLICATIONS['base85']}/9'/11123213'", False),
        (f"m/83696968'/{APPLICATIONS['mnemonic']}/0'/13'", False),
        ("m/83696968'/707764'/0'/13'", False),
        ("m/83696968'/0'/0'/0'", False),
        ("m/83696968'/128169'/0/0'", False),
    ],
)
def test_apply_bad(path, works):
    master = parse_ext_key(COMMON_XPRV)
    if works:
        apply_85(master, path)
    else:
        with pytest.raises((ValueError, NotImplementedError)):
            apply_85(master, path)


def test_derive_public():
    master = parse_ext_key(
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    )
    with pytest.raises(ValueError):
        derive(master, "m/1'")


def test_drng_input():
    DRNG(bytes(64))
    with pytest.raises(ValueError):
        DRNG(bytes(65))
