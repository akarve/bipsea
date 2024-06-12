import contextlib
import logging

import pytest
from data.bip32_vectors import INVALID_KEYS, VECTORS
from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import INFINITY
from ecdsa.errors import MalformedPointError

from bipsea.bip32 import (
    TYPED_CHILD_KEY_COUNT,
    CKDpriv,
    CKDpub,
    to_master_key,
    validate_private_child_params,
    validate_public_child_params,
)
from bipsea.bip32types import parse_ext_key, validate_prv_str
from bipsea.bip85 import derive
from bipsea.util import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME)


@pytest.mark.parametrize(
    "vector",
    VECTORS,
    ids=lambda v: f"Vector-{VECTORS.index(v) + 1}",
)
def test_vectors_and_parse_ext_key(vector):
    seed = bytes.fromhex(vector["seed_hex"])
    for ch, tests in vector["chain"].items():
        for type_, expected in tests.items():
            assert type_ in ("ext pub", "ext prv")
            master = to_master_key(seed, mainnet=True, private=True)
            derived = derive(master, ch, private=type_ == "ext prv")
            assert str(derived) == expected
            xprv = str(parse_ext_key(expected))
            assert validate_prv_str(xprv, type_ == "ext prv")
        if ch == "m":
            assert expected == xprv


@pytest.mark.parametrize(
    "key_str, reason",
    INVALID_KEYS,
    ids=[f"Vector-5-{reason[:32]}-{key[:8]}" for key, reason in INVALID_KEYS],
)
def test_parse_invalid_keys(key_str: str, reason: str):
    with pytest.raises(ValueError):
        parse_ext_key(key_str)


def test_validate_private_params():
    with pytest.raises(ValueError):
        validate_private_child_params(SECP256k1.order + 1, 1, 0)
        validate_private_child_params(SECP256k1.order - 1, 0, 0)

    validate_private_child_params(SECP256k1.order - 1, 1, 0)


def test_validate_public_params():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    with pytest.raises(ValueError):
        validate_public_child_params(SECP256k1.order, public_key, 0)
        validate_public_child_params(SECP256k1.order, INFINITY, 0)
    validate_public_child_params(SECP256k1.order - 1, public_key, 0)


@pytest.mark.parametrize(
    "key_str, reason",
    INVALID_KEYS,
    ids=[f"Vector-5-{reason[:32]}-{key[:8]}" for key, reason in INVALID_KEYS],
)
def test_ckdpriv_invalid_keys(key_str: str, reason: str):
    with pytest.raises(ValueError):
        parse_ext_key(key_str)
    if "checksum" in reason:
        # the checksum case blows up on base58decode_check even if we don't validate
        pass
    else:
        bad_key = parse_ext_key(key_str, validate=False)
        if bad_key.is_public():
            passes = any(r in reason for r in ("prvkey version / pubkey mismatch",))

            with no_raise() if passes else pytest.raises(ValueError):
                CKDpriv(
                    private_key=bad_key.data,
                    chain_code=bad_key.chain_code,
                    child_number=int.from_bytes(bad_key.child_number, "big"),
                    depth=bad_key.depth,
                    version=bad_key.version,
                )
        else:
            passes = any(
                r in reason
                for r in (
                    "prvkey prefix 04",
                    "invalid prvkey prefix 01",
                    "zero depth",
                )
            )
            # TypeError because of https://github.com/tlsfuzzer/python-ecdsa/issues/341
            with no_raise() if passes else pytest.raises((ValueError, TypeError)):
                CKDpriv(
                    private_key=bad_key.data,
                    chain_code=bad_key.chain_code,
                    child_number=int.from_bytes(bad_key.child_number, "big"),
                    depth=bad_key.depth,
                    version=bad_key.version,
                )


@pytest.mark.parametrize(
    "key_str, reason",
    INVALID_KEYS,
    ids=[f"Vector-5-{reason[:32]}-{key[:8]}" for key, reason in INVALID_KEYS],
)
def test_ckdpub_invalid_keys(key_str: str, reason: str):
    with pytest.raises(ValueError):
        parse_ext_key(key_str)
    if "checksum" in reason:
        # the checksum case blows up on base58decode_check even if we don't validate
        pass
    else:
        bad_key = parse_ext_key(key_str, validate=False)
        if bad_key.is_public():
            passes = any(s in reason for s in ("zero depth",))
            with (
                pytest.raises((MalformedPointError, ValueError))
                if not passes
                else no_raise()
            ):
                CKDpub(
                    public_key=bad_key.data,
                    chain_code=bad_key.chain_code,
                    child_number=bad_key.child_number,
                    depth=bad_key.depth,
                    version=bad_key.version,
                    finger=bad_key.finger,
                )
        else:
            with pytest.raises((MalformedPointError, ValueError)):
                CKDpub(
                    public_key=bad_key.data,
                    chain_code=bad_key.chain_code,
                    child_number=bad_key.child_number,
                    depth=bad_key.depth,
                    version=bad_key.version,
                    finger=bad_key.finger,
                )


def test_ckd_pub_bad_child_number():
    key = parse_ext_key(
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    )
    with pytest.raises(ValueError, match="hardened"):
        CKDpub(
            public_key=key.data,
            chain_code=key.chain_code,
            child_number=TYPED_CHILD_KEY_COUNT.to_bytes(4, "big"),
            depth=key.depth,
            version=key.version,
            finger=key.finger,
        )


@contextlib.contextmanager
def no_raise():
    yield
