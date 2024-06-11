import contextlib
import logging

import pytest
from data.bip32_vectors import INVALID_KEYS, VECTORS
from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import INFINITY

from bipsea.bip32 import CKDpriv, to_master_key, validate_private_child_params, validate_public_child_params
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
        if "mismatch" not in reason:
            if bad_key.is_public():
                with pytest.raises(ValueError):
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
                with (
                    pytest.raises((ValueError, TypeError)) if not passes else no_raise()
                ):
                    CKDpriv(
                        private_key=bad_key.data,
                        chain_code=bad_key.chain_code,
                        child_number=int.from_bytes(bad_key.child_number, "big"),
                        depth=bad_key.depth,
                        version=bad_key.version,
                    )
    # TODO call CKDpriv, CKDpub, N() on these keys


@contextlib.contextmanager
def no_raise():
    yield
