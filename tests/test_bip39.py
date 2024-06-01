import hashlib
import logging
import re
import warnings
from unicodedata import is_normalized

import pytest
import requests
from data.bip39_vectors import VECTORS

from bipsea.bip32 import to_master_key
from bipsea.bip39 import (
    N_MNEMONICS,
    N_WORDS_META,
    WORDS_FILE_HASH,
    entropy_to_words,
    to_master_seed,
    verify_seed_words,
)
from bipsea.util import LOGGER

logger = logging.getLogger(LOGGER)


@pytest.mark.parametrize(
    "language, vectors", VECTORS.items(), ids=[l for l in VECTORS.keys()]
)
def test_vectors(language, vectors):
    for vector in vectors:
        _, mnemonic, seed, xprv = vector
        expected_seed = bytes.fromhex(seed)
        expected_words = re.split(r"\s", mnemonic)
        computed_seed = to_master_seed(expected_words, passphrase="TREZOR")
        assert expected_seed == computed_seed
        assert computed_seed != to_master_seed(expected_words, passphrase="TREZOr")
        computed_xprv = to_master_key(expected_seed, mainnet=True, private=True)
        assert str(computed_xprv) == xprv
        if language == "english":
            assert verify_seed_words(language, expected_words)


def test_meta():
    """Computed BIP-39 table with ENT, CS, ENT+CS"""
    for k, v in N_WORDS_META.items():
        assert (v["entropy_bits"] % 32) == 0, "Entropy bits must be a multiple of 32"
        assert (
            v["checksum_bits"] == v["entropy_bits"] // 32
        ), "Unexpected mismatch between checksum and entropy sizes"


def test_verify_checksum():
    correct = (
        "noodle life devote warm sponsor truck ship safe race noble royal proof".split(
            " "
        )
    )
    assert verify_seed_words("english", correct)
    assert not verify_seed_words("english", correct[:-1])
    assert not verify_seed_words("english", correct[:-1] + ["mix"])


@pytest.mark.parametrize(
    "language, vectors", VECTORS.items(), ids=[l for l in VECTORS.keys()]
)
def test_seed_word_generation(language, vectors):
    for vector in vectors:
        entropy_str, mnemonic = vector[:2]
        if language == "english":
            expected_words = re.split(r"\s", mnemonic)
            entropy_bytes = bytes.fromhex(entropy_str)
            if all(b == 0 for b in entropy_bytes):
                warnings.simplefilter("ignore")
            computed_words = entropy_to_words(
                len(expected_words), user_entropy=entropy_bytes
            )
            assert expected_words == computed_words
            assert verify_seed_words("english", computed_words)
        else:
            pytest.skip(f"{language} not supported")


@pytest.mark.network
def test_words_in_bip39_wordlist():
    """make sure we match github"""
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    response = requests.get(url)
    wordlist = response.text.split()
    assert all(is_normalized("NFKD", w) for w in wordlist)
    assert len(wordlist) == N_MNEMONICS
    response_hash = hashlib.sha256(response.content).hexdigest()
    assert (
        response_hash == WORDS_FILE_HASH
    ), f"Hash mismatch: {response_hash} != {WORDS_FILE_HASH}"
