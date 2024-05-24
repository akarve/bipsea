"""
Mnemonic is only used a testing oracle in certain cases and is not
part of our implementation.
"""
import hashlib
import logging
import re
from unicodedata import is_normalized


import pytest
import requests
from seedwords import DICT_HASH, entropy_to_words, N_MNEMONICS, to_seed
from preseed import from_hex
from const import LOGGER
from data.bip39_vectors import VECTORS


logger = logging.getLogger(LOGGER)

WORD_COUNTS = {12, 15, 18, 21, 24}


@pytest.mark.parametrize(
    "language, vectors", VECTORS.items(), ids=[l for l in VECTORS.keys()]
)
def test_vectors(language, vectors):
    logger.info(language)
    for vector in vectors:
        entropy_str, mnemonic, seed, xprv = vector
        entropy_bytes = from_hex(entropy_str)
        expected_words = re.split(r"\s", mnemonic)
        expected_seed = from_hex(seed)
        computed_seed = to_seed(expected_words, passphrase="TREZOR")
        assert expected_seed == computed_seed

        if language == "english":
            computed_words = entropy_to_words(
                len(expected_words), user_entropy=entropy_bytes, passphrase="TREZOR"
            )
            assert expected_words == computed_words


@pytest.mark.network
def test_words_in_bip39_wordlist():
    """make sure we match github"""
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    response = requests.get(url)
    wordlist = response.text.split()
    assert all(is_normalized("NFKD", w) for w in wordlist)
    assert len(wordlist) == N_MNEMONICS
    response_hash = hashlib.sha256(response.content).hexdigest()
    assert response_hash == DICT_HASH, f"Hash mismatch: {response_hash} != {DICT_HASH}"
