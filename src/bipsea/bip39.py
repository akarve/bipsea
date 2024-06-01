"""Complete BIP-39 implementation"""

import hashlib
import logging
import secrets
import warnings
from hashlib import pbkdf2_hmac
from importlib import resources
from typing import List
from unicodedata import normalize

import click

from .util import LOGGER

logger = logging.getLogger(LOGGER)


# https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
WORDS_FILE_NAME = "english.txt"
WORDS_FILE_HASH = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

N_MNEMONICS = 2048
N_WORD_BITS = 11
N_WORDS_ALLOWED = [12, 15, 18, 21, 24]
N_WORDS_META = {
    n_words: {
        "checksum_bits": n_words // 3,  # CS in BIP-39
        "total_bits": n_words * N_WORD_BITS,  # ENT+CS in BIP-39
        "entropy_bits": (n_words * N_WORD_BITS) - (n_words // 3),  # ENT in BIP-39
    }
    for n_words in N_WORDS_ALLOWED
}


def entropy_to_words(n_words: int, user_entropy: bytes):
    """If caller does not provide entropy use secrets.randbits
    * Only produces seed words in English"""
    if n_words not in N_WORDS_ALLOWED:
        raise ValueError(f"n_words must be one of {N_WORDS_ALLOWED}")

    n_checksum_bits = N_WORDS_META[n_words]["checksum_bits"]
    n_entropy_bits = N_WORDS_META[n_words]["entropy_bits"]
    int_entropy = (
        int.from_bytes(user_entropy, "big")
        if user_entropy
        else secrets.randbits(n_entropy_bits)
    )
    difference = int_entropy.bit_length() - n_entropy_bits
    if difference > 0:
        int_entropy >>= difference
    elif difference <= -8:
        warnings.warn(
            (
                f"Warning: {difference + n_entropy_bits} bits in, {n_entropy_bits} bits out."
                " Input more entropy?"
            )
        )

    entropy_hash = hashlib.sha256(int_entropy.to_bytes(n_entropy_bits // 8, "big"))
    int_checksum = int.from_bytes(entropy_hash.digest(), "big") >> (
        8 * entropy_hash.digest_size - n_checksum_bits  # cut hash down to CS-many bits
    )
    int_entropy_cs = (int_entropy << n_checksum_bits) + int_checksum  # shift CS bits in

    dictionary = bip39_english_words()  # get bip39 words from disk
    swords = []
    mask11 = N_MNEMONICS - 1  # mask lowest 11 bits
    for _ in range(n_words):
        idx = int_entropy_cs & mask11
        swords.append(dictionary[idx])
        int_entropy_cs >>= N_WORD_BITS

    assert int_entropy_cs == 0, "Unexpected unused entropy"
    swords.reverse()  # backwards is forwards because we started masking from the checksum end

    return swords


def verify_seed_words(language, words: List[str]) -> bool:
    """verify the seed words are in the english bip-39 dict and have the right checksum"""
    if language != "english":
        raise NotImplementedError(f"{language} not supported")
    n_words = len(words)

    if n_words not in N_WORDS_ALLOWED:
        return False

    universe = bip39_english_words()
    if not all(w in universe for w in words):
        return False

    n_entropy_bits = N_WORDS_META[n_words]["entropy_bits"]
    bin_indexes = [bin(universe.index(w))[2:].zfill(N_WORD_BITS) for w in words]
    bin_string = "".join(bin_indexes)
    n_checksum_bits = N_WORDS_META[n_words]["checksum_bits"]
    int_entropy = int(bin_string[:-n_checksum_bits], 2)
    int_checksum = int(bin_string[-n_checksum_bits:], 2)

    entropy_hash = hashlib.sha256(int_entropy.to_bytes(n_entropy_bits // 8, "big"))
    checksum = int.from_bytes(entropy_hash.digest(), "big") >> (
        8 * entropy_hash.digest_size - n_checksum_bits
    )

    return checksum == int_checksum


def bip39_english_words(file_name=WORDS_FILE_NAME) -> List[str]:
    """Returns a list of BIP39 English words."""
    with resources.open_text("bipsea", file_name) as f:
        raw = f.read()
    file_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert file_hash == WORDS_FILE_HASH, f"unexpected contents in {file_name}"
    dictionary = raw.splitlines()
    assert (
        len(dictionary) == N_MNEMONICS == len(set(dictionary))
    ), "expected {} unique words".format(N_MNEMONICS)

    return dictionary


def to_master_seed(mnemonic: List[str], passphrase, iterations=2048):
    """converts english mnemonics to all lower case"""
    mnemonic = [m.lower() for m in mnemonic]
    mnemonic_nfkd = normalize("NFKD", " ".join(m.lower() for m in mnemonic)).encode(
        "utf-8"
    )
    salt_nfkd = normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")

    return pbkdf2_hmac(
        hash_name="sha512",
        password=mnemonic_nfkd,
        salt=salt_nfkd,
        iterations=iterations,
    )
