#!/usr/bin/python
"""Complete BIP-39 implementation"""

import hashlib
import logging
import secrets
import warnings
from hashlib import pbkdf2_hmac
from typing import List
from unicodedata import normalize

import click

from .util import LOGGER

logger = logging.getLogger(LOGGER)


# https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
DICT_NAME = "english.txt"
DICT_HASH = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

N_MNEMONICS = 2048
N_WORD_BITS = 11
N_WORDS_ALLOWED = [12, 15, 18, 21, 24]


def entropy_to_words(n_words: int, user_entropy: bytes, passphrase: bytes = b""):
    """* If the caller does not provide entropy use secrets.randbits to generate it
    * Only produces seed words in English"""
    if n_words not in N_WORDS_ALLOWED:
        raise ValueError(f"n_words must be one of {N_WORDS_ALLOWED}")
    n_checksum_bits = n_words // 3  # CS in BIP39
    n_total_bits = n_words * N_WORD_BITS  # ENT+CS in BIP39
    n_entropy_bits = n_total_bits - n_checksum_bits  # ENT in BIP39
    assert (n_entropy_bits % 32) == 0, "Entropy bits must be a multiple of 32"
    assert (
        n_checksum_bits == n_entropy_bits // 32
    ), "Unexpected mismatch between checksum and entropy sizes"

    int_entropy = (
        int.from_bytes(user_entropy, "big")
        if user_entropy
        else secrets.randbits(n_entropy_bits)
    )
    difference = int_entropy.bit_length() - n_entropy_bits
    if difference > 0:
        int_entropy >>= difference
    elif difference <= -8:
        warn_stretching(difference + n_entropy_bits, n_entropy_bits)

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


def bip39_english_words(file_name=DICT_NAME) -> List[str]:
    """returns a set or array of bip39 english words"""
    with open(file_name, "rb") as source:
        raw = source.read()
    file_hash = hashlib.sha256()
    file_hash.update(raw)
    assert DICT_HASH == file_hash.hexdigest(), f"unexpected contents: {DICT_NAME}"
    dictionary = raw.decode().split("\n")[:-1]
    assert (
        len(dictionary) == N_MNEMONICS == len(set(dictionary))
    ), f"expected {N_MNEMONICS} words"

    return dictionary


def to_master_seed(mnemonic: List[str], passphrase, iterations=2048):
    """converts english mnemonics to all lower case"""
    mnemonic = [m.lower() for m in mnemonic]
    assert set(mnemonic)
    mnemonic_nfkd = normalize("NFKD", " ".join(mnemonic)).encode("utf-8")
    salt_nfkd = normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")

    seed = pbkdf2_hmac(
        hash_name="sha512",
        password=mnemonic_nfkd,
        salt=salt_nfkd,
        iterations=iterations,
    )
    return seed


def warn_stretching(given: int, target: int, cli: bool = False):
    msg = f"Warning: {given} bits in, {target} bits out. Input more entropy."
    if cli:
        click.secho(msg, fg="yellow", err=True)
    else:
        warnings.warn(msg)


if __name__ == "__main__":
    entropy_to_words()
