#!/usr/bin/python
"""Complete implementation of BIP-39 in Python with CLI
https://en.bitcoin.it/wiki/BIP_0039

TODO: CLI design:
(xprv or seed or entropy) | derivation path > output?
"""

import hashlib
import logging
import math
from unicodedata import normalize
from hashlib import pbkdf2_hmac
from typing import List
import secrets


from preseed import from_hex
from const import LOGGER


logger = logging.getLogger(LOGGER)


# https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
DICT_NAME = "english.txt"
DICT_HASH = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

N_MNEMONICS = 2048
N_WORD_BITS = 11
N_WORDS_ALLOWED = {12, 15, 18, 21, 24}


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
    if user_entropy and int_entropy:  # could have bytes but an int of 0
        approx_strength = math.ceil(math.log(int_entropy, 2))
        desired_strength = math.ceil(approx_strength / N_WORD_BITS)
        if approx_strength < desired_strength:
            logger.warning(
                f"{approx_strength} bits of entropy will be stretched to {desired_strength})"
            )

    entropy_hash = hashlib.sha256(int_entropy.to_bytes(n_entropy_bits // 8, "big"))
    int_checksum = int.from_bytes(entropy_hash.digest(), "big") >> (
        8 * entropy_hash.digest_size - n_checksum_bits  # cut hash down to CS-many bits
    )
    int_entropy_cs = (int_entropy << n_checksum_bits) + int_checksum  # shift CS bits in

    dictionary = file_to_array()  # get bip39 words from disk
    swords = []
    mask11 = N_MNEMONICS - 1  # mask lowest 11 bits
    for _ in range(n_words):
        idx = int_entropy_cs & mask11
        swords.append(dictionary[idx])
        int_entropy_cs >>= N_WORD_BITS
    assert int_entropy_cs == 0, "Unexpected unused entropy"
    swords.reverse()  # backwards is forwards because we started masking from the checksum end

    return swords


def file_to_array(file_name=DICT_NAME):
    with open(file_name, "rb") as source:
        raw = source.read()
    file_hash = hashlib.sha256()
    file_hash.update(raw)
    assert DICT_HASH == file_hash.hexdigest(), f"unexpected contents: {DICT_NAME}"
    dictionary = raw.decode().split("\n")[:-1]
    assert len(dictionary) == N_MNEMONICS, f"expected {N_MNEMONICS} words"

    return dictionary


def to_seed(mnemonic: List[str], passphrase, iterations=2048):
    mnemonic_nfkd = normalize("NFKD", " ".join(mnemonic)).encode("utf-8")
    salt_nfkd = normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")

    seed = pbkdf2_hmac(
        hash_name="sha512",
        password=mnemonic_nfkd,
        salt=salt_nfkd,
        iterations=iterations,
    )
    return seed


if __name__ == "__main__":
    entropy_to_words()
