#!/usr/bin/python
"""give you some ideas, man
https://en.bitcoin.it/wiki/BIP_0039
"""

import binascii
import hashlib
import math
from unicodedata import normalize
from hashlib import pbkdf2_hmac
import secrets

import click

# https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
DICT_NAME = "english.txt"
DICT_HASH = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

N_MNEMONICS = 2048
N_WORD_BITS = 11


@click.command()
@click.option("--nwords", default=12, type=click.IntRange(12, 24))
@click.option("--number/--no-number", help="Number the word list", default=False)
@click.option("--meta/--no-meta", help="Display entropy, checksum, seed", default=False)
@click.option(
    "--entropy",
    "user_entropy",
    type=int,
    default=None,
    help="Provide your own entropy as an int",
)
@click.option("--passphrase", type=str, default="", help="Optional BIP39 passphrase")
def gen_words(nwords, number, meta, user_entropy, passphrase):
    assert (nwords % 3) == 0, "--nwords must be divisible by 3"
    n_checksum_bits = nwords // 3  # CS in BIP39
    n_total_bits = nwords * N_WORD_BITS  # ENT+CS in BIP39
    n_entropy_bits = n_total_bits - n_checksum_bits  # ENT in BIP39
    assert (n_entropy_bits % 32) == 0, "Entropy bits must be a multiple of 32"
    assert (
        n_checksum_bits == n_entropy_bits // 32
    ), "Unexpected mismatch between checksum and entropy sizes"
    if user_entropy:
        strength = math.ceil(math.log(user_entropy, 2)) + 1
        implied = math.ceil(strength / N_WORD_BITS)
        print(f"Seed @ {strength} bits of entropy ({implied} words)")
    int_entropy = user_entropy if user_entropy else secrets.randbits(n_entropy_bits)
    entropy_hash = hashlib.sha256(int_entropy.to_bytes(n_entropy_bits // 8, "big"))
    # drop hash down to CS-many bits
    int_checksum = int.from_bytes(entropy_hash.digest(), "big") >> (
        8 * entropy_hash.digest_size - n_checksum_bits
    )
    # shift CS bits in
    int_entropy_cs = (int_entropy << n_checksum_bits) + int_checksum
    # get bip39 words from disk
    dictionary = dictionary_as_array()

    swords = []
    mask11 = N_MNEMONICS - 1  # mask lowest 11 bits
    for _ in range(nwords):
        idx = int_entropy_cs & mask11
        swords.append(dictionary[idx])
        int_entropy_cs >>= N_WORD_BITS
    assert int_entropy_cs == 0, "Unexpected unused entropy"
    swords.reverse()  # backwards is forwards because we started masking from the checksum end
    user_entropy = to_seed(swords, passphrase)
    if meta:
        print(f"ENT (int, {n_entropy_bits} bits) {int_entropy}")
        print(f"CS  (int, {n_checksum_bits}) {int_checksum}")
        print("SEED (hex)", user_entropy.hex())

    if number:
        for i, m in enumerate(swords):
            print(f"{i + 1}) {m}")
    else:
        print(" ".join(swords))


def dictionary_as_array(file_name=DICT_NAME):
    with open(file_name, "rb") as source:
        raw = source.read()
    file_hash = hashlib.sha256()
    file_hash.update(raw)
    assert DICT_HASH == file_hash.hexdigest(), f"unexpected contents: {DICT_NAME}"
    dictionary = raw.decode().split("\n")[:-1]
    assert len(dictionary) == N_MNEMONICS, f"expected {N_MNEMONICS} words"

    return dictionary


def to_seed(mnemonic, passphrase="", iterations=2048):
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
    gen_words()
