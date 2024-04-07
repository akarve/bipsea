#!/usr/bin/python
"""give you some ideas, man
https://en.bitcoin.it/wiki/BIP_0039
"""

import binascii
import hashlib
import math
import secrets

import click

# https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
FILE_NAME = "english.txt"
FILE_HASH = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

N_MNEMONICS = 2048
N_WORD_BITS = 11


@click.command()
@click.option("--wordcount", default=12, type=click.IntRange(12, 24))
@click.option(
    "--number/--no-number", help="Print numbers before seed words", default=False
)
@click.option(
    "--index/--no-index",
    help="Display 1-indexed position in list instead of the word itself",
    default=False,
)
@click.option(
    "--entropy/--no-entropy", help="Display entropy & checksum in binary", default=False
)
@click.option(
    "--seed", type=int, default=None, help="Use a specific seed for generating words"
)
def seed(wordcount, number, index, entropy, seed):
    assert (wordcount % 3) == 0, "--wordcount must be divisible by 3"
    n_checksum_bits = wordcount // 3  # CS in BIP39
    n_total_bits = wordcount * N_WORD_BITS  # ENT+CS in BIP39
    n_entropy_bits = n_total_bits - n_checksum_bits  # ENT in BIP39
    assert (n_entropy_bits % 32) == 0, "Entropy bits must be a multiple of 32"
    assert (
        n_checksum_bits == n_entropy_bits // 32
    ), "Unexpected mismatch between checksum and entropy sizes"
    if seed:
        strength = math.ceil(math.log(seed, 2)) + 1
        implied = math.ceil(strength / N_WORD_BITS)
        print(f"Seed @ {strength} bits of entropy ({implied} words)")
    # strong entropy https://docs.python.org/3/library/secrets.html
    int_entropy = seed if seed else secrets.randbits(n_entropy_bits)
    # format to fixed width hex since entropy may have leading 0s
    form = "{:0{width}x}"
    str_entropy_hex = form.format(
        int_entropy, width=str(n_entropy_bits // 4)
    )  # 4 bits per hex char
    str_entropy_hash = hashlib.sha256(binascii.unhexlify(str_entropy_hex)).hexdigest()
    # grab the first two hex chars; BIP39 never needs more than 8 bits
    str_checksum_hex = str_entropy_hash[:2]
    int_checksum_bits = int(str_checksum_hex, 16)
    # drop down to CS-many bits
    int_checksum_bits >>= 8 - n_checksum_bits
    # make room for CS bits and add them
    int_entropy_cs = (int_entropy << n_checksum_bits) + int_checksum_bits
    if entropy:
        print(f"ENT (int) {int_entropy}")
        print(
            "ENT ({width} bits) {:0{width}b}".format(int_entropy, width=n_entropy_bits)
        )
        print(
            "CS  ({width}) {:0{width}b}".format(
                int_checksum_bits,
                width=n_checksum_bits,
            )
        )
    # get mnemonics into memory
    with open(FILE_NAME, "rb") as source:
        raw = source.read()
    file_hash = hashlib.sha256()
    file_hash.update(raw)
    assert FILE_HASH == file_hash.hexdigest(), f"unexpected contents: {FILE_NAME}"
    words = raw.decode().split("\n")[:-1]  # chop trailing newline
    assert len(words) == N_MNEMONICS, f"expected {N_MNEMONICS} words"
    mnemonic = []
    # mask for lowest 11 bits
    mask11 = N_MNEMONICS - 1
    for _ in range(wordcount):
        idx = int_entropy_cs & mask11
        mnemonic.append(str(idx + 1) if index else words[idx])
        int_entropy_cs >>= N_WORD_BITS
    assert int_entropy_cs == 0, "Unexpected unused entropy"
    # read backwards since we started masking from the checksum end
    mnemonic.reverse()
    if number:
        for i, m in enumerate(mnemonic):
            print(f"{i + 1}) {m}")
    else:
        print(" ".join(mnemonic))


if __name__ == "__main__":
    seed()
