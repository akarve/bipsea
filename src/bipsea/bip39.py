"""Complete BIP-39 implementation"""

import hashlib
import logging
import secrets
import warnings
from hashlib import pbkdf2_hmac

try:
    from importlib.resources import files
except ImportError:
    from importlib_resources import files  # for Python 3.8

from typing import List
from unicodedata import normalize

from .util import LOGGER_NAME, __app_name__

logger = logging.getLogger(LOGGER_NAME)


LANGUAGES = {
    # https://github.com/bitcoin/bips/tree/master/bip-0039
    "chinese_simplified": {
        "file": "chinese_simplified.txt",
        "hash": "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
        # https://en.wikipedia.org/wiki/List_of_ISO_639_language_codes
        # we add -sim and -tra (not an iso convention)
        "code": "zho-sim",
    },
    "chinese_traditional": {
        "file": "chinese_traditional.txt",
        "hash": "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f",
        "code": "zho-tra",
    },
    "czech": {
        "file": "czech.txt",
        "hash": "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc",
        "code": "ces",
    },
    "english": {
        "file": "english.txt",
        "hash": "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
        "code": "eng",
    },
    "french": {
        "file": "french.txt",
        "hash": "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59",
        "code": "fra",
    },
    "italian": {
        "file": "italian.txt",
        "hash": "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
        "code": "ita",
    },
    "japanese": {
        "file": "japanese.txt",
        "hash": "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd",
        "code": "jpn",
    },
    "korean": {
        "file": "korean.txt",
        "hash": "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60",
        "code": "kor",
    },
    "portuguese": {
        "file": "portuguese.txt",
        "hash": "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f",
        "code": "por",
    },
    "spanish": {
        "file": "spanish.txt",
        "hash": "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b",
        "code": "spa",
    },
}

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


def entropy_to_words(n_words: int, user_entropy: bytes, language: str):
    """If caller does not provide entropy use secrets.randbits"""
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
    # only warn if the user provided the entropy (always trust randbits)
    elif user_entropy and (difference <= -8):
        warnings.warn(
            (
                f"{difference + n_entropy_bits} bits in, {n_entropy_bits} bits out."
                " Input more entropy?"
            )
        )

    entropy_hash = hashlib.sha256(int_entropy.to_bytes(n_entropy_bits // 8, "big"))
    int_checksum = int.from_bytes(entropy_hash.digest(), "big") >> (
        8 * entropy_hash.digest_size - n_checksum_bits  # cut hash down to CS-many bits
    )
    int_entropy_cs = (int_entropy << n_checksum_bits) + int_checksum  # shift CS bits in

    dictionary = bip39_words(language)
    swords = []
    mask_11 = N_MNEMONICS - 1
    for _ in range(n_words):
        idx = int_entropy_cs & mask_11
        swords.append(dictionary[idx])
        int_entropy_cs >>= N_WORD_BITS

    assert int_entropy_cs == 0, "Unexpected unused entropy"
    swords.reverse()  # backwards is forwards because we started masking from the checksum end

    return swords


def validate_mnemonic_words(words: List[str], language: str) -> bool:
    """verify the seed words are in the english bip-39 dict and have the right checksum"""
    n_words = len(words)

    if n_words not in N_WORDS_ALLOWED:
        return False

    universe = bip39_words(language)
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


def bip39_words(language) -> List[str]:
    """Returns a list of BIP-39 words in the given language"""
    if language not in LANGUAGES:
        raise ValueError(f"Unexpected language: {language}")
    file_name = LANGUAGES[language]["file"]
    list_path = files(__app_name__) / "wordlists" / file_name
    with list_path.open("r") as f:
        raw = f.read()

    return raw.splitlines()


def normalize_str(input: str, lower=False):
    return normalize("NFKD", input.lower() if lower else input)


def normalize_list(words: List[str], lower=False):
    """lower() then nfkd()"""
    return [normalize_str(w, lower) for w in words]


def to_master_seed(mnemonic: List[str], passphrase, iterations=2048):
    """apply pbkdf2"""
    mnemonic_nfkd = " ".join(normalize_list(mnemonic, lower=True)).encode("utf-8")
    salt_nfkd = normalize_str("mnemonic" + passphrase).encode("utf-8")

    return pbkdf2_hmac(
        hash_name="sha512",
        password=mnemonic_nfkd,
        salt=salt_nfkd,
        iterations=iterations,
    )
