"""constants and utilities"""

import binascii
import logging
from hashlib import pbkdf2_hmac
from unicodedata import normalize as unicode_normalize

__version__ = "0.2.1"
__app_name__ = "bipsea"

FORMAT = "utf-8"
NFKD = "NFKD"
LOGGER = __app_name__


logger = logging.getLogger(LOGGER)


def to_hex_string(data: bytes) -> str:
    return binascii.hexlify(data).decode("utf-8")


def pbkdf2(
    mnemonic: str, passphrase: str, iterations: int = 2048, hash_name: str = "sha512"
) -> bytes:
    return pbkdf2_hmac(
        hash_name=hash_name,
        password=normalize(mnemonic),
        salt=normalize("mnemonic" + passphrase),
        iterations=iterations,
    )


def normalize(input: str) -> str:
    return unicode_normalize(NFKD, input).encode(FORMAT)
