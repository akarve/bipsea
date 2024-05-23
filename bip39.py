from unicodedata import normalize as unicode_normalize
from hashlib import pbkdf2_hmac


FORMAT = "utf-8"
NFKD = "NFKD"


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
