import binascii

from ecdsa import SigningKey, SECP256k1

from bip32 import ExtendedKey, hmac_sha512


HMAC_KEY = b"bip-entropy-from-k"


def to_entropy(data: bytes) -> bytes:
    return hmac_sha512(key=HMAC_KEY, data=data)


def derive_key(master: str, path: str):
    pass


def to_hex_string(data: bytes) -> str:
    return binascii.hexlify(data).decode("utf-8")
