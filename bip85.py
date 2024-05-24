import binascii
import hashlib

from ecdsa import SigningKey, SECP256k1

from bip32 import ExtendedKey, hmac_sha512


HMAC_KEY = b"bip-entropy-from-k"
ENTROPY_CODES = {
    "12 words": {"entropy_bits": 128, "code": "12'"},
    "18 words": {"entropy_bits": 192, "code": "18'"},
    "24 words": {"entropy_bits": 256, "code": "24'"},
}
LANGUAGE_CODES = {
    "English": "0'",
    "Japanese": "1'",
    "Korean": "2'",
    "Spanish": "3'",
    "Chinese (Simplified)": "4'",
    "Chinese (Traditional)": "5'",
    "French": "6'",
    "Italian": "7'",
    "Czech": "8'",
}


def to_entropy(data: bytes) -> bytes:
    return hmac_sha512(key=HMAC_KEY, data=data)


def derive_key(master: str, path: str):
    pass


def to_hex_string(data: bytes) -> str:
    return binascii.hexlify(data).decode("utf-8")


class DRNG:
    def __init__(self, seed: bytes):
        if len(seed) != 64:
            raise ValueError("Seed must be exactly 64 bytes long")
        self.shake = hashlib.shake_256(seed)
        self.cursor = 0

    def read(self, n: int) -> bytes:
        start = self.cursor
        self.cursor = stop = start + n

        return self.shake.digest(stop)[start:stop]
