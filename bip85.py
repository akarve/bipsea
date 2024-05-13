import os
import hmac
import hashlib

import base58
from ecdsa import SigningKey, SECP256k1

from bip32 import ExtendedKey


# INPUT:
# * MASTER BIP32 ROOT KEY: xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb
# * PATH: m/83696968'/0'/0'

# OUTPUT:
# * DERIVED KEY=cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0
# * DERIVED ENTROPY=efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7


def derive_key(master: str, path: str):
    pass
