import binascii
import hashlib
import hmac
from collections import namedtuple
import re
from typing import Dict

import base58
from ecdsa import SigningKey, SECP256k1, VerifyingKey

"""
# in readme summarize each
# put it all together
# cards and entropy
# CLI for 85 :yay:
# clean out seed etc over-printing in seedwords
# say name cli commands by bip?

https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki HDW
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki Seed words
https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki Derivation paths
https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki Entropy
"""


class ExtendedKey(
    namedtuple(
        "ExtendedKey",
        [
            "version",
            "depth",
            "finger",
            "child_number",
            "chain_code",
            "data",
        ],
    )
):
    def __str__(self):
        # return super().__str__()
        key_ = (
            self.version
            + self.depth
            + self.finger
            + self.child_number
            + self.chain_code
            + self.data
        )
        return base58.b58encode_check(key_, alphabet=base58.BITCOIN_ALPHABET).decode()


# HARDENED_CHILD_KEY_COUNT = 2**31 (as comment for clarity)
NORMAL_CHILD_KEY_COUNT = 2**31

VERSIONS = {
    "mainnet": {
        "public": bytes.fromhex("0488B21E"),
        "private": bytes.fromhex("0488ADE4"),
    },
    "testnet": {
        "public": bytes.fromhex("043587CF"),
        "private": bytes.fromhex("04358394"),
    },
}


def to_extended_master(seed: bytes, mainnet=True, private=False) -> ExtendedKey:
    master = hmac.new(key=b"Bitcoin seed", msg=seed, digestmod="sha512").digest()
    if not validate_derived_key(master):
        raise ValueError("Invalid master key")

    secret_key = master[:32]
    chain_code = master[32:]

    ecdsa_keys = to_ecdsa_pair(secret_key)
    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"][
            "private" if private else "public"
        ],
        depth=bytes(1),
        finger=bytes(4),
        child_number=bytes(4),
        chain_code=chain_code,
        data=ecdsa_keys["ser_256"]
        if private
        else ecdsa_keys["ser_p"].to_string("compressed"),
    )


def validate_derived_key(key: bytes) -> bool:
    assert len(key) == 64
    secret_key = key[:32]
    secret_int = int.from_bytes(secret_key, "big")
    if (secret_int == 0) or (secret_int >= SECP256k1.order):
        return False

    return True


def to_ecdsa_pair(secret_key: bytes):
    private_key = SigningKey.from_secret_exponent(
        int.from_bytes(secret_key, "big"), curve=SECP256k1
    )

    public_key = private_key.get_verifying_key()
    ser_p = public_key
    ser_256 = bytes(1) + secret_key
    assert len(ser_p.to_string("compressed")) == len(ser_256) == 33

    return {"ser_p": ser_p, "ser_256": ser_256}


def derive_key(seed: bytes, path: str, mainnet=True, private=False):
    segments = path.split("/")
    for depth, segment in enumerate(segments):
        if depth == 0:
            key = to_extended_master(seed, mainnet=mainnet, private=private)
        else:
            index, hardened = segment_to_index(segment)
            if private:
                key = CKDpriv(
                    key.data,
                    key.chain_code,
                    index,
                    depth,
                    mainnet=mainnet,
                )
            else:
                # TODO unit test proving the two are equivalent when they should be
                if hardened:
                    key = N(
                        key.data,
                        key.chain_code,
                        index,
                        depth,
                        mainnet=mainnet,
                    )
                else:
                    key = CKDpub(
                        key.data,
                        key.chain_code,
                        index,
                        depth,
                        mainnet=mainnet,
                    )

    return key


def segment_to_index(segment: str) -> (bytes, bool):
    hardened = segment[-1] in {"h", "H", "'"}
    if hardened:
        segment = segment[:-1]
    index = int(segment)
    assert index <= (NORMAL_CHILD_KEY_COUNT - 1)
    if hardened:
        index += NORMAL_CHILD_KEY_COUNT

    return (index, hardened)


def parse_ext_key(key: str):
    """
    master - master bip32 root (extended) key, base 58
    """
    master_dec = base58.b58decode_check(
        key,
        alphabet=base58.BITCOIN_ALPHABET,
    )
    assert len(master_dec) == 78, "expected 78 bytes"
    # serialization order
    # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    key = ExtendedKey(
        version=master_dec[:4],
        depth=master_dec[4:5],  # slice so we get bytes, not an int
        finger=master_dec[5:9],
        child_number=master_dec[9:13],
        chain_code=master_dec[13:45],
        data=master_dec[45:],
    )

    assert key.version in (
        set(VERSIONS["mainnet"].values()) | set(VERSIONS["testnet"].values())
    )
    assert len(key.version) == 4
    assert len(key.finger) == len(key.child_number) == 4
    assert len(key.data) - 1 == 32 == len(key.chain_code)

    return key


def CKDpriv(
    secret_key: bytes,
    chain_code: bytes,
    index: int,
    depth: int,
    mainnet: bool,
) -> ExtendedKey:
    hardened = index >= NORMAL_CHILD_KEY_COUNT
    parent_ecdsa_pair = to_ecdsa_pair(secret_key)
    data = (
        parent_ecdsa_pair["ser_256"]
        if hardened
        else parent_ecdsa_pair["ser_p"].to_string("compressed")
    )

    while True:
        derived = hmac.new(
            key=chain_code,
            msg=data + index.to_bytes(4, "big"),
            digestmod=hashlib.sha512,
        )
        if validate_derived_key(derived):
            break
        else:
            index += 1
            if hardened:
                assert index < 2**32
            else:
                assert index < NORMAL_CHILD_KEY_COUNT

    derived_secret_int = int.from_bytes(derived[:32], "big")
    derived_chain_code = derived[32:]
    child_key = (
        derived_secret_int + int.from_bytes(secret_key, "big")
    ) % SECP256k1.order

    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"]["private"],
        depth=depth.to_bytes(1, "big"),
        finger=fingerprint(child_key),
        child_number=index.to_bytes(4, "big"),
        chain_code=derived_chain_code,
        data=child_key,
    )


def CKDpub(
    key: bytes, chain_code: bytes, index: int, depth: int, mainnet: bool
) -> ExtendedKey:
    if index >= NORMAL_CHILD_KEY_COUNT:
        return ValueError("Must not invoke CKDpub() for hardened child")
    ecdsa_pair = to_ecdsa_pair(key)
    derived = hmac.new(
        key=chain_code,
        msg=ecdsa_pair["ser_p"].to_string("compressed") + index.to_bytes(4, "big"),
        digestmod=hashlib.sha512,
    )

    derived_left_int = int.from_bytes(derived[:32], "big")
    derived_chain_code = derived[32:]
    child_key = VerifyingKey.from_public_point(
        derived_left_int * SECP256k1.generator + ecdsa_pair["ser_p"]
    )

    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"]["public"],
        depth=depth.to_bytes(1, "big"),
        finger=fingerprint(child_key),
        child_number=index.to_bytes(4, "big"),
        chain_code=derived_chain_code,
        data=child_key,
    )


def N(
    key: bytes, chain_code: bytes, index: int, depth: int, mainnet: bool
) -> ExtendedKey:
    """neuter a private key into the public one (no derivation per se)"""
    ecdsa_pair = ecdsa_pair(key)

    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"]["public"],
        depth=depth.to_bytes(1, "big"),
        finger=fingerprint(key),
        child_number=index.to_bytes(4, "big"),
        chain_code=chain_code,
        data=ecdsa_pair["ser_p"],
    )


def fingerprint(secret_key: bytes) -> bytes:
    ecdsa_pair = to_ecdsa_pair(secret_key)
    pub_key = ecdsa_pair["ser_p"]
    sha256 = hashlib.sha256(pub_key).digest()
    ripemd = hashlib.new("ripemd160")
    ripemd.update(sha256)
    finger = ripemd.digest()[:4]

    return binascii.hexlify(finger)
