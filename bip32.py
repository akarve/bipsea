import binascii
import hashlib
import hmac
from collections import namedtuple
import re
from typing import Dict

import base58
from ecdsa import SigningKey, SECP256k1

"""
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
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
    net = "mainnet" if mainnet else "testnet"
    return ExtendedKey(
        version=VERSIONS[net]["private" if private else "public"],
        depth=bytes(1),
        finger=bytes(4),
        child_number=bytes(4),
        chain_code=chain_code,
        data=ecdsa_keys["ser_256"] if private else ecdsa_keys["ser_p"],
    )


def validate_derived_key(key: bytes) -> bool:
    assert len(key) == 64
    secret_key = key[:32]
    secret_int = int.from_bytes(secret_key, "big")
    if (secret_int == 0) or (secret_int >= SECP256k1.order):
        return False


def to_ecdsa_pair(secret_key: bytes):
    private_key = SigningKey.from_secret_exponent(
        int.from_bytes(secret_key, "big"), curve=SECP256k1
    )

    public_key = private_key.get_verifying_key()
    ser_p = public_key.to_string("compressed")
    ser_256 = bytes(1) + secret_key
    assert len(ser_p) == len(ser_256) == 33

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
                    private=private,
                )
            else:
                if hardened:
                    key = N(
                        key.data,
                        key.chain_code,
                        index,
                        depth,
                        mainnet=mainnet,
                        private=private,
                    )
                else:
                    key = CKDpub(
                        key.data,
                        key.chain_code,
                        index,
                        depth,
                        mainnet=mainnet,
                        private=private,
                    )

    return key


def segment_to_index(segment: str) -> (bytes, bool):
    hardened = segment[-1] in {"h", "H", "'"}
    segment = segment[:-1] if hardened else segment
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
    private: bool,
) -> ExtendedKey:
    hardened = index >= NORMAL_CHILD_KEY_COUNT
    parent_ecdsa_pair = to_ecdsa_pair(secret_key)
    data = parent_ecdsa_pair["ser_256"] if hardened else parent_ecdsa_pair["ser_p"]

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

    secret_key = derived[:32]
    chain_code = derived[32:]

    ecdsa_pair = to_ecdsa_pair(secret_key)
    net = "mainnet" if mainnet else "testnet"
    return ExtendedKey(
        version=VERSIONS[net]["private" if private else "public"],
        depth=depth.to_bytes(1, "big"),
        finger=bytes(4),  # TODO RIPEMD
        child_number=index.to_bytes(4, "big"),
        chain_code=chain_code,
        data=ecdsa_pair["ser_256"] if private else ecdsa_pair["ser_p"],
    )


def CKDpub(
    key: bytes, chain_code: bytes, index: int, depth: int, mainnet: bool, private: bool
) -> ExtendedKey:
    raise NotImplementedError("not yet")


def N(
    key: bytes, chain_code: bytes, index: int, depth: int, mainnet: bool, private: bool
) -> ExtendedKey:
    """neuter"""
    raise NotImplementedError("not yet")


def fingerprint(secret_key: bytes) -> bytes:
    ecdsa_pair = to_ecdsa_pair(secret_key)
    pub_key = ecdsa_pair["ser_p"]
    sha2 = hashlib.sha256(pub_key).digest()
    ripemd = hashlib.new("ripemd160")
    ripemd.update(sha2)
    finger = ripemd160_hash.digest()[:4]

    return binascii.hexlify(finger)
