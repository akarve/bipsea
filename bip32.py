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


def hmac_(key: bytes, data: bytes) -> bytes:
    return hmac.new(key=key, msg=data, digestmod="sha512").digest()


def to_master_key(seed: bytes, mainnet=True, private=False) -> ExtendedKey:
    master = hmac_(key=b"Bitcoin seed", data=seed)
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
        data=ecdsa_keys["ser_256"] if private else ecdsa_keys["ser_p"],
    )


def validate_derived_key(key: bytes) -> bool:
    assert len(key) == 64
    secret_key = key[:32]
    secret_int = int.from_bytes(secret_key, "big")
    if (secret_int == 0) or (secret_int >= SECP256k1.order):
        return False

    return True


def to_ecdsa_pair(secret_key: bytes):
    """ecdsa from_/to_string are actually from_/to_bytes b/c of some kind of
    Python 2 hangover"""
    private_key = SigningKey.from_string(secret_key, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    ser_p = public_key.to_string("compressed")
    ser_256 = bytes(1) + secret_key
    assert len(ser_p) == len(ser_256) == 33

    return {"ser_p": ser_p, "ser_256": ser_256}


def derive_key(master_seed: bytes, path: str, mainnet=True, private=False):
    segments = path.split("/")
    assert segments[0] == "m", "expected 'm' (private) at derivation path root"
    indexes = [segment_to_index(s) for s in segments[1:]]
    max_depth = len(indexes)
    if indexes:
        # if we're doing any derivation keep the private key
        parent_key = to_master_key(master_seed, mainnet=mainnet, private=True)
    else:
        return to_master_key(master_seed, mainnet=mainnet, private=private)
    for depth, (index, hardened) in enumerate(indexes, 1):
        # we implement the simplest algorithm: only use N() or CKDpub() at the
        # highest depth (final segment).
        # otherwise we would need to look ahead for the last hardened child
        # and use CKDpriv() up to that point (because hardened public children require
        # a private parent key) and such code would be hard to read
        last = depth == max_depth
        if last and not private:
            if hardened:
                parent_key = N(
                    parent_key.data,
                    parent_key.chain_code,
                    index,
                    depth,
                    mainnet=mainnet,
                )
            else:
                parent_key = CKDpub(
                    parent_key.data,
                    parent_key.chain_code,
                    index,
                    depth,
                    mainnet=mainnet,
                )
                assert parent_key == N(
                    parent_key.data,
                    parent_key.chain_code,
                    index,
                    depth,
                    mainnet=mainnet,
                ), "CKDpub() and N() should produce identical results for non-hardened public children"

        else:
            parent_key = CKDpriv(
                parent_key.data,
                parent_key.chain_code,
                index,
                depth,
                mainnet=mainnet,
            )

    return parent_key


def segment_to_index(segment: str) -> (bytes, bool):
    """for internal (non-m) derivation path segments which should all be integers
    once the optional hardened symbol is dropped"""
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
    master - bip32 extended key, base 58
    """
    master_dec = base58.b58decode_check(key, alphabet=base58.BITCOIN_ALPHABET)
    assert len(master_dec) == 78, "expected 78 bytes"

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
    data = parent_ecdsa_pair["ser_256"] if hardened else parent_ecdsa_pair["ser_p"]

    while True:
        derived = hmac_(key=chain_code, msg=data + index.to_bytes(4, "big"))
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
    private_key: bytes, chain_code: bytes, index: int, depth: int, mainnet: bool
) -> ExtendedKey:
    if index >= NORMAL_CHILD_KEY_COUNT:
        return ValueError("Must not invoke CKDpub() for hardened child")
    ecdsa_pair = to_ecdsa_pair(private_key)
    derived = hmac_(key=chain_code, msg=ecdsa_pair["ser_p"] + index.to_bytes(4, "big"))
    derived_left_int = int.from_bytes(derived[:32], "big")
    derived_chain_code = derived[32:]
    child_key = VerifyingKey.from_public_point(
        derived_left_int * SECP256k1.generator
        + VerifyingKey.from_string(ecdsa_pair["ser_p"], curve=SECP256k1).pubkey.point
    )

    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"]["public"],
        depth=depth.to_bytes(1, "big"),
        finger=fingerprint(derived[:32]),
        child_number=index.to_bytes(4, "big"),
        chain_code=derived_chain_code,
        data=child_key.to_string("compressed"),
    )


def N(
    private_key: bytes, chain_code: bytes, index: int, depth: int, mainnet: bool
) -> ExtendedKey:
    """neuter a private key into the public one (no derivation per se)"""
    ecdsa_pair = to_ecdsa_pair(private_key)

    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"]["public"],
        depth=depth.to_bytes(1, "big"),
        finger=fingerprint(private_key),
        child_number=index.to_bytes(4, "big"),
        chain_code=chain_code,
        data=ecdsa_pair["ser_p"],
    )


def fingerprint(private_key: bytes) -> bytes:
    ecdsa_pair = to_ecdsa_pair(private_key)
    pub_key = ecdsa_pair["ser_p"]
    sha256 = hashlib.sha256(pub_key).digest()
    ripemd = hashlib.new("ripemd160")
    ripemd.update(sha256)
    finger = ripemd.digest()[:4]

    return binascii.hexlify(finger)
