"""
Complete implementation of BIP-32 hierarchical deterministic wallets.
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki HDW
"""

import hashlib
import hmac
import logging
import warnings
from typing import List

from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.keys import MalformedPointError

from .bip32types import VERSIONS, ExtendedKey
from .util import LOGGER

logger = logging.getLogger(LOGGER)


# same count for hardened and unhardened children
TYPED_CHILD_KEY_COUNT = 2**31


def to_master_key(seed: bytes, mainnet: bool, private: bool) -> ExtendedKey:
    master = hmac_sha512(key=b"Bitcoin seed", data=seed)
    secret_key = master[:32]
    chain_code = master[32:]
    pub_key = to_public_key(bytes(1) + secret_key)

    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"][
            "private" if private else "public"
        ],
        depth=bytes(1),
        finger=bytes(4),
        child_number=bytes(4),
        chain_code=chain_code,
        data=bytes(1) + secret_key if private else pub_key,
    )


def derive_key(master: ExtendedKey, path: List[str], private: bool):
    indexes = [segment_to_index(s) for s in path[1:]]
    key_chain = [
        (
            master
            if indexes or private
            else N(
                master.data,
                master.chain_code,
                master.child_number,
                depth=bytes(1),
                finger=master.finger,
                version=VERSIONS[master.get_network()]["public"],
            )
        )
    ]
    for depth, (index, _) in enumerate(indexes, 1):
        parent = key_chain[-1]
        key_chain.append(
            CKDpriv(
                parent.data,
                parent.chain_code,
                index,
                depth.to_bytes(1, "big"),
                version=parent.version,
            )
        )
    # only use N() or CKDpub() if public at the highest depth (final segment)
    # so as to avoid complex, hard-to-read flow control with look-ahead since once
    # we harden a child anywhere in the chain we can't recover the private key
    if private or not indexes:
        return key_chain[-1]
    else:
        last_is_hardened = indexes[-1][1]
        parent = key_chain[-1]
        if last_is_hardened:
            # N() is not a true derivation so just neuter the very last private key
            return N(
                parent.data,
                parent.chain_code,
                parent.child_number,
                parent.depth,
                finger=parent.finger,
                version=VERSIONS[parent.get_network()]["public"],
            )
        else:
            # CKDpub() is a true derivation so go to grandparent as parent
            grand_parent = key_chain[-2]
            return CKDpub(
                to_public_key(grand_parent.data),
                grand_parent.chain_code,
                parent.child_number,
                parent.depth,
                finger=parent.finger,
                version=VERSIONS[parent.get_network()]["public"],
            )


def CKDpriv(
    secret_key: bytes,
    chain_code: bytes,
    child_number: int,
    depth: bytes,
    version: bytes,
) -> ExtendedKey:
    hardened = child_number >= TYPED_CHILD_KEY_COUNT
    secret_int = int.from_bytes(secret_key[1:], "big")
    data = (
        secret_key
        if hardened
        else VerifyingKey.from_public_point(
            secret_int * SECP256k1.generator,
            curve=SECP256k1,
        ).to_string("compressed")
    )
    derived = hmac_sha512(
        key=chain_code,
        data=data + child_number.to_bytes(4, "big"),
    )
    # BIP-32: In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid
    # (Note: this has probability lower than 1 in 2**127.)
    parse_256_IL = int.from_bytes(derived[:32], "big")
    child_key_int = (parse_256_IL + int.from_bytes(secret_key, "big")) % SECP256k1.order
    if (parse_256_IL >= SECP256k1.order) or not child_key_int:
        raise ValueError(
            f"Rare invalid child key. Retry with the next child index: {child_number} + 1."
        )
    child_key = bytes(1) + child_key_int.to_bytes(32, "big")

    return ExtendedKey(
        version=version,
        depth=depth,
        finger=fingerprint(secret_key),
        child_number=child_number.to_bytes(4, "big"),
        chain_code=derived[32:],
        data=child_key,
    )


def N(
    private_key: bytes,
    chain_code: bytes,
    child_number: bytes,
    depth: bytes,
    finger: bytes,
    version: bytes,
) -> ExtendedKey:
    """neuter a private key into the public one (no derivation per se)
    pass in the fingerprint since it is from the parent (which we don't have)
    """
    return ExtendedKey(
        version=version,
        depth=depth,
        finger=finger,
        child_number=child_number,
        chain_code=chain_code,
        data=to_public_key(private_key),
    )


def CKDpub(
    public_key: bytes,
    chain_code: bytes,
    child_number: bytes,
    depth: bytes,
    finger: bytes,
    version: bytes,
) -> ExtendedKey:
    child_number_int = int.from_bytes(child_number, "big")
    if child_number_int >= TYPED_CHILD_KEY_COUNT:
        raise ValueError(f"Cannot call CKDpub() for hardened child: {child_number_int}")

    parent_key = VerifyingKey.from_string(public_key, curve=SECP256k1).pubkey.point

    derived = hmac_sha512(
        key=chain_code,
        data=public_key + child_number,
    )
    parse_256_IL = int.from_bytes(derived[:32], "big")
    child_point = SECP256k1.generator * parse_256_IL + parent_key
    # BIP-39: In case parse256(IL) ≥ n or Ki is the point at infinity, the resulting
    # key is invalid, and one should proceed with the next value for i.
    if parse_256_IL >= SECP256k1.order:
        raise ValueError(f"Invalid key. Try next child index: {child_number} + 1.")
    try:
        child_key = VerifyingKey.from_public_point(
            child_point,
            curve=SECP256k1,
        ).to_string("compressed")
    except MalformedPointError as mal:
        # TODO: Is this in fact how to detect the point at infinity?
        raise ValueError(
            f"Invalid key (point at infinity?). Try next child index: {child_number} + 1."
        ) from mal
    derived_chain_code = derived[32:]

    return ExtendedKey(
        data=child_key,
        chain_code=derived_chain_code,
        child_number=child_number_int.to_bytes(4, "big"),
        depth=depth,
        version=version,
        finger=finger,
    )


def to_public_key(secret_key: bytes, as_point=False):
    """returns compressed ecdsa public key"""
    # ecdsa from_/to_string are actually from_/to_bytes b/c of some kind of
    # Python 2 hangover
    assert len(secret_key) == 33
    # chop the first byte 0x00 else ECDSA will throw
    private_key = SigningKey.from_string(secret_key[1:], curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    compressed = public_key.to_string("compressed")

    return compressed


def segment_to_index(segment: str) -> (bytes, bool):
    """for internal (non-m) derivation path segments which should all be integers
    once the optional hardened symbol is dropped"""
    # As of BIP-44 we can use ' for hardened paths
    # https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    hardened = segment[-1] in ("h", "H", "'")
    if hardened:
        segment = segment[:-1]
    index = int(segment)
    assert index <= (TYPED_CHILD_KEY_COUNT - 1)
    if hardened:
        index += TYPED_CHILD_KEY_COUNT

    return (index, hardened)


def fingerprint(private_key: bytes) -> bytes:
    pub_key = to_public_key(private_key)
    ripemd = hashlib.new("ripemd160")
    ripemd.update(hashlib.sha256(pub_key).digest())
    fingerprint = ripemd.digest()[:4]

    return fingerprint


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key=key, msg=data, digestmod="sha512").digest()
