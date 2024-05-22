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


import hashlib, hmac
import logging

from ecdsa import SigningKey, SECP256k1, VerifyingKey

from bip32_ext_key import ExtendedKey, VERSIONS


logger = logging.getLogger("btcseed")


# HARDENED_CHILD_KEY_COUNT = 2**31 (as comment for clarity)
NORMAL_CHILD_KEY_COUNT = 2**31


def to_master_key(seed: bytes, mainnet=True, private=False) -> ExtendedKey:
    master = hmac_(key=b"Bitcoin seed", data=seed)
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


def derive_key(master_seed: bytes, path: str, mainnet: bool, private: bool):
    segments = path.split("/")
    assert segments[0] == "m", "expected 'm' (private) at derivation path root"
    indexes = [segment_to_index(s) for s in segments[1:]]
    max_depth = len(indexes)
    parent_key = to_master_key(
        master_seed,
        mainnet=mainnet,
        # if we're doing any derivation we must start with the master private key
        private=True if indexes else private,
    )
    for depth, (index, hardened) in enumerate(indexes, 1):
        logger.debug(f"derive {index} {hardened}")
        # only use N() or CKDpub() at the  highest depth (final segment)
        # so as to avoid complex look ahead and hard-to-read flow control
        logger.debug("CKDpriv()")
        next = CKDpriv(
            parent_key.data,
            parent_key.chain_code,
            index,
            depth,
            mainnet=mainnet,
        )
        if (depth == max_depth) and not private:
            logger.info("N()")
            neutered_key = N(
                next.data,
                next.chain_code,
                index,
                depth,
                finger=next.finger,
                mainnet=mainnet,
            )
            if hardened:
                parent_key = neutered_key
            else:
                logger.info("CKDpub()")
                parent_key = CKDpub(
                    parent_key.data,
                    parent_key.chain_code,
                    index,
                    depth,
                    finger=parent_key.finger,
                    mainnet=mainnet,
                )
        else:
            parent_key = next

    return parent_key


def CKDpriv(
    secret_key: bytes,
    chain_code: bytes,
    index: int,
    depth: int,
    mainnet: bool,
) -> ExtendedKey:
    hardened = index >= NORMAL_CHILD_KEY_COUNT
    secret_int = int.from_bytes(secret_key[1:], "big")
    data = (
        secret_key
        if hardened
        else VerifyingKey.from_public_point(
            secret_int * SECP256k1.generator,
            curve=SECP256k1,
        ).to_string("compressed")
    )
    while True:
        derived = hmac_(key=chain_code, data=data + index.to_bytes(4, "big"))
        if validate_derived_key(derived):
            break
        else:
            index += 1
            if hardened:
                assert index < 2**32
            else:
                assert index < NORMAL_CHILD_KEY_COUNT

    child_key_int = (
        int.from_bytes(derived[:32], "big") + int.from_bytes(secret_key, "big")
    ) % SECP256k1.order
    child_key = bytes(1) + child_key_int.to_bytes(32, "big")

    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"]["private"],
        depth=depth.to_bytes(1, "big"),
        finger=fingerprint(secret_key),
        child_number=index.to_bytes(4, "big"),
        chain_code=derived[32:],
        data=child_key,
    )


def N(
    private_key: bytes,
    chain_code: bytes,
    index: int,
    depth: int,
    mainnet: bool,
    finger: bytes,
) -> ExtendedKey:
    """neuter a private key into the public one (no derivation per se)
    pass in the fingerprint since it is from the parent (which we don't have)
    """
    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"]["public"],
        depth=depth.to_bytes(1, "big"),
        finger=finger,
        child_number=index.to_bytes(4, "big"),
        chain_code=chain_code,
        data=to_public_key(private_key),
    )


def CKDpub(
    public_key: bytes,
    chain_code: bytes,
    index: int,
    depth: int,
    finger: bytes,
    mainnet: bool,
) -> ExtendedKey:
    if index >= NORMAL_CHILD_KEY_COUNT:
        raise ValueError("Must not invoke CKDpub() for hardened child")
    derived = hmac_(key=chain_code, data=public_key + index.to_bytes(4, "big"))
    derived_key = int.from_bytes(derived[:32], "big")
    derived_chain_code = derived[32:]
    child_key = VerifyingKey.from_public_point(
        derived_key * SECP256k1.generator
        + VerifyingKey.from_string(public_key, curve=SECP256k1).pubkey.point
    ).to_string("compressed")

    # TODO:
    # In case parse256(IL) ≥ n or Ki is the point at infinity, the resulting key is invalid,
    # and one should proceed with the next value for i.

    return ExtendedKey(
        version=VERSIONS["mainnet" if mainnet else "testnet"]["public"],
        depth=depth.to_bytes(1, "big"),
        finger=finger,
        child_number=index.to_bytes(4, "big"),
        chain_code=derived_chain_code,
        data=child_key.to_bytes(),
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
    assert len(compressed) == 33, "compressed public key should be 32 bytes"

    return compressed


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


def fingerprint(private_key: bytes) -> bytes:
    logger.debug(f"fingerprint input: {private_key}")
    pub_key = to_public_key(private_key)
    logger.debug(f"fingerprint pubkey: {pub_key}")
    ripemd = hashlib.new("ripemd160")
    ripemd.update(hashlib.sha256(pub_key).digest())
    fingerprint = ripemd.digest()[:4]
    logger.debug(f"+ fingerprint: {fingerprint}")

    return fingerprint


def hmac_(key: bytes, data: bytes) -> bytes:
    return hmac.new(key=key, msg=data, digestmod="sha512").digest()


def validate_derived_key(key: bytes) -> bool:
    assert len(key) == 64
    secret_key = key[:32]
    secret_int = int.from_bytes(secret_key, "big")
    if (secret_int == 0) or (secret_int >= SECP256k1.order):
        return False

    return True
