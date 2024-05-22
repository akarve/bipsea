from collections import namedtuple
from typing import Dict

import base58


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

    def __new__(
        cls,
        version: bytes,
        depth: bytes,
        finger: bytes,
        child_number: bytes,
        chain_code: bytes,
        data: bytes,
    ):
        assert len(version) == 4
        assert len(depth) == 1
        assert len(finger) == 4
        assert len(child_number) == 4
        assert len(chain_code) == 32
        assert len(data) == 33
        return super().__new__(
            cls, version, depth, finger, child_number, chain_code, data
        )


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
