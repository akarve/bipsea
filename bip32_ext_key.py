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

    ext_key = ExtendedKey(
        version=master_dec[:4],
        depth=master_dec[4:5],  # slice so we get bytes, not an int
        finger=master_dec[5:9],
        child_number=master_dec[9:13],
        chain_code=master_dec[13:45],
        data=master_dec[45:],
    )

    matched = False
    for net in VERSIONS:
        for vis in VERSIONS[net]:
            if ext_key.version == VERSIONS[net][vis]:
                matched = True
                if net == "mainnet":
                    assert key.startswith("x")
                else:
                    assert key.startswith("t")
                if vis == "public":
                    assert key[1:4] == "pub"
                    assert ext_key.data[0] == bytes(1)
                else:
                    assert key[1:4] == "prv"
                    assert ext_key.data[0] in {bytes.fromhex("02"), bytes.fromhex("03")}
    assert matched, f"unrecognized version: {ext_key.version}"

    depth = int.from_bytes(ext_key.depth, "big")
    if depth == 0:
        assert ext_key.finger == bytes(4)
    else:
        assert ext_key.finger != bytes(4)

    assert len(ext_key.version) == 4
    assert len(ext_key.finger) == len(ext_key.child_number) == 4
    assert len(ext_key.data) - 1 == 32 == len(ext_key.chain_code)

    return ext_key
