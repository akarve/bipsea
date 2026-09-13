"""Bech32 (BIP-173) encoding, encode-only subset.

Vendored from the reference implementation
https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
Copyright (c) 2017 Pieter Wuille, MIT License.
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0] * 6) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _to_5bit(data: bytes) -> list[int]:
    acc = 0
    bits = 0
    ret = []
    for value in data:
        acc = (acc << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            ret.append((acc >> bits) & 31)
    if bits:
        ret.append((acc << (5 - bits)) & 31)
    return ret


def encode(hrp: str, payload: bytes) -> str:
    data = _to_5bit(payload)
    combined = data + _create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)
