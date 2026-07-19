from ecdsa import SECP256k1


def hardened_int(segment: str) -> int:
    if not segment.endswith("'"):
        raise ValueError(f"Expected hardened segment, got {segment}")
    return int(segment[:-1])


def validate_secp256k1_key(key: bytes) -> bytes:
    # BIP-32: in case parse256(key) >= n or key = 0 the secret is invalid, and
    # one should proceed with the next index. (Probability lower than 1 in 2**127.)
    secret = int.from_bytes(key, "big")
    if secret == 0 or secret >= SECP256k1.order:
        raise ValueError(
            "Rare invalid secret key (0 or >= secp256k1 order). "
            "Retry with the next child index."
        )
    return key
