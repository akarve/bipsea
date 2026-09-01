from typing import Any

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.age.bech32 import encode as bech32_encode
from bipsea.apps.shared import hardened_int

SEED_BYTES = 32
HRPS = {
    "classic": "age-secret-key-",
    "pq": "age-secret-key-pq-",
}


class AgeApp:
    """age file-encryption identities (https://age-encryption.org/v1).

    Per the BIP-85 "age file encryption keys" example use, the 32-byte HEX
    output at m/83696968'/128169'/32'/{index}' is the secret key of an age
    identity. No dedicated application number; shares hex's 128169'.
    """

    name = "age"
    code = "128169'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "flavor",
                ("-f", "--flavor"),
                str,
                default="classic",
                choices=list(HRPS),
                help=(
                    "Identity flavor: classic (X25519) or pq (X-Wing, age v1.3.0+)."
                    " Use a given index with only one flavor."
                ),
            ),
        ]

    def path_segments(self, index: int, **_) -> list[str]:
        return [f"{SEED_BYTES}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        length = hardened_int(segments[0])
        if length != SEED_BYTES:
            raise ValueError(f"Expected {SEED_BYTES}-byte segment, got {length}")
        return {}

    def apply(self, entropy: bytes, flavor: str = "classic", **_) -> dict[str, Any]:
        if flavor not in HRPS:
            raise ValueError(f"Expected flavor in {list(HRPS)}, got {flavor}")
        return {
            "entropy": entropy,
            "application": bech32_encode(HRPS[flavor], entropy[:SEED_BYTES]).upper(),
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/128169'/32'/0'",
                entropy="ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc9e3548a8eafa3d247778f0327061c5289026d19ff6beeefad57683e8ff27dc80",
                output="AGE-SECRET-KEY-1AG7WKZCZA689SAMECCL5K7E6Y854PGSN78K98J4KPRGNAPUKUMWQWNNT4U",
            ),
        ]


app = AgeApp()
