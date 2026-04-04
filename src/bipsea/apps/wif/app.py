from typing import Any

import base58

from bipsea.app_protocol import Param, TestVector


class WifApp:
    name = "wif"
    code = "2'"

    @property
    def params(self) -> list[Param]:
        return []

    def path_segments(self, index: int, **_) -> list[str]:
        return [f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {}

    def apply(self, entropy: bytes, network: str = "mainnet", **_) -> dict[str, Any]:
        trimmed = entropy[:32]
        prefix = b"\x80" if network == "mainnet" else b"\xef"
        suffix = b"\x01"  # use with compressed public keys because BIP-32
        extended = prefix + trimmed + suffix
        return {
            "entropy": trimmed,
            "application": base58.b58encode_check(extended).decode("utf-8"),
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/2'/0'",
                entropy="7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1",
                output="Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp",
            ),
        ]


app = WifApp()
