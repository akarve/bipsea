from typing import Any

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int
from bipsea.util import to_hex_string


class HexApp:
    name = "hex"
    code = "128169'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "length",
                ("-n", "--length"),
                int,
                required=True,
                range=(16, 64),
                help="Output length in bytes",
                role="number",
            ),
        ]

    def path_segments(self, index: int, length: int, **_) -> list[str]:
        return [f"{length}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {"length": hardened_int(segments[0])}

    def apply(self, entropy: bytes, length: int, **_) -> dict[str, Any]:
        if not (16 <= length <= 64):
            raise ValueError(f"Expected length in [16, 64], got {length}")
        return {
            "entropy": entropy,
            "application": to_hex_string(entropy[:length]),
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/128169'/64'/0'",
                entropy="492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c",
                output="492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c",
            ),
        ]


app = HexApp()
