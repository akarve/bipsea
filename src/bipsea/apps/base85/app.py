import base64 as b64
from typing import Any

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int


class Base85App:
    name = "base85"
    code = "707785'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "length",
                ("-n", "--length"),
                int,
                required=True,
                range=(10, 80),
                help="Password length in characters",
                role="number",
            ),
        ]

    def path_segments(self, index: int, length: int, **_) -> list[str]:
        return [f"{length}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {"length": hardened_int(segments[0])}

    def apply(self, entropy: bytes, length: int, **_) -> dict[str, Any]:
        if not (10 <= length <= 80):
            raise ValueError(f"Expected length in [10, 80], got {length}")
        return {
            "entropy": entropy,
            "application": b64.b85encode(entropy).decode("utf-8")[:length],
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/707785'/12'/0'",
                entropy="f7cfe56f63dca2490f65fcbf9ee63dcd85d18f751b6b5e1c1b8733af6459c904a75e82b4a22efff9b9e69de2144b293aa8714319a054b6cb55826a8e51425209",
                output="_s`{TW89)i4`",
            ),
        ]


app = Base85App()
