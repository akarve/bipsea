import base64 as b64
from typing import Any

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int


class Base64App:
    name = "base64"
    code = "707764'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "length",
                ("-n", "--length"),
                int,
                required=True,
                range=(20, 86),
                help="Password length in characters",
                role="number",
            ),
        ]

    def path_segments(self, index: int, length: int, **_) -> list[str]:
        return [f"{length}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {"length": hardened_int(segments[0])}

    def apply(self, entropy: bytes, length: int, **_) -> dict[str, Any]:
        if not (20 <= length <= 86):
            raise ValueError(f"Expected length in [20, 86], got {length}")
        return {
            "entropy": entropy,
            "application": b64.b64encode(entropy).decode("utf-8")[:length],
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/707764'/21'/0'",
                entropy="74a2e87a9ba0cdd549bdd2f9ea880d554c6c355b08ed25088cfa88f3f1c4f74632b652fd4a8f5fda43074c6f6964a3753b08bb5210c8f5e75c07a4c2a20bf6e9",
                output="dKLoepugzdVJvdL56ogNV",
            ),
        ]


app = Base64App()
