from typing import Any

from bipsea.app_protocol import Param, TestVector
from bipsea.drng import DRNG
from bipsea.util import to_hex_string


class DrngApp:
    name = "drng"
    code = "0'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "length",
                ("-n", "--length"),
                int,
                required=True,
                help="Number of bytes to generate",
                role="number",
            ),
        ]

    def path_segments(self, index: int, **_) -> list[str]:
        return ["0'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {}

    def apply(self, entropy: bytes, length: int, **_) -> dict[str, Any]:
        drng = DRNG(entropy)
        return {
            "entropy": entropy,
            "application": to_hex_string(drng.read(length)),
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/0'/0'/0'",
                entropy="efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7",
                output="b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd883d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc8c7355b87a925a37ee405a7502991111",
            ),
        ]


app = DrngApp()
