import math
from typing import Any

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int
from bipsea.drng import DRNG


class DiceApp:
    name = "dice"
    code = "89101'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "rolls",
                ("-n", "--rolls"),
                int,
                required=True,
                range=(1, 10_000),
                help="Number of rolls",
                role="number",
            ),
            Param(
                "sides",
                ("-s", "--sides"),
                int,
                default=6,
                range=(2, None),
                help="Number of sides on die",
            ),
        ]

    def path_segments(self, index: int, rolls: int, sides: int = 6, **_) -> list[str]:
        return [f"{sides}'", f"{rolls}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {
            "sides": hardened_int(segments[0]),
            "rolls": hardened_int(segments[1]),
        }

    def apply(self, entropy: bytes, rolls: int, sides: int = 6, **_) -> dict[str, Any]:
        return {
            "entropy": entropy,
            "application": self._do_rolls(entropy, sides, rolls),
        }

    def _do_rolls(self, entropy: bytes, sides: int, rolls: int) -> str:
        max_width = len(str(sides - 1))
        history = []
        bits_per_roll = math.ceil(math.log(sides, 2))
        bytes_per_roll = math.ceil(bits_per_roll / 8)
        drng = DRNG(entropy)
        while len(history) < rolls:
            trial_int = int.from_bytes(drng.read(bytes_per_roll), "big")
            available_bits = 8 * bytes_per_roll
            excess_bits = available_bits - bits_per_roll
            trial_int >>= excess_bits
            if trial_int < sides:
                history.append(f"{trial_int:0{max_width}d}")
        return ",".join(history)

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/89101'/6'/10'/0'",
                entropy="5e41f8f5d5d9ac09a20b8a5797a3172b28c806aead00d27e36609e2dd116a59176a738804236586f668da8a51b90c708a4226d7f92259c69f64c51124b6f6cd2",
                output="1,0,0,2,0,1,5,5,2,4",
            ),
        ]


app = DiceApp()
