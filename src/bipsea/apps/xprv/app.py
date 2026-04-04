from typing import Any

from bipsea.app_protocol import Param, TestVector
from bipsea.bip32 import VERSIONS, ExtendedKey


class XprvApp:
    name = "xprv"
    code = "32'"

    @property
    def params(self) -> list[Param]:
        return []

    def path_segments(self, index: int, **_) -> list[str]:
        return [f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {}

    def apply(self, entropy: bytes, **_) -> dict[str, Any]:
        derived_key = ExtendedKey(
            version=VERSIONS["mainnet"]["private"],
            depth=bytes(1),
            finger=bytes(4),
            child_number=bytes(4),
            chain_code=entropy[:32],
            data=bytes(1) + entropy[32:],
        )
        return {
            "entropy": entropy[32:],
            "application": str(derived_key),
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/32'/0'",
                entropy="ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682",
                output="xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX",
            ),
        ]


app = XprvApp()
