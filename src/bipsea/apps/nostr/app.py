from typing import Any

from bech32 import bech32_encode, convertbits

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int


def nsec_encode(key_bytes: bytes) -> str:
    data = convertbits(key_bytes, 8, 5)
    return bech32_encode("nsec", data)


class NostrApp:
    name = "nostr"
    code = "128002'"

    @property
    def params(self) -> list[Param]:
        return []

    def path_segments(self, index: int, identity: int, **_) -> list[str]:
        return [f"{identity}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {
            "identity": hardened_int(segments[0]),
            "index": hardened_int(segments[1]),
        }

    def apply(self, entropy: bytes, **_) -> dict[str, Any]:
        key = entropy[:32]
        return {
            "entropy": key,
            "application": nsec_encode(key),
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/128002'/1'/1'",
                entropy="ff6eb0fcdf1ef87a2a06b0d7884d495b486d0faa210e9f80f23fd649d6e114d2",
                output="nsec1lahtplxlrmu852sxkrtcsn2ftdyx6ra2yy8flq8j8ltyn4hpznfq23uvqz",
            ),
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/128002'/1'/2'",
                entropy="917628689652288f6983c8a01db516d0697d5198dcf9de9010597f5e322fba6e",
                output="nsec1j9mzs6yk2g5g76vrezspmdgk6p5h65vcmnuaayqst9l4uv30hfhqje0jyh",
            ),
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/128002'/2'/1'",
                entropy="fa2e784291b1fd347ba3624672e3090cb2cee34b8567180336e3aa290d02715b",
                output="nsec1lgh8ss53k87ng7arvfr89ccfpjevac6ts4n3sqekuw4zjrgzw9dsq3uelh",
            ),
        ]


app = NostrApp()
