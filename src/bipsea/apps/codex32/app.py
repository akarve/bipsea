from typing import Any

from codex32 import Codex32String

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int
from bipsea.drng import DRNG

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CANONICAL_SHARE_INDICES = "acdefghjk"
MAX_HEADER_INDEX = 2**30


def _validate_payload_len(payload_len: int) -> tuple[int, int]:
    byte_len = 5 * payload_len // 8
    pad_len = 5 * payload_len % 8
    if not (16 <= byte_len <= 64 and pad_len <= 4):
        raise ValueError(f"Invalid profile-0 payload length: {payload_len}")
    return byte_len, pad_len


def _decode_header(header_index: int) -> tuple[str, str]:
    if not (0 <= header_index < MAX_HEADER_INDEX):
        raise ValueError(f"Header index must be in [0, {MAX_HEADER_INDEX})")

    header = "".join(
        BECH32_CHARSET[(header_index >> shift) & 31] for shift in range(25, -1, -5)
    )
    threshold = header[0]
    share_index = header[-1]

    if threshold == "0":
        if share_index != "s":
            raise ValueError("Threshold 0 requires share index s")
    elif threshold in "23456789":
        basis = CANONICAL_SHARE_INDICES[: int(threshold)]
        if share_index not in basis:
            raise ValueError(
                f"Share index {share_index} is outside the threshold-{threshold} "
                "canonical initial basis"
            )
    else:
        raise ValueError(f"Invalid codex32 threshold: {threshold}")

    return header, share_index


def _payload_chars(
    entropy: bytes, payload_len: int, share_index: str, byte_len: int, pad_len: int
) -> str:
    bit_len = 5 * payload_len
    drng = DRNG(entropy)

    if share_index == "s":
        payload = int.from_bytes(drng.read(byte_len), "big") << pad_len
    else:
        read_len = (bit_len + 7) // 8
        payload = int.from_bytes(drng.read(read_len), "big")
        payload >>= read_len * 8 - bit_len

    return "".join(
        BECH32_CHARSET[(payload >> shift) & 31] for shift in range(bit_len - 5, -1, -5)
    )


class Codex32App:
    name = "codex32"
    code = "93'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "payload_len",
                ("-n", "--number"),
                int,
                default=26,
                range=(26, 103),
                help="Codex32 payload length in bech32 characters",
                role="number",
            ),
        ]

    def path_segments(self, index: int, payload_len: int = 26, **_) -> list[str]:
        _validate_payload_len(payload_len)
        _decode_header(index)
        return ["0'", f"{payload_len}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        if len(segments) != 3:
            raise ValueError("Codex32 paths require profile, payload length, and index")

        profile, payload_len, header_index = map(hardened_int, segments)
        if profile != 0:
            raise ValueError(f"Unsupported codex32 profile: {profile}")
        _validate_payload_len(payload_len)
        _decode_header(header_index)
        return {
            "profile": profile,
            "payload_len": payload_len,
            "header_index": header_index,
        }

    def apply(
        self,
        entropy: bytes,
        payload_len: int,
        header_index: int,
        profile: int = 0,
        **_,
    ) -> dict[str, Any]:
        if profile != 0:
            raise ValueError(f"Unsupported codex32 profile: {profile}")

        byte_len, pad_len = _validate_payload_len(payload_len)
        header, share_index = _decode_header(header_index)
        payload = _payload_chars(entropy, payload_len, share_index, byte_len, pad_len)
        codex32 = Codex32String.from_unchecksummed_string(f"ms1{header}{payload}")
        return {"entropy": entropy, "application": str(codex32).lower()}

    @property
    def vectors(self) -> list[TestVector]:
        master = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
        return [
            TestVector(
                master=master,
                path="m/83696968'/93'/0'/26'/520937584'",
                entropy="a95e647c44382b2c6f7aa9f6f57461a42a2f77af83f0b23ca305f5c3076ca518c237cd41e56e9d8c7e7e8e0dd6c22d4deae2dda8931c18ffbe6cc2e097cf6116",
                output="ms10secrsewj3lghkgl6n3pe0h7aeyu0yyqlws7qlpv4takg",
            ),
            TestVector(
                master=master,
                path="m/83696968'/93'/0'/26'/353105021'",
                entropy="c95df7678fd370b68c419e694c04ed65a86df7368c0371bf3310cc9f5ed474ae02a8eeab8f5c64e7fadbccde17cfd68275570a88039c242c6b2053b13aa764f2",
                output="ms12sharan26hdftg98lnz68h3p2c796vyvc3w06df5kav9m",
            ),
            TestVector(
                master=master,
                path="m/83696968'/93'/0'/26'/353105016'",
                entropy="be19028ae7a81c558c9fe9f461ceddda629318a6eb1ff309cd408b0e3cd4a031788117f50d551ff38200e96afb5d14c443b7bb91e05e190b360751cb81bd6750",
                output="ms12sharcjlku4rmnudpgw7h8yup99c8yjk6qe7fnm4nlla4",
            ),
        ]


app = Codex32App()
