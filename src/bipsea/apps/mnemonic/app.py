from typing import Any

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int
from bipsea.bip39 import (
    LANGUAGES,
    N_WORDS_META,
    entropy_to_words,
    validate_mnemonic_words,
)

INDEX_TO_LANGUAGE = {
    "0'": "english",
    "1'": "japanese",
    "2'": "korean",
    "3'": "spanish",
    "4'": "chinese_simplified",
    "5'": "chinese_traditional",
    "6'": "french",
    "7'": "italian",
    "8'": "czech",
    "9'": "portuguese",  # not in BIP-85 but in BIP-39 test vectors
}

LANGUAGE_TO_INDEX = {v: k for k, v in INDEX_TO_LANGUAGE.items()}

assert set(INDEX_TO_LANGUAGE.values()) == set(LANGUAGES.keys())


class MnemonicApp:
    name = "mnemonic"
    code = "39'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "n_words",
                ("-n", "--words"),
                int,
                required=True,
                choices=[str(n) for n in N_WORDS_META.keys()],
                help="Number of mnemonic words",
                role="number",
            ),
            Param(
                "language",
                ("-t", "--language"),
                str,
                default="english",
                choices=list(LANGUAGES.keys()),
                help="Output language",
            ),
        ]

    def path_segments(
        self, index: int, n_words: int, language: str = "english", **_
    ) -> list[str]:
        lang_code = LANGUAGE_TO_INDEX[language]
        return [lang_code, f"{n_words}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {
            "language": INDEX_TO_LANGUAGE[segments[0]],
            "n_words": hardened_int(segments[1]),
        }

    def apply(
        self, entropy: bytes, n_words: int, language: str = "english", **_
    ) -> dict[str, Any]:
        if n_words not in N_WORDS_META:
            raise ValueError(f"Unsupported number of words: {n_words}")
        n_bytes = N_WORDS_META[n_words]["entropy_bits"] // 8
        trimmed = entropy[:n_bytes]
        words = entropy_to_words(n_words, trimmed, language)
        assert validate_mnemonic_words(words, language)
        return {
            "entropy": trimmed,
            "application": " ".join(words),
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/39'/0'/12'/0'",
                entropy="6250b68daf746d12a24d58b4787a714b",
                output="girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
            ),
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/39'/0'/18'/0'",
                entropy="938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc",
                output="near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token",
            ),
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/39'/0'/24'/0'",
                entropy="ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f",
                output="puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano",
            ),
        ]


app = MnemonicApp()
