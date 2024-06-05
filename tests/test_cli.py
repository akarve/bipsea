import logging
import random

import pytest
from click.testing import CliRunner
from data.bip39_vectors import VECTORS
from data.bip85_vectors import BIP_39, HEX, PWD_BASE85, WIF

from bipsea.bip39 import LANGUAGES, verify_seed_words
from bipsea.bipsea import CODE_TO_LANG, N_WORDS_ALLOWED, cli
from bipsea.util import ASCII_INPUTS, LOGGER

logger = logging.getLogger(LOGGER)


MNEMONIC_12 = {
    "words": "punch man spread gap size struggle clean crouch cloth swear erode fan",
    "xprv": (
        "xprv9s21ZrQH143K417dJYmPr6Qmy2t61xrKtDCCL3Cec4NMFFFRZTF"
        "2jSbtqSXpuCz8UqgsuyrPC5wngx3dk5Gt8zQnbnHVAsMyb7bWtHZ95Jk"
    ),
}


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.parametrize("language, vectors", VECTORS.items(), ids=VECTORS.keys())
def test_seed_command_to_actual_seed(runner, language, vectors):
    for vector in vectors[:1]:  # for speed since test_bip39 already covers all
        _, mnemonic, _, xprv = vector
        for upper in (True, False):
            mnemonic = mnemonic.upper() if upper else mnemonic
            result = runner.invoke(
                cli,
                [
                    "seed",
                    "-t",
                    "xprv",
                    "-f",
                    LANGUAGES[language]["code"],
                    "--input",
                    mnemonic,
                    "-p",
                    "TREZOR",
                ],
            )
            assert result.exit_code == 0
            last = result.output.strip().split("\n")[-1]
            assert last == xprv


@pytest.mark.parametrize("language, vectors", VECTORS.items(), ids=VECTORS.keys())
def test_seed_option_sensitivity(runner, language, vectors):
    """prove that meaningful passphrase mnemonic changes change the xprv
    (but white space after the mnemonic doesn't)"""
    for vector in vectors[:1]:  # one vector per language for speed
        _, mnemonic, _, xprv = vector
        lang_code = LANGUAGES[language]["code"]
        base_cmd = ["seed", "-t", "xprv", "-f", lang_code]
        change_passphrase = runner.invoke(
            cli, base_cmd + ["-u", mnemonic, "-p", "TREZoR"]
        )
        assert change_passphrase.exit_code == 0
        result_xprv = change_passphrase.output.strip().split("\n")[-1]
        assert result_xprv != xprv

        for suffix in ("", ".", " \t\n "):
            cmd = base_cmd + ["-u", mnemonic + suffix, "-p", "TREZOR"]
            result = runner.invoke(cli, cmd)
            if suffix == ".":
                assert result.exit_code != 0
                assert "Unexpected" in result.output
            else:
                assert result.exit_code == 0
                result_xprv = result.output.strip().split("\n")[-1]
                assert result_xprv == xprv


@pytest.mark.parametrize("code", [v["code"] for v in LANGUAGES.values()])
@pytest.mark.parametrize("n", N_WORDS_ALLOWED, ids=lambda n: f"{n}-words")
def test_seed_command_from_rand(runner, n, code):
    for style in ("--not-pretty", "--pretty"):
        cmd = ["seed", "-t", code, "-n", str(n), "-f", "rand"]
        cmd.append(style)
        result = runner.invoke(cli, cmd)
        output = result.output.strip()
        split_on = "\n" if style == "--pretty" else " "
        words = output.split(split_on)
        assert len(words) == int(n)
        assert result.exit_code == 0
        if style != "--pretty":
            assert verify_seed_words(words, CODE_TO_LANG[code])


def test_seed_command_from_custom_words(runner):
    lengths = {"short": 5, "enough": 42}
    base = ["seed", "-t", "xprv"]
    for k, v in lengths.items():
        cmd = base + ["-f", "any", "-u", gen_custom_seed_words(v, 0)]
        result = runner.invoke(cli, cmd)
        assert result.exit_code == 0
        if k == "short":
            assert "Warning" in result.output
        else:
            assert "Warning" not in result.output


def gen_custom_seed_words(length: int, seed: int):
    """non bip-39 seeds (--from "any")"""
    random.seed(seed)
    custom = "".join(
        random.choice("".join(sorted(list(ASCII_INPUTS)))) for _ in range(length)
    )

    return custom


def test_seed_from_and_to_words(runner):
    result = runner.invoke(cli, ["seed", "--from", "eng", "--to", "eng"])
    assert result.exit_code != 0
    assert "--input" in result.output
    assert "--from rand" in result.output


@pytest.mark.parametrize("n", [-1, 11, 13, 0])
def test_seed_bad_n(runner, n):
    result = runner.invoke(cli, ["seed", "--from", "eng", "-n", n])
    assert result.exit_code != 0
    assert "--number" in result.output


@pytest.mark.parametrize("from_", ["baz", "zho", "free"])
def test_seed_bad_from(runner, from_):
    result = runner.invoke(cli, ["seed", "--from", "baz"])
    assert result.exit_code != 0
    assert "not one of" in result.output


def test_seed_bad_to(runner):
    result = runner.invoke(cli, ["seed", "--to", "blah"])
    assert result.exit_code != 0
    assert "not one of" in result.output


def test_bipsea_integration(runner):
    result_seed = runner.invoke(
        cli,
        ["seed", "-f", "eng", "-u", MNEMONIC_12["words"], "-n", "12", "-t", "xprv"],
    )
    xprv = result_seed.output.strip()
    assert xprv == MNEMONIC_12["xprv"]
    assert result_seed.exit_code == 0
    result_entropy = runner.invoke(
        cli, ["entropy", "-a", "base64", "-n", "20", "--input", xprv]
    )
    assert result_entropy.exit_code == 0
    pwd64 = result_entropy.output.strip()
    assert pwd64 == "72zJIS7JhyR5r5NjkuE/"
    assert len(pwd64) == 20


@pytest.mark.parametrize("vector", PWD_BASE85, ids=["PWD_BASE85"])
def test_entropy_n(runner, vector):
    xprv = vector["master"]
    for app in ("base64", "base85", "hex", "drng"):
        for n in (20, 50, 64):
            result = runner.invoke(
                cli, ["entropy", "-a", app, "-n", n, "--input", xprv]
            )
            assert result.exit_code == 0
            answer = result.output.strip()
            length = len(answer)
            if app in ("hex", "drng"):
                length = length // 2
            assert length == n


@pytest.mark.parametrize("vector", PWD_BASE85, ids=["PWD_BASE85"])
def test_entropy_n_out_of_range(runner, vector):
    xprv = vector["master"]
    for app in ("base64", "base85", "hex", "drng"):
        for n in (-1, 0, 1025):
            if n == 1025 and app == "drng":
                break
            result = runner.invoke(
                cli, ["entropy", "-a", app, "-n", n, "--input", xprv]
            )
            assert result.exit_code != 0
            assert "Error" in result.output


@pytest.mark.parametrize(
    "vector",
    BIP_39,
    ids=[f"BIP_39-{v['mnemonic_length']}-words" for v in BIP_39],
)
def test_entropy_bip39(runner, vector):
    xprv = vector["master"]
    n_words = vector["mnemonic_length"]
    result = runner.invoke(
        cli, ["entropy", "-a", "words", "--input", xprv, "-n", n_words]
    )
    assert result.exit_code == 0
    assert result.output.strip() == vector["derived_mnemonic"]


@pytest.mark.parametrize("vector", HEX, ids=["HEX"])
def test_entropy_hex(runner, vector):
    xprv = vector["master"]
    result = runner.invoke(cli, ["entropy", "-a", "hex", "--input", xprv, "-n", 64])
    assert result.exit_code == 0
    assert result.output.strip() == vector["derived_entropy"]


@pytest.mark.parametrize("vector", WIF, ids=["WIF"])
def test_entropy_wif(runner, vector):
    xprv = vector["master"]
    result = runner.invoke(cli, ["entropy", "-a", "wif", "--input", xprv])
    assert result.exit_code == 0
    assert result.output.strip() == vector["derived_wif"]
