import logging

import pytest
from click.testing import CliRunner

from bipsea import N_WORDS_ALLOWED, cli
from tests.data.bip39_vectors import VECTORS
from tests.data.bip85_vectors import BIP39, HEX, PWD_BASE64, PWD_BASE85, WIF
from util import LOGGER

logger = logging.getLogger(LOGGER)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.parametrize("language, vectors", VECTORS.items())
def test_seed_command_to_actual_seed(runner, language, vectors):
    for vector in vectors:
        _, mnemonic, _, xprv = vector

        for upper in (True, False):
            mnemonic = mnemonic.upper() if upper else mnemonic
            result = runner.invoke(
                cli,
                ["seed", "-t", "xprv", "-f", "words", "-i", mnemonic, "-p", "TREZOR"],
            )
            assert result.exit_code == 0
            assert result.output.strip() == xprv


@pytest.mark.parametrize("language, vectors", VECTORS.items())
def test_seed_option_sensitivity(runner, language, vectors):
    """prove that passphrase and mnemonic changes alter xprv (but white space around
    mnemonic doesn't)"""
    # make tests faster by only covering one per language
    for vector in vectors[:1]:
        _, mnemonic, _, xprv = vector

        change_passphrase = runner.invoke(
            cli, ["seed", "-t", "xprv", "-f", "words", "-i", mnemonic, "-p", "TrEZOR"]
        )
        assert change_passphrase.exit_code == 0
        assert change_passphrase.output.strip() != xprv

        append_mnemonic = runner.invoke(
            cli,
            ["seed", "-t", "xprv", "-f", "words", "-i", mnemonic + ".", "-p", "TREZOR"],
        )
        assert append_mnemonic.exit_code == 0
        assert append_mnemonic.output.strip() != xprv

        whitespace_mnemonic = runner.invoke(
            cli,
            [
                "seed",
                "-t",
                "xprv",
                "-f",
                "words",
                "-i",
                "  " + mnemonic + " \t\n ",
                "-p",
                "TREZOR",
            ],
        )
        assert whitespace_mnemonic.exit_code == 0
        assert whitespace_mnemonic.output.strip() == xprv

        testnet = runner.invoke(
            cli, ["seed", "-t", "tprv", "-f", "words", "-i", mnemonic, "-p", "TREZOR"]
        )
        assert testnet.exit_code == 0
        tprv = testnet.output.strip()
        assert tprv != xprv
        assert tprv.startswith("tprv")


@pytest.mark.parametrize("n", N_WORDS_ALLOWED)
def test_seed_command_n_words(runner, n):
    for from_ in ("string", "rand"):
        cmd = ["seed", "-t", "words", "-n", str(n)]
        cmd += ["-f", from_]
        if from_ == "string":
            # "s"*15 is shorter than the lowest entropy of 128 bits
            # "l"*32 is longer than the highest entropy of 256 bits
            for input in ("s" * 15, "l" * 32):
                cmd += ["-i", input]
                result = runner.invoke(cli, cmd, catch_exceptions=False)
                if "s" in input:
                    assert "Warning" in result.output
                else:
                    assert "Warning" not in result.output
                    assert len(result.output.split()) == int(n)
                assert result.exit_code == 0


def test_seed_from_and_to_words(runner):
    result = runner.invoke(cli, ["seed", "--from", "words", "--to", "words"])
    assert result.exit_code != 0
    assert "--input" in result.output
    assert "--from rand" in result.output


def test_seed_from_and_n(runner):
    result = runner.invoke(cli, ["seed", "--from", "words", "-n", "45"])
    assert result.exit_code != 0
    assert "--number" in result.output


def test_seed_bad_from(runner):
    result = runner.invoke(cli, ["seed", "--from", "baz"])
    assert result.exit_code != 0
    assert "not one of" in result.output


def test_seed_bad_to(runner):
    result = runner.invoke(cli, ["seed", "--to", "blah"])
    assert result.exit_code != 0
    assert "not one of" in result.output


@pytest.mark.parametrize("vector", PWD_BASE64)
def test_bipsea_integration(runner, vector):
    result_seed = runner.invoke(
        cli,
        ["seed", "-f", "string", "-i", "yooooooooooooooo", "-n", "12", "-t", "xprv"],
    )
    xprv = result_seed.output.strip()
    assert result_seed.exit_code == 0
    result_entropy = runner.invoke(
        cli, ["entropy", "-a", "base64", "-n", "20", "--input", xprv]
    )
    assert result_entropy.exit_code == 0
    pwd64 = result_entropy.output.strip()
    assert pwd64 == "lGqIFs50nYCWA0DjxHRB"
    assert len(pwd64) == 20


@pytest.mark.parametrize("vector", PWD_BASE85)
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


@pytest.mark.parametrize("vector", PWD_BASE85)
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


@pytest.mark.parametrize("vector", BIP39)
def test_entropy_bip39(runner, vector):
    xprv = vector["master"]
    n_words = vector["mnemonic_length"]
    result = runner.invoke(
        cli, ["entropy", "-a", "words", "--input", xprv, "-n", n_words]
    )
    assert result.exit_code == 0
    assert result.output.strip() == vector["derived_mnemonic"]


@pytest.mark.parametrize("vector", HEX)
def test_entropy_hex(runner, vector):
    xprv = vector["master"]
    result = runner.invoke(cli, ["entropy", "-a", "hex", "--input", xprv, "-n", 64])
    assert result.exit_code == 0
    assert result.output.strip() == vector["derived_entropy"]


@pytest.mark.parametrize("vector", WIF)
def test_entropy_wif(runner, vector):
    xprv = vector["master"]
    result = runner.invoke(cli, ["entropy", "-a", "wif", "--input", xprv])
    assert result.exit_code == 0
    assert result.output.strip() == vector["derived_wif"]
