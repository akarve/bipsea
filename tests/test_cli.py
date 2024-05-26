import logging
import warnings

import pytest
from click.testing import CliRunner
from tests.data.bip39_vectors import VECTORS

from util import LOGGER
from bipsea import cli, N_WORDS_ALLOWED


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
                with warnings.catch_warnings(record=True) as w:
                    result = runner.invoke(cli, cmd)
                    if "s" in input:
                        assert len(w) > 0
                    else:
                        assert len(w) == 0
                    assert result.exit_code == 0
                    assert len(result.output.split()) == int(n)


def test_bip85_command(runner):
    pass


def test_from_and_to_words(runner):
    result = runner.invoke(cli, ["seed", "--from", "words", "--to", "words"])
    assert result.exit_code != 0
    assert "--input" in result.output
    assert "--from rand" in result.output


def test_from_and_n(runner):
    result = runner.invoke(cli, ["seed", "--from", "words", "-n", "45"])
    assert result.exit_code != 0
    assert "--number" in result.output


def test_bad_from(runner):
    result = runner.invoke(cli, ["seed", "--from", "baz"])
    assert result.exit_code != 0
    assert "not one of" in result.output


def test_bad_to(runner):
    result = runner.invoke(cli, ["seed", "--to", "blah"])
    assert result.exit_code != 0
    assert "not one of" in result.output
