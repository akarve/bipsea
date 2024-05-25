import logging

import pytest
from click.testing import CliRunner
from tests.data.bip39_vectors import VECTORS

from const import LOGGER
from bip32 import to_master_key
from bipsea import cli, SEED_N_RANGE_STR
from preseed import from_hex


logger = logging.getLogger(LOGGER)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.parametrize("language, vectors", VECTORS.items())
def test_seed_command_to_actual_seed(runner, language, vectors):
    for vector in vectors:
        _, mnemonic, _, xprv = vector
        result = runner.invoke(
            cli, ["seed", "-t", "xprv", "-f", "words", "-i", mnemonic, "-p", "TREZOR"]
        )
        assert result.exit_code == 0
        assert result.output.strip() == xprv

        diff_pass = runner.invoke(
            cli, ["seed", "-t", "xprv", "-f", "words", "-i", mnemonic, "-p", "TrEZOR"]
        )
        assert diff_pass.exit_code == 0
        assert diff_pass.output.strip() != xprv

        diff_mnem = runner.invoke(
            cli,
            ["seed", "-t", "xprv", "-f", "words", "-i", mnemonic + ".", "-p", "TrEZOR"],
        )
        assert diff_mnem.exit_code == 0
        assert diff_mnem.output.strip() != xprv


@pytest.mark.parametrize("language, vectors", VECTORS.items())
def test_seed_option_sensitivity(runner, language, vectors):
    """prove that passphrase and mnemonic changes alter xprv (but white space around
    mnemonic doesn't)"""
    # make tests faster by only covering one per language
    for vector in vectors[:1]:
        _, mnemonic, _, xprv = vector

        diff_pass = runner.invoke(
            cli, ["seed", "-t", "xprv", "-f", "words", "-i", mnemonic, "-p", "TrEZOR"]
        )
        assert diff_pass.exit_code == 0
        assert diff_pass.output.strip() != xprv

        diff_mnem = runner.invoke(
            cli,
            ["seed", "-t", "xprv", "-f", "words", "-i", mnemonic + ".", "-p", "TREZOR"],
        )
        assert diff_mnem.exit_code == 0
        assert diff_mnem.output.strip() != xprv

        space_mnem = runner.invoke(
            cli,
            [
                "seed",
                "-t",
                "xprv",
                "-f",
                "words",
                "-i",
                "  " + mnemonic + "\t\n ",
                "-p",
                "TREZOR",
            ],
        )
        assert space_mnem.exit_code == 0
        assert space_mnem.output.strip() == xprv


@pytest.mark.parametrize("n", SEED_N_RANGE_STR)
def test_seed_command_n_words(runner, n):
    result = runner.invoke(cli, ["seed", "-f", "rand", "-t", "words", "-n", n])
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
