import pytest
from click.testing import CliRunner
from bipsea import cli, SEED_N_RANGE_STR


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.parametrize("n", SEED_N_RANGE_STR)
def test_seed_command_words(runner, n):
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
