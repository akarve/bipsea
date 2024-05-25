import pytest
from click.testing import CliRunner
from bipsea import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_seed_command(runner):
    result = runner.invoke(cli, ["seed", "-f", "rand", "-t", "words"])
    assert result.exit_code == 0


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
