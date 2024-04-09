"""
for we accept non-deterministic tests as good in the huge space of possible
entropy
"""
import hashlib
import secrets
import string

from mnemonic import Mnemonic
import pytest
import requests
from click.testing import CliRunner
from seedwords import DICT_HASH, N_MNEMONICS, seed

COVERAGE = 2**10  # stochastic
WORD_COUNTS = {12, 15, 18, 21, 24}


def test_entropy_flag():
    """the entropy we report is also what mnemo computes"""
    runner = CliRunner()
    for w in WORD_COUNTS:
        for _ in range(COVERAGE):
            result = runner.invoke(seed, ["--meta", "--nwords", w])
            lines = result.output.splitlines()
            entropy = int(lines[0].split()[-1])
            phrase = lines[-1]
            mnemo = Mnemonic("english")
            assert mnemo.check(phrase)
            assert int.from_bytes(mnemo.to_entropy(phrase), "big") == entropy


def test_no_args():
    """no args produces 12 seed words and checksums out"""
    for _ in range(31):
        runner = CliRunner()
        result = runner.invoke(seed)
        assert result.exit_code == 0
        assert len(result.output.splitlines()[-1].split()) == 12
        mnemo = Mnemonic("english")
        assert mnemo.check(result.output.splitlines()[-1])


def test_seed():
    """seed we put in is also what mnemonic gets out"""
    runner = CliRunner()
    for w in WORD_COUNTS:
        for _ in range(COVERAGE):
            ebits = 128 + (((w - 12) // 3) * 32)
            entropy = secrets.randbits(ebits)
            passphrase = _random_passphrase()
            result = runner.invoke(
                seed,
                [
                    "--nwords",
                    w,
                    "--entropy",
                    entropy,
                    "--passphrase",
                    passphrase,
                    "--meta",
                ],
            )
            lines = result.output.splitlines()
            words = lines[-1]
            mnemo = Mnemonic("english")
            assert mnemo.check(words)
            assert int.from_bytes(mnemo.to_entropy(words), "big") == entropy
            seed_hex = lines[-2].split()[-1]
            assert seed_hex == mnemo.to_seed(words, passphrase).hex()


def test_word_counts():
    """test differing word counts; incl erroneous ones"""
    runner = CliRunner()
    for c in range(31):
        result = runner.invoke(seed, ["--nwords", str(c)])
        if c in WORD_COUNTS:
            assert result.exit_code == 0
            assert len(result.output.split()) == c
            mnemo = Mnemonic("english")
            assert mnemo.check(result.output.splitlines()[-1])

        else:
            assert result.exit_code != 0
            if result.exit_code != 2:
                assert "Error" in str(result)


@pytest.mark.network
def test_words_in_bip39_wordlist():
    """make sure we match github"""
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    response = requests.get(url)
    wordlist = response.text.split()
    assert len(wordlist) == N_MNEMONICS
    response_hash = hashlib.sha256(response.content).hexdigest()
    assert response_hash == DICT_HASH, f"Hash mismatch: {response_hash} != {DICT_HASH}"


def _random_passphrase():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(secrets.randbelow(32)))
