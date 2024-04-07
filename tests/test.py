"""
for we accept non-determinism
"""
import hashlib
import secrets

from mnemonic import Mnemonic
import pytest
import requests
from click.testing import CliRunner
from seedwords import FILE_HASH, N_MNEMONICS, seed

WORD_COUNTS = {12, 15, 18, 21, 24}


def test_entropy_flag():
    runner = CliRunner()
    for w in WORD_COUNTS:
        for _ in range(31):
            result = runner.invoke(seed, ["--entropy", "--wordcount", w])
            lines = result.output.splitlines()
            entropy = int(lines[0].split()[-1])
            phrase = lines[-1]
            mnemo = Mnemonic("english")
            assert mnemo.check(phrase)
            assert int.from_bytes(mnemo.to_entropy(phrase), "big") == entropy


def test_no_args():
    for _ in range(31):
        runner = CliRunner()
        result = runner.invoke(seed)
        assert result.exit_code == 0
        assert len(result.output.split()) == 12
        mnemo = Mnemonic("english")
        assert mnemo.check(result.output.splitlines()[-1])


def test_word_counts():
    runner = CliRunner()
    for c in range(31):
        result = runner.invoke(seed, ["--wordcount", str(c)])
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
    # Fetch the BIP39 wordlist
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    response = requests.get(url)
    wordlist = response.text.split()
    assert len(wordlist) == N_MNEMONICS
    response_hash = hashlib.sha256(response.content).hexdigest()
    assert response_hash == FILE_HASH, f"Hash mismatch: {response_hash} != {FILE_HASH}"
