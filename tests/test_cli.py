import logging
import random

import pytest
from click.testing import CliRunner
from data.bip39_vectors import VECTORS
from data.bip85_vectors import BIP_39, HEX, PWD_BASE85, WIF

from bipsea.bip39 import LANGUAGES, validate_mnemonic_words
from bipsea.bipsea import ISO_TO_LANGUAGE, N_WORDS_ALLOWED, cli
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


class TestMnemonic:
    @pytest.mark.parametrize("lang", ("zho", "x", "esperanto"))
    def test_mnemonic_bad_lang(self, runner, lang):
        cmd = ["mnemonic", "-t", lang]
        result = runner.invoke(cli, cmd)
        assert result.exit_code != 0
        assert "not one of" in result.output

    @pytest.mark.parametrize("n", [-1, 11, 13, 0, 25])
    def test_mnemonic_bad_number(self, runner, n):
        cmd = ["mnemonic", "-n", int(n)]
        result = runner.invoke(cli, cmd)
        assert result.exit_code != 0
        assert "not one of" in result.output


class TestValidate:
    def test_free_mnemonics(self, runner):
        lengths = {"short": 5, "enough": 42}
        for k, v in lengths.items():
            cmd = ["validate", "-f", "free", "-m", self.gen_free_ascii_mnemonic(v, 0)]
            result = runner.invoke(cli, cmd)
            assert result.exit_code == 0
            if k == "short":
                assert "Warning" in result.output
            else:
                assert "Warning" not in result.output

    def gen_free_ascii_mnemonic(self, length: int, seed: int):
        random.seed(seed)
        custom = "".join(
            random.choice("".join(sorted(list(ASCII_INPUTS)))) for _ in range(length)
        )

        return custom


# slowest tests because they call pbkdf2
class TestXPRV:

    @pytest.mark.parametrize("vectors", VECTORS.values(), ids=VECTORS.keys())
    def test_bip_39_vectors(self, runner, vectors):
        for vector in vectors:  # for speed since test_bip39 already covers all
            _, mnemonic, _, xprv = vector
            result = runner.invoke(
                cli, ["xprv", "--mnemonic", mnemonic, "-p", "TREZOR"]
            )
            assert result.exit_code == 0
            last = result.output.strip().split("\n")[-1]
            assert last == xprv

    @pytest.mark.parametrize("vector", VECTORS["english"])
    def test_english_vectors_change_passphrase(self, runner, vector):
        """prove that meaningful passphrase mnemonic changes change the xprv
        (but white space after the mnemonic doesn't)"""
        _, mnemonic, _, xprv = vector
        xprv_cmd = ["xprv"]
        change_passphrase = runner.invoke(
            cli, xprv_cmd + ["-m", mnemonic, "-p", "TREZoR"]
        )
        assert change_passphrase.exit_code == 0
        result_xprv = change_passphrase.output.strip().split("\n")[-1]
        assert result_xprv != xprv

    @pytest.mark.parametrize("fix", (".", " \t\n "), ids=lambda x: f"pre/suffix-{x}")
    @pytest.mark.parametrize("vector", VECTORS["english"])
    def test_english_vectors_change_mnemonic(self, runner, vector, fix):
        _, mnemonic, _, xprv = vector
        cmd = ["xprv", "--mnemonic", fix + mnemonic + fix, "-p", "TREZOR"]
        result = runner.invoke(cli, cmd)
        assert result.exit_code == 0
        result_xprv = result.output.strip().split("\n")[-1]
        if fix == ".":
            assert result_xprv != xprv
        else:
            assert result_xprv == xprv


class TestMnemonicAndValidate:

    @pytest.mark.parametrize("style", ("--pretty", "--not-pretty"), ids=lambda x: x[1:])
    @pytest.mark.parametrize("n", N_WORDS_ALLOWED)
    @pytest.mark.parametrize("lang", ISO_TO_LANGUAGE.keys())
    def test_commands(self, runner, lang, n, style):
        n_words = str(n)
        mnemonic = ["mnemonic", "-n", n_words, "-t", lang, style]
        result = runner.invoke(cli, mnemonic)
        assert result.exit_code == 0

        output = result.output.strip()
        words = output.split("\n" if style == "--pretty" else " ")
        if style == "--pretty":
            words = [w.partition(") ")[2] for w in words]
        assert len(words) == int(n)
        assert validate_mnemonic_words(words, ISO_TO_LANGUAGE[lang])

        if style != "--pretty":
            validate = ["validate", "-f", lang, "--mnemonic", output]
            check_result = runner.invoke(cli, validate)
            assert check_result.exit_code == 0
            check_output = check_result.output.strip()
            assert check_output == output


class TestDerive:
    @pytest.mark.parametrize("vector", PWD_BASE85)
    def test_pwd_base85(self, runner, vector):
        xprv = vector["master"]
        for app in ("base64", "base85", "hex", "drng"):
            for n in (20, 50, 64):
                result = runner.invoke(cli, ["derive", "-a", app, "-n", n, "-x", xprv])
                assert result.exit_code == 0
                answer = result.output.strip()
                length = len(answer)
                if app in ("hex", "drng"):
                    length = length // 2
                assert length == n

    @pytest.mark.parametrize("n", (20, 50, 64))
    @pytest.mark.parametrize("app", ("base64", "base85", "hex", "drng"))
    @pytest.mark.parametrize("vector", PWD_BASE85, ids=["PWD_BASE85"])
    def test_n(self, runner, vector, app, n):
        xprv = vector["master"]
        result = runner.invoke(cli, ["derive", "-a", app, "-n", n, "--xprv", xprv])
        assert result.exit_code == 0
        answer = result.output.strip()
        length = len(answer)
        if app in ("hex", "drng"):
            length = length // 2
        assert length == n

    @pytest.mark.parametrize("n", (-1, 0, 1025))
    @pytest.mark.parametrize("app", ["base64", "base85", "hex", "drng"])
    @pytest.mark.parametrize("vector", PWD_BASE85, ids=["PWD_BASE85"])
    def test_bad_n(self, runner, vector, app, n):
        xprv = vector["master"]
        if n == 1025 and app == "drng":
            return
        result = runner.invoke(cli, ["entropy", "-a", app, "-n", n, "--input", xprv])
        assert result.exit_code != 0
        assert "Error" in result.output

    @pytest.mark.parametrize(
        "vector",
        BIP_39,
        ids=[f"BIP_39-{v['mnemonic_length']}-words" for v in BIP_39],
    )
    def test_derive_app_39(self, runner, vector):
        xprv = vector["master"]
        n_words = vector["mnemonic_length"]
        result = runner.invoke(
            cli, ["derive", "-a", "mnemonic", "--xprv", xprv, "-n", n_words]
        )
        assert result.exit_code == 0
        words = result.output.strip()
        assert words == vector["derived_mnemonic"]


# end new class(es)


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



@pytest.mark.parametrize(
    "vector",
    BIP_39,
    ids=[f"BIP_39-{v['mnemonic_length']}-words" for v in BIP_39],
)
def test_entropy_bip39(runner, vector):
    xprv = vector["master"]
    n_words = vector["mnemonic_length"]
    result = runner.invoke(
        cli, ["entropy", "-a", "mnemonic", "--input", xprv, "-n", n_words]
    )
    assert result.exit_code == 0
    words = result.output.strip()
    assert words == vector["derived_mnemonic"]


@pytest.mark.parametrize("iso", [v["code"] for v in LANGUAGES.values()])
def test_entropy_bip39_languages(runner, iso):
    xprv = MNEMONIC_12["xprv"]
    result = runner.invoke(
        cli, ["entropy", "-a", "mnemonic", "--input", xprv, "-n", 12, "-t", iso]
    )
    assert result.exit_code == 0
    words = result.output.strip()
    assert validate_mnemonic_words(words.split(" "), ISO_TO_LANGUAGE[iso])


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


def test_seed_bad_input(runner):
    phrase = "きわめる そせい ばかり なみだ みつかる くしゃみ にあう ひみつ かくとく よけい げんき ほきょう"
    result = runner.invoke(cli, ["seed", "-f", "spa", "--input", phrase])
    assert result.exit_code != 0
    assert "not in spa" in result.output
