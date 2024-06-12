import logging
import random
import subprocess
import sys
import tempfile
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from data.bip39_vectors import VECTORS
from data.bip85_vectors import (
    BIP_39,
    COMMON_XPRV,
    DICE,
    HEX,
    PWD_BASE64,
    PWD_BASE85,
    WIF,
)

from bipsea.bip32types import validate_prv_str
from bipsea.bip39 import LANGUAGES, validate_mnemonic_words
from bipsea.bipsea import ISO_TO_LANGUAGE, N_WORDS_ALLOWED, cli, try_for_pipe_input
from bipsea.util import ASCII_INPUTS, LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME)


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
    def test_wrong_language(self, runner):
        mnemonic = "きわめる そせい ばかり なみだ みつかる くしゃみ にあう ひみつ かくとく よけい げんき ほきょう"
        result = runner.invoke(cli, ["validate", "-f", "spa", "-m", mnemonic])
        assert result.exit_code != 0
        assert "Non-spanish" in result.output

    @pytest.mark.parametrize(
        "size, num", [("one", 1), ("under", 8), ("at", 9), ("over", 400)]
    )
    def test_free_mnemonics(self, runner, size, num):
        cmd = ["validate", "-f", "free", "-m", self.gen_free_ascii_mnemonic(num)]
        result = runner.invoke(cli, cmd)
        assert result.exit_code == 0
        if size in ("one", "under"):
            assert "Warning" in result.output
        else:
            assert "Warning" not in result.output

    def gen_free_ascii_mnemonic(self, length: int, seed: int = 0):
        random.seed(seed)
        custom = "".join(
            random.choice("".join(sorted(list(ASCII_INPUTS)))) for _ in range(length)
        )

        return custom


class TestXPRV:
    @pytest.mark.slow  # calls PBKDF2 a lot
    @pytest.mark.parametrize("vectors", VECTORS.values(), ids=VECTORS.keys())
    def test_bip_39_vectors(self, runner, vectors):
        for vector in vectors:
            _, mnemonic, _, xprv = vector
            result = runner.invoke(
                cli, ["xprv", "--mnemonic", mnemonic, "-p", "TREZOR"]
            )
            assert result.exit_code == 0
            last = result.output.strip().split("\n")[-1]
            assert last == xprv

    @pytest.mark.slow  # calls PBKDF2 a lot
    @pytest.mark.parametrize("vector", VECTORS["english"])
    def test_english_vectors_change_passphrase(self, runner, vector):
        """prove that meaningful passphrase and mnemonic changes change the xprv
        (but white space around the mnemonic does not)"""
        _, mnemonic, _, xprv = vector
        change_passphrase = runner.invoke(cli, ["xprv", "-m", mnemonic, "-p", "TREZoR"])
        assert change_passphrase.exit_code == 0
        result_xprv = change_passphrase.output.strip().split("\n")[-1]
        assert result_xprv != xprv

    @pytest.mark.slow  # calls PBKDF2 a lot
    @pytest.mark.parametrize("fix", ("x", " \t\n "), ids=lambda x: f"add-{x}")
    @pytest.mark.parametrize("vector", VECTORS["english"])
    def test_english_vectors_change_mnemonic(self, runner, vector, fix):
        _, mnemonic, _, xprv = vector
        cmd = ["xprv", "--mnemonic", fix + mnemonic + fix, "-p", "TREZOR"]
        result = runner.invoke(cli, cmd)
        assert result.exit_code == 0
        result_xprv = result.output.strip().split("\n")[-1]
        if fix == "x":
            assert result_xprv != xprv
        else:
            assert result_xprv == xprv

    @pytest.mark.parametrize(
        "mainnet", (True, False), ids=lambda x: "mainnet" if x else "testnet"
    )
    def test_testnet(self, runner, mainnet):
        xprv_cmd = [
            "xprv",
            "-m",
            MNEMONIC_12["words"],
            "--mainnet" if mainnet else "--testnet",
        ]
        xprv_result = runner.invoke(cli, xprv_cmd)
        assert xprv_result.exit_code == 0
        output = xprv_result.output.strip()
        assert validate_prv_str(output, private=True)
        if mainnet:
            assert output == MNEMONIC_12["xprv"]
        else:
            assert output.startswith("tprv")


class TestMnemonicAndValidate:
    @pytest.mark.parametrize("n", N_WORDS_ALLOWED)
    @pytest.mark.parametrize("style", ("--pretty", "--not-pretty"), ids=lambda x: x[2:])
    @pytest.mark.parametrize("lang", ISO_TO_LANGUAGE.keys())
    def test_commands(self, runner, n, style, lang):
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
    @pytest.mark.parametrize("n", (20, 50, 64))
    @pytest.mark.parametrize("app", ("base64", "base85", "hex", "drng"))
    def test_password_length(self, runner, app, n):
        xprv = COMMON_XPRV
        result = runner.invoke(cli, ["derive", "-a", app, "-n", n, "-x", xprv])
        assert result.exit_code == 0
        answer = result.output.strip()
        length = len(answer)
        if app in ("hex", "drng"):
            length = length // 2
        assert length == n

    @pytest.mark.parametrize("n", (20, 50, 64))
    @pytest.mark.parametrize("app", ("base64", "base85", "hex", "drng"))
    def test_n(self, runner, app, n):
        xprv = COMMON_XPRV
        result = runner.invoke(cli, ["derive", "-a", app, "-n", n, "--xprv", xprv])
        assert result.exit_code == 0
        answer = result.output.strip()
        length = len(answer)
        if app in ("hex", "drng"):
            length = length // 2
        assert length == n

    @pytest.mark.parametrize("n", (-1, 0, 1025))
    @pytest.mark.parametrize("app", ["base64", "base85", "hex", "drng"])
    def test_bad_n(self, runner, app, n):
        xprv = COMMON_XPRV
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
    def test_mnemonic(self, runner, vector):
        xprv = vector["master"]
        n_words = vector["mnemonic_length"]
        result = runner.invoke(
            cli, ["derive", "-a", "mnemonic", "--xprv", xprv, "-n", n_words]
        )
        assert result.exit_code == 0
        words = result.output.strip()
        assert words == vector["derived_mnemonic"]

    @pytest.mark.parametrize("iso", [v["code"] for v in LANGUAGES.values()])
    def test_mnemonic_languages(self, runner, iso):
        xprv = MNEMONIC_12["xprv"]
        result = runner.invoke(
            cli, ["derive", "-a", "mnemonic", "-x", xprv, "-n", 12, "-t", iso]
        )
        assert result.exit_code == 0
        words = result.output.strip()
        assert validate_mnemonic_words(words.split(" "), ISO_TO_LANGUAGE[iso])

    @pytest.mark.parametrize("vector", DICE)
    def test_dice(self, runner, vector):
        xprv = vector["master"]
        result = runner.invoke(
            cli, ["derive", "-a", "dice", "-x", xprv, "-n", 10, "-s", 6]
        )
        assert result.exit_code == 0
        assert result.output.strip() == vector["derived_rolls"]

    @pytest.mark.parametrize("vector", HEX)
    def test_hex(self, runner, vector):
        xprv = vector["master"]
        result = runner.invoke(cli, ["derive", "-a", "hex", "-x", xprv, "-n", 64])
        assert result.exit_code == 0
        assert result.output.strip() == vector["derived_entropy"]

    @pytest.mark.parametrize("vector", WIF)
    def test_wif(self, runner, vector):
        xprv = vector["master"]
        result = runner.invoke(cli, ["derive", "-a", "wif", "-x", xprv])
        assert result.exit_code == 0
        assert result.output.strip() == vector["derived_wif"]

    @pytest.mark.parametrize("vector", PWD_BASE64)
    def test_base64(self, runner, vector):
        xprv = vector["master"]
        result = runner.invoke(cli, ["derive", "-a", "base64", "-x", xprv, "-n", 21])
        assert result.exit_code == 0
        assert result.output.strip() == vector["derived_pwd"]

    @pytest.mark.parametrize("vector", PWD_BASE85)
    def test_base85(self, runner, vector):
        xprv = vector["master"]
        result = runner.invoke(cli, ["derive", "-a", "base85", "-x", xprv, "-n", 12])
        assert result.exit_code == 0
        assert result.output.strip() == vector["derived_pwd"]

    def test_bad_application(self, runner):
        result = runner.invoke(
            cli, ["derive", "-x", MNEMONIC_12["xprv"], "--application", "google"]
        )
        assert result.exit_code != 0
        logger.debug(result.output)
        assert "application" in result.output

    @pytest.mark.parametrize("app", ("wif", "xprv"))
    def test_num_not_allowed(self, runner, app):
        result = runner.invoke(
            cli, ["derive", "-x", MNEMONIC_12["xprv"], "--application", app, "-n", 2]
        )
        assert result.exit_code != 0
        logger.debug(result.output)
        assert "--number" in result.output

    def test_bad_xprv(self, runner):
        result = runner.invoke(
            cli, ["derive", "-x", MNEMONIC_12["xprv"][1:], "--application", "mnemonic"]
        )
        assert result.exit_code != 0
        assert "Invalid" in result.output
        assert "--xprv" in result.output


class TestIntegration:
    def test_chain_no_pipe(self, runner):
        """this also tests that the default options are compatible"""
        mnemonic_result = runner.invoke(cli, ["mnemonic"])
        assert mnemonic_result.exit_code == 0
        mnemonic = mnemonic_result.output.strip()

        validate_result = runner.invoke(cli, ["validate", "-m", mnemonic])
        assert validate_result.exit_code == 0
        validate = validate_result.output.strip()
        assert mnemonic == validate

        xprv_result = runner.invoke(cli, ["xprv", "-m", validate])
        assert xprv_result.exit_code == 0
        xprv = xprv_result.output.strip()

        derive_result = runner.invoke(
            cli, ["derive", "-x", xprv, "-a", "mnemonic", "-n", "12", "-t", "jpn"]
        )
        assert derive_result.exit_code == 0
        words = derive_result.output.splitlines()[-1].strip()
        assert validate_mnemonic_words(words.split(" "), "japanese")

    @pytest.mark.parametrize("input", ("m", 1, "\t"))
    def test_too_short_inputs(self, runner, input):
        for cmd in ("validate", "xprv"):
            bad_m_result = runner.invoke(cli, [cmd, "-m", input])
            assert bad_m_result.exit_code != 0
            assert "Error" in bad_m_result.output

        for cmd in "derive":
            bad_x_result = runner.invoke(cli, ["derive", "-x", input, "-a", "base85"])
            assert bad_x_result.exit_code != 0
            assert "Error" in bad_x_result.output

    def test_try_for_pipe_input(self, monkeypatch):
        test_input = "test input"
        monkeypatch.setattr(sys, "stdin", StringIO(test_input))
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        assert try_for_pipe_input() == test_input.strip()

        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        assert try_for_pipe_input() == ""

    @pytest.mark.parametrize(
        "cmd, opt", [("validate", "-m"), ("derive", "-m"), ("xprv", "-x")]
    )
    def test_no_m(self, runner, cmd, opt):
        result = runner.invoke(cli, [cmd, opt])
        assert result.exit_code != 0
        assert "Error" in result.output

    groups = {
        "help": [
            "bipsea --version",
            "bipsea --help",
            "bipsea mnemonic --help",
            "bipsea validate --help",
            "bipsea xprv --help",
            "bipsea derive --help",
        ],
        "all-defaults": [
            "bipsea mnemonic | bipsea validate | bipsea xprv | bipsea derive -a mnemonic -n 12",
        ],
        "mnemonic": [
            "bipsea mnemonic -t jpn -n 15",
            "bipsea mnemonic -n 12 --pretty",
            "bipsea mnemonic -t spa -n 12 | bipsea validate -f spa",
            "bipsea mnemonic | bipsea validate",
            "bipsea mnemonic | bipsea validate | bipsea xprv",
        ],
        "all-fixed": [
            'bipsea xprv -m "elder major green sting survey canoe inmate funny bright jewel anchor volcano" | bipsea derive -a mnemonic -n 12',
        ],
        "validate": [
            'bipsea validate -f free -m "123456123456123456" | bipsea xprv',
            'bipsea validate -f free -m "$(cat input.txt)"',
        ],
        "derive": [
            'bipsea validate -m "elder major green sting survey canoe inmate funny bright jewel anchor volcano" | bipsea xprv | bipsea derive -a base85',
            'bipsea validate -m "elder major green sting survey canoe inmate funny bright jewel anchor volcano" | bipsea xprv | bipsea derive -a mnemonic -t jpn -n 12',
            'bipsea validate -m "elder major green sting survey canoe inmate funny bright jewel anchor volcano" | bipsea xprv | bipsea derive -a drng -n 1000',
            'bipsea validate -m "elder major green sting survey canoe inmate funny bright jewel anchor volcano" | bipsea xprv | bipsea derive -a dice -n 100 -s 6',
        ],
    }

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "group, commands",
        groups.items(),
        ids=[f"{group}-{len(commands)}" for group, commands in groups.items()],
    )
    def test_commands(self, group, commands):
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as script:
            script.write("#!/bin/sh\n")
            for cmd in commands:
                script.write(cmd + "\n")
            script.flush()

        Path(script.name).chmod(0o755)

        try:
            result = subprocess.run(
                ["poetry", "run", script.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert result.returncode == 0, (
                f"Group failed: {group}\n"
                f"Output: {result.stdout}\n"
                f"Error: {result.stderr}"
            )
        finally:
            Path(script.name).unlink()
