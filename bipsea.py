"""CLI"""

import hashlib
import logging
import re
import select
import sys
import threading

import click

from bip32 import to_master_key
from bip32types import parse_ext_key
from bip85 import DRNG, PURPOSE_CODES, apply_85, derive, to_entropy
from seedwords import (
    N_WORDS_ALLOWED,
    bip39_english_words,
    entropy_to_words,
    to_master_seed,
    warn_stretching,
)
from util import LOGGER, __version__, to_hex_string

SEED_FROM_VALUES = [
    "string",
    "rand",
    "words",
]
SEED_TO_VALUES = [
    "words",
    "tprv",
    "xprv",
]
TIMEOUT = 1

APPLICATIONS = {
    "base64": "707764'",
    "base85": "707785'",
    "drng": None,
    "hex": "128169'",
    "words": "39'",
    "wif": "2'",
    "xprv": "32'",
}

N_WORDS_ALLOWED_HELP = "|".join(str(n) for n in N_WORDS_ALLOWED)


logger = logging.getLogger(LOGGER)


class InputThread(threading.Thread):
    def run(self):
        self.seed = click.get_text_stream("stdin").read().strip()


@click.group()
@click.version_option(version=__version__, prog_name="bipsea")
def cli():
    pass


@click.command(help="Generate a master private seed")
@click.option(
    "-f",
    "--from",
    "from_",
    type=click.Choice(SEED_FROM_VALUES, case_sensitive=True),
    required=True,
    help="|".join(SEED_FROM_VALUES),
    default="rand",
)
@click.option("-i", "--input", help="string in the format specified by --from")
@click.option(
    "-t",
    "--to",
    type=click.Choice(SEED_TO_VALUES, case_sensitive=True),
    default="words",
    help="|".join(SEED_TO_VALUES),
    required=True,
)
@click.option(
    "-n",
    "--number",
    type=click.Choice(N_WORDS_ALLOWED),
)
@click.option("-p", "--passphrase", default="")
@click.option(
    "--pretty", is_flag=True, default=False, help="number and separate seed words"
)
def seed(from_, input, to, number, passphrase, pretty):
    if input:
        input = input.strip()
    if (from_ == "rand" and input) or (from_ != "rand" and not input):
        raise click.BadOptionUsage(
            option_name="--from",
            message="--input is required (unless --from rand)",
        )
    if from_ == "words":
        if number:
            raise click.BadOptionUsage(
                option_name="--number",
                message="omit when you specify --from words",
            )
        if to == "words":
            raise click.BadOptionUsage(
                option_name="--to", message="--from words is redundant"
            )
        words = re.split(r"\s+", input)
        n_words = len(words)
        if not n_words in N_WORDS_ALLOWED:
            raise click.BadOptionUsage(
                option_name="--number",
                message=f"--",
            )
    else:
        if not number:
            number = 24  # set here so we don't falsely trip `if number` above
        else:
            number = int(number)
        if from_ == "string":
            string_bytes = input.encode("utf-8")
            # this is how entropy works out in BIP-39
            target_bits = 128 + ((number - 12) // 3) * 32
            short = len(string_bytes) * 8 - target_bits
            if short < 0:
                warn_stretching(short + target_bits, target_bits)
            entropy = hashlib.sha256(string_bytes).digest()
        elif from_ == "rand":
            entropy = None
        words = entropy_to_words(
            n_words=int(number), user_entropy=entropy, passphrase=passphrase
        )
    if to == "words":
        english_words = set(bip39_english_words())
        if not all(w in english_words for w in words):
            raise click.BadOptionUsage(
                option_name="--from words --input",
                message=f"One or more words not in BIP-39 English list {words}",
            )
        output = " ".join(words)
        if pretty:
            output = "\n".join(f"{i+1}) {w}" for i, w in enumerate(words))

        click.echo(output)

    elif to in ("tprv", "xprv"):
        if pretty:
            raise click.BadOptionUsage(
                option_name="--pretty", message="--pretty has no effect on --to xprv"
            )
        mainnet = to == "xprv"
        seed = to_master_seed(words, passphrase)
        kprv = to_master_key(seed, mainnet=mainnet, private=True)

        click.echo(kprv)


cli.add_command(seed)


@click.command(name="entropy", help="Derive entropy according to BIP-85")
@click.option(
    "-a",
    "--application",
    required=True,
    help="|".join(APPLICATIONS.keys()),
    type=click.Choice(APPLICATIONS.keys(), case_sensitive=True),
)
@click.option(
    "-n",
    "--number",
    type=int,
    help="target length for derived entropy (in bytes, chars, or words)",
)
@click.option(
    "-i",
    "--index",
    type=click.IntRange(0, 2**31 - 1),
    default=0,
    help="child index",
)
def bip85(application, number, index):
    stdin, o, stderr = select.select([sys.stdin], [], [sys.stderr], TIMEOUT)
    if number:
        if application in {"wif"}:
            raise click.BadOptionUsage(
                option_name="--number",
                message="--number has no effect when --application wif",
            )
    else:
        number = 18
    if stdin:
        logger.debug(stdin)
        prv = sys.stdin.readline().strip()
        assert prv[:4] in ("tprv", "xprv")
        master = parse_ext_key(prv)

        path = f"m/{PURPOSE_CODES['BIP-85']}"
        app_value = APPLICATIONS[application]
        path += f"/{app_value}" if app_value else ""
        if application == "words":
            if number not in N_WORDS_ALLOWED:
                raise click.BadOptionUsage(
                    option_name="--number",
                    message=f"--application wif requires --number in {N_WORDS_ALLOWED_HELP}",
                )
            path += f"/0'/{number}'/{index}'"
        elif application in ("wif", "xprv"):
            path += f"/{index}'"
        elif application in ("hex", "base64", "base85"):
            path += f"/{number}'/{index}'"
        else:
            assert application == "drng"
            # TODO file to 85: not clear structure of master root keys; is it {0'}/{index}'?
            path += f"0'{index}"

        derived = derive(master, path)

        if application == "drng":
            drng = DRNG(to_entropy(master.data[1:]))
            output = to_hex_string(drng.read(number))
        else:
            output = apply_85(derived, path)["application"]

        click.echo(output)
    else:
        click.echo("Missing input: try `bipsea seed -t xprv | bipsea entropy -a foo`")


cli.add_command(bip85)


if __name__ == "__main__":
    cli()
