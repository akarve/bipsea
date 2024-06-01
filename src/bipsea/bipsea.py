"""CLI"""

import logging
import math
import re
import select
import string
import sys
import threading
from collections import Counter

import click

from .bip32 import to_master_key
from .bip32types import parse_ext_key
from .bip39 import N_WORDS_ALLOWED, entropy_to_words, to_master_seed, verify_seed_words
from .bip85 import (
    APPLICATIONS,
    DRNG,
    PURPOSE_CODES,
    RANGES,
    apply_85,
    derive,
    to_entropy,
)
from .util import LOGGER, __app_name__, __version__, to_hex_string

MIN_ENTROPY = 256
SEED_FROM_VALUES = [
    "rand",
    "words",
]
SEED_TO_VALUES = [
    "words",
    "tprv",
    "xprv",
]
TIMEOUT = 0.1

N_WORDS_ALLOWED_STR = [str(n) for n in N_WORDS_ALLOWED]
N_WORDS_ALLOWED_HELP = "|".join(N_WORDS_ALLOWED_STR)


logger = logging.getLogger(LOGGER)
logger.setLevel(logging.DEBUG)


@click.group()
@click.version_option(version=__version__, prog_name=__app_name__)
def cli():
    pass


@click.command(
    name="seed", help="Generate an extended master private key (BIP-32, BIP-39)"
)
@click.option(
    "-f",
    "--from",
    "from_",
    type=click.Choice(SEED_FROM_VALUES, case_sensitive=True),
    required=True,
    help="|".join(SEED_FROM_VALUES),
    default="rand",
)
@click.option("-i", "--input", help="String in the format specified by --from")
@click.option(
    "-t",
    "--to",
    type=click.Choice(SEED_TO_VALUES, case_sensitive=True),
    default="xprv",
    help="|".join(SEED_TO_VALUES),
    required=True,
)
@click.option(
    "-n",
    "--number",
    default="24",
    type=click.Choice(N_WORDS_ALLOWED_STR),
)
@click.option("-p", "--passphrase", default="")
@click.option(
    "--pretty", is_flag=True, default=False, help="Number and separate seed words"
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Allow only checksummed BIP-39 English words",
)
def bip39_cmd(from_, input, to, number, passphrase, pretty, strict):
    if input:
        input = input.strip()
    number = int(number)
    if (from_ == "rand" and input) or (from_ != "rand" and not input):
        raise click.BadOptionUsage(
            option_name="--from",
            message="`--from words` requires `--input STRING`, `--from rand` forbids `--input`",
        )
    if from_ == "words":
        words = re.split(r"\s+", input)
        n_words = len(words)
        if strict:
            if not verify_seed_words("english", words):
                raise click.BadOptionUsage(
                    option_name="--input",
                    message=f"Non BIP-39 words from `--input` ({' '.join(words)}) or bad BIP-39 checksum",
                )
        else:
            implied = implied_entropy(input)
            if implied < MIN_ENTROPY:
                click.secho(
                    (
                        f"Warning: {implied} bits of implied entropy is less than the"
                        f"recommended {MIN_ENTROPY} bits."
                    )
                )
        entropy = to_master_seed(words, passphrase)
    else:  # from_ == "rand"
        entropy = None
        if strict:
            raise click.BadOptionUsage(
                option_name="--strict",
                message="`--strict` requires `--from words`",
            )
        words = entropy_to_words(n_words=number, user_entropy=entropy)
    if to == "words":
        if from_ == "words":
            raise click.BadOptionUsage(
                option_name="--to",
                message="`--to words` incompatible with `--from words`",
            )
        output = " ".join(words)
        if pretty:
            output = "\n".join(f"{i+1}) {w}" for i, w in enumerate(words))

        click.echo(output)

    elif to in ("tprv", "xprv"):
        if pretty:
            raise click.BadOptionUsage(
                option_name="pretty",
                message="`--pretty` has no effect with `--to xprv`",
            )
        mainnet = to == "xprv"
        seed = to_master_seed(words, passphrase)
        kprv = to_master_key(seed, mainnet=mainnet, private=True)

        click.echo(kprv)


cli.add_command(bip39_cmd)


@click.command(name="entropy", help="Derive secrets according to BIP-85")
@click.option(
    "-a",
    "--application",
    default="words",
    required=True,
    help="|".join(APPLICATIONS.keys()),
    type=click.Choice(APPLICATIONS.keys(), case_sensitive=True),
)
@click.option(
    "-n",
    "--number",
    type=int,
    help="desired length for derived entropy (bytes, chars, or words)",
)
@click.option(
    "-i",
    "--index",
    type=click.IntRange(0, 2**31 - 1),
    default=0,
    help="child index",
)
@click.option(
    "-s",
    "--special",
    default=10,
    type=int,
    help="Additional integer (e.g. for 'dice' sides)",
)
@click.option(
    "-p",
    "--input",
    help="`--input xprv123...` can be used instead of an input pipe `bipsea seed | bipsea entropy`",
)
def bip85_cmd(application, number, index, special, input):
    if not input:
        stdin, _, _ = select.select([sys.stdin], [], [], TIMEOUT)
        if stdin:
            prv = sys.stdin.readline().strip()
        else:
            no_prv()
    else:
        prv = input
    if number is not None:
        number = int(number)
        if application in ("wif", "xprv"):
            raise click.BadOptionUsage(
                option_name="--number",
                message="`--number` has no effect when `--application wif|xprv`",
            )
        elif number < 1:
            raise click.BadOptionUsage(
                option_name="--number",
                message="must be a positive integer",
            )
    else:
        number = 24
    if not prv[:4] in ("tprv", "xprv"):
        no_prv()
    master = parse_ext_key(prv)

    path = f"m/{PURPOSE_CODES['BIP-85']}"
    app_code = APPLICATIONS[application]
    path += f"/{app_code}"
    if application == "words":
        if number not in N_WORDS_ALLOWED:
            raise click.BadOptionUsage(
                option_name="--number",
                message=f"`--application wif` requires `--number NUMBER` in {N_WORDS_ALLOWED_HELP}",
            )
        path += f"/0'/{number}'/{index}'"
    elif application in ("wif", "xprv"):
        path += f"/{index}'"
    elif application in ("base64", "base85", "hex"):
        check_range(number, application)
        path += f"/{number}'/{index}'"
    elif application == "drng":
        path += f"/0'/{index}'"
    elif application == "dice":
        check_range(number, application)
        path += f"/{special}'/{number}'/{index}'"
    else:
        raise click.BadOptionUsage(
            option_name="--application",
            message=f"unrecognized {application}",
        )

    derived = derive(master, path)
    if application == "drng":
        drng = DRNG(to_entropy(derived.data[1:]))
        output = to_hex_string(drng.read(number))
    else:
        output = apply_85(derived, path)["application"]
    click.echo(output)


cli.add_command(bip85_cmd)


def check_range(number: int, application: str):
    (min, max) = RANGES[application]
    if not (min <= number <= max):
        raise click.BadOptionUsage(
            option_name="--number",
            message=f"out of range; try [{min}, {max}] for {application}",
        )


def no_prv():
    raise click.BadOptionUsage(
        option_name="[incoming pipe]",
        message="Bad input. Need xprv or tprv. Try `bipsea seed` | bipsea entropy`",
    )


def implied_entropy(s):
    return math.floor(math.log(len(s) ** len(string.printable), 2))


if __name__ == "__main__":
    cli()
