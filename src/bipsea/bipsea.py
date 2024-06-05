"""CLI"""

import logging
import re
import select
import sys

import click

from .bip32 import to_master_key
from .bip32types import parse_ext_key
from .bip39 import (
    LANGUAGES,
    N_WORDS_ALLOWED,
    entropy_to_words,
    normalize_list,
    normalize_str,
    to_master_seed,
    verify_seed_words,
)
from .bip85 import (
    APPLICATIONS,
    DRNG,
    PURPOSE_CODES,
    RANGES,
    apply_85,
    derive,
    to_entropy,
)
from .util import (
    LOGGER,
    MIN_REL_ENTROPY,
    __app_name__,
    __version__,
    relative_entropy,
    to_hex_string,
)

CODE_TO_LANG = {v["code"]: k for k, v in LANGUAGES.items()}


SEED_FROM_VALUES = [
    "any",
    "rand",
] + list(CODE_TO_LANG.keys())


SEED_TO_VALUES = [
    "tprv",
    "xprv",
] + [code for code in CODE_TO_LANG.keys()]

TIMEOUT = 0.1

N_WORDS_ALLOWED_STR = [str(n) for n in N_WORDS_ALLOWED]
N_WORDS_ALLOWED_HELP = "|".join(N_WORDS_ALLOWED_STR)


logger = logging.getLogger(LOGGER)


@click.group()
@click.version_option(version=__version__, prog_name=__app_name__)
def cli():
    pass


@click.command(name="seed", help="Generate a BIP-32 extended private key.")
@click.option(
    "-f",
    "--from",
    "from_",
    type=click.Choice(SEED_FROM_VALUES, case_sensitive=True),
    help="Input format.",
    default="rand",
)
@click.option(
    "-t",
    "--to",
    type=click.Choice(SEED_TO_VALUES, case_sensitive=True),
    default="xprv",
    help="Output format.",
)
@click.option("-u", "--input", help="Text as specified by --from")
@click.option(
    "-n",
    "--number",
    default="24",
    type=click.Choice(N_WORDS_ALLOWED_STR),
    help="Number of words.",
)
@click.option("-p", "--passphrase", default="")
@click.option(
    "--pretty/--not-pretty",
    is_flag=True,
    default=False,
    help="Number and newline between words.",
)
def bip39_cmd(from_, to, input, number, passphrase, pretty):
    input = input.strip() if input else input
    number = int(number)
    if (from_ == "rand" and input) or (from_ != "rand" and not input):
        raise click.BadOptionUsage(
            option_name="--from",
            message="`--from words` requires `--input STRING`, `--from rand` forbids `--input`",
        )
    language = CODE_TO_LANG.get(from_)
    if language or from_ == "any":
        if to == "words":
            raise click.BadOptionUsage(
                option_name="--to",
                message="`--to words` incompatible with `--from LANGUAGE`",
            )
        words = normalize_list(re.split(r"\s+", input), lower=True)
        if language and not verify_seed_words(words, language):
            raise click.BadParameter(
                f"Unexpected {language} words from `--input` ({' '.join(words)}) or bad checksum.",
                param_hint="--input",
            )
        if from_ == "any":
            implied = relative_entropy(normalize_str(input, lower=True))
            if implied < MIN_REL_ENTROPY:
                click.secho(
                    (
                        f"Warning: Relative entropy of input seems low ({implied:.2f})."
                        " Consider more complex --input."
                    ),
                    fg="yellow",
                    err=True,
                )
    else:  # from_ == rand
        entropy = None
        words = entropy_to_words(number, entropy, CODE_TO_LANG.get(to, "english"))

    if to in CODE_TO_LANG.keys():
        if pretty:
            output = "\n".join(f"{i+1}) {w}" for i, w in enumerate(words))
        else:
            output = " ".join(words)

        click.echo(output)
    else:  # to == xprv | tprv
        if pretty:
            raise click.BadOptionUsage(
                option_name="pretty",
                message="`--pretty` has no effect with `--to xprv`",
            )
        # TODO: we do the entropy measure for not-strict against the string
        # but that's not what we pass in here. here we pass in split on \s+
        # for compatibility with foreign languages but is it really what we should
        # do for the general case of arbitrary secrets?
        # if so then not space is not that significant... :/
        # * probably right thing to do is give the higher of the space or string
        # score
        seed = to_master_seed(words, passphrase)
        prv = to_master_key(seed, mainnet=to == "xprv", private=True)

        click.echo(prv)


cli.add_command(bip39_cmd)


@click.command(name="entropy", help="Derive secrets according to BIP-85")
@click.option(
    "-a",
    "--application",
    default="words",
    required=True,
    type=click.Choice(APPLICATIONS.keys(), case_sensitive=True),
)
@click.option(
    "-n",
    "--number",
    type=int,
    help="length of output (bytes, chars, or words)",
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
    help="additional int (e.g. for 'dice' sides)",
)
@click.option(
    "-u",
    "--input",
    help="`--input xprv123...` can be used instead of an input pipe `bipsea seed | bipsea entropy`",
)
def bip85_cmd(application, number, index, special, input):
    if not input:
        stdin, _, _ = select.select([sys.stdin], [], [], TIMEOUT)
        if stdin:
            lines = sys.stdin.readlines()
            if lines:
                # get just the last line because there might be a warning above
                prv = lines[-1].strip()
            else:
                no_prv()
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


if __name__ == "__main__":
    cli()
