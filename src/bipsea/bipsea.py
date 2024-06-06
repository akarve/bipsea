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
    INDEX_TO_LANGUAGE,
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

ISO_TO_LANGUAGE = {v["code"]: k for k, v in LANGUAGES.items()}

SEED_FROM_VALUES = [
    "any",
    "random",
] + list(ISO_TO_LANGUAGE.keys())


SEED_TO_VALUES = [
    "tprv",
    "xprv",
] + list(ISO_TO_LANGUAGE.keys())


ENTROPY_TO_VALUES = list(ISO_TO_LANGUAGE.keys())

N_WORDS_ALLOWED_STR = [str(n) for n in N_WORDS_ALLOWED]

TIMEOUT = 0.08


logger = logging.getLogger(LOGGER)


@click.group()
@click.version_option(version=__version__, prog_name=__app_name__)
def cli():
    pass


@click.command(
    name="seed", help="Generates a BIP-32 extended private key or a BIP-39 mnemonic."
)
@click.option(
    "-f",
    "--from",
    "from_",
    type=click.Choice(SEED_FROM_VALUES),
    help=(
        "Mnemonic input format. 'any' skips validation, 'random' makes a fresh phrase, "
        "'ISO_CODE' validates `--input` against a BIP-39 wordlist."
    ),
    default="random",
)
@click.option(
    "-t",
    "--to",
    type=click.Choice(SEED_TO_VALUES),
    default="xprv",
    help="Output format. 'tprv', 'xprv', or 'ISO_CODE' for the mnemonic.",
)
@click.option(
    "-u",
    "--input",
    help="Mnemonic phrase, usually space-separated, in the format specified by --from.",
)
@click.option(
    "-n",
    "--number",
    default="24",
    type=click.Choice(N_WORDS_ALLOWED_STR),
    help="Number of mnemonic words.",
)
@click.option("-p", "--passphrase", default="", help="BIP-39 passphrase.")
@click.option(
    "--pretty/--not-pretty",
    is_flag=True,
    default=False,
    help="Print a number before, and a newline after, each mnemonic word.",
)
def bip39_cmd(from_, to, input, number, passphrase, pretty):
    if input:
        input = input.strip()
    number = int(number)

    if from_ != "random":
        if not input:
            raise click.BadOptionUsage(
                option_name="--from",
                message="`--from [any|language]` requires `--input`",
            )
        if not to.endswith("prv"):
            raise click.BadOptionUsage(
                option_name="--to",
                message=f"`--to {to}` requires `--from rand`",
            )
        words = normalize_list(re.split(r"\s+", input), lower=True)
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
        else:
            language = ISO_TO_LANGUAGE[from_]
            if not verify_seed_words(words, language):
                raise click.BadParameter(
                    f"mnemonic not in {ISO_TO_LANGUAGE[from_]} wordlist or has bad checksum.",
                    param_hint="--input",
                )
    else:
        if input:
            raise click.BadOptionUsage(
                option_name="--from",
                message="``--from rand` forbids `--input`",
            )
        entropy = None
        words = entropy_to_words(number, entropy, ISO_TO_LANGUAGE.get(to, "english"))

    if to in ISO_TO_LANGUAGE.keys():
        if pretty:
            output = "\n".join(f"{i + 1}) {w}" for i, w in enumerate(words))
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


@click.command(name="entropy", help="Derives a secret according to BIP-85.")
@click.option(
    "-a",
    "--application",
    default="mnemonic",
    required=True,
    type=click.Choice(APPLICATIONS.keys()),
)
@click.option(
    "-n",
    "--number",
    type=int,
    help="Length of output in bytes, chars, or words, depending on --application.",
)
@click.option(
    "-i",
    "--index",
    type=click.IntRange(0, 2**31 - 1),
    default=0,
    help="Child index. Increment for fresh secrets.",
)
@click.option(
    "-s",
    "--special",
    default=10,
    type=click.IntRange(min=2),
    help="Number of sides for `--application dice`.",
)
@click.option(
    "-u",
    "--input",
    help="An xprv. Alternatively  you can `echo $XPRV | bipsea entropy`.",
)
@click.option(
    "-t",
    "--to",
    type=click.Choice(ENTROPY_TO_VALUES),
    help="Output language for `--application mnemonic`.",
)
def bip85_cmd(application, number, index, special, input, to):
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

    if to:
        if application != "mnemonic":
            raise click.BadOptionUsage(
                option_name="--to",
                message="--to requires `--application mnemonic`",
            )
    else:
        to = "eng"

    if application == "mnemonic":
        language = ISO_TO_LANGUAGE[to]
        code_85 = next(i for i, l in INDEX_TO_LANGUAGE.items() if l == language)
        path += f"/{code_85}/{number}'/{index}'"
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
            message=f"--number out of range. Try [{min}, {max}] for {application}.",
        )


def no_prv():
    raise click.BadOptionUsage(
        option_name="--input",
        message="Missing xprv or tprv from pipe or --input. Try `bipsea seed | bipsea entropy`.",
    )


if __name__ == "__main__":
    cli()
