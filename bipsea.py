"""CLI"""

import hashlib
import logging
import re
import select
import sys
import threading

import click

from bip32 import to_master_key
from const import __version__, LOGGER
from seedwords import entropy_to_words, to_seed


SEED_FROM_VALUES = ["string", "rand", "words"]
SEED_TO_VALUES = ["words", "tprv", "xprv"]
SEED_N_RANGE_STR = list([str(i) for i in range(12, 25, 3)])
TIMEOUT = 1


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
    type=click.Choice(SEED_N_RANGE_STR),
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
            message="--input is required unless you say --from rand",
        )
    if from_ == "words":
        if number:
            raise click.BadOptionUsage(
                option_name="--number",
                message="omit --number when you specify --from words",
            )
        if to == "words":
            raise click.BadOptionUsage(
                option_name="--to", message="--from words --to words is redundant"
            )
        words = re.split(r"\s+", input)
        n_words = len(words)
        if not str(n_words) in SEED_N_RANGE_STR:
            raise click.BadOptionUsage(
                option_name="--input",
                message=f"invalid number of words {n_words}",
            )
    else:
        if not number:
            number = 24  # set here so we don't falsely trip `if number` above
        if from_ == "string":
            entropy = hashlib.sha256(input.encode("utf-8")).digest()
        elif from_ == "rand":
            entropy = None
        words = entropy_to_words(int(number), entropy, passphrase)
    if to == "words":
        output = " ".join(words)
        if pretty:
            output = "\n".join(f"{i+1}) {w}" for i, w in enumerate(words))
        click.echo(output)
    elif to in {"tprv", "xprv"}:
        if pretty:
            raise click.BadOptionUsage(
                option_name="--pretty", message="--pretty has no effect on --to xprv"
            )
        mainnet = to == "xprv"
        prv = to_master_key(to_seed(words, passphrase), mainnet=mainnet, private=True)
        click.echo(str(prv))


cli.add_command(seed)


@click.command(name="entropy", help="Derive entropy according to BIP-85")
@click.option("-a", "--application", required=True)
@click.option("-n", "--number", type=int, default=64, help="bytes")
def bip85(application, number):
    i, o, e = select.select([sys.stdin], [], [], TIMEOUT)
    if i:
        seed = sys.stdin.readline().strip()
        click.echo(seed)
    else:
        click.echo("Missing input: try `bipsea seed -t xprv | bipsea entropy -a foo`")


cli.add_command(bip85)


if __name__ == "__main__":
    cli()
