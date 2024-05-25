"""CLI"""

import hashlib
import select
import sys
import threading

import click

from const import __version__
from seedwords import entropy_to_words, to_seed


SEED_FROM_VALUES = ["hex", "rand", "words", "xprv"]
SEED_TO_VALUES = ["words", "xprv"]
TIMEOUT = 1


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
    required=True,
)
@click.option(
    "-n",
    "--number",
    type=click.Choice([str(i) for i in range(12, 25, 3)]),
)
@click.option("-p", "--passphrase", default="")
def seed(from_, input, to, number, passphrase):
    if to not in SEED_TO_VALUES:
        raise click.BadOptionUsage(option_name="--to", message=f"must be one of {'|'.join(SEED_TO_VALUES)}")
    if from_ not in SEED_FROM_VALUES:
        raise click.BadOptionUsage(option_name="--from", message=f"must be one of {'|'.join(SEED_FROM_VALUES)}")
    if from_ != "rand" and not input:
        raise click.BadOptionUsage(option_name="--from", message="--input is required unless --from rand")
    if from_ == "words":
        if number:
            raise click.BadOptionUsage(option_name="--number", message="omit --number when you specify --from words")
        if to == "words":
            raise click.BadOptionUsage(option_name="--to", message="--from words is redundant with --to words")
    number = 24  # set default here so it doesn't trip the above logic
    if to == "words":
        entropy = None
        if from_ == "rand":
            pass
        elif from_ == "string":
            entropy = hashlib.sha256(input.encode("utf-8")).digest()
        elif from_ == "words":
            click.BadParameter("`--from words --to words` is weirdly redundant")
        number = number if number else 24  # do this here so we don't break callback validation with defaults
        words = entropy_to_words(int(number), entropy, passphrase)
        output = "\n".join(f"{i+1}) {w}" for i, w in enumerate(words))
    click.echo(output)


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
