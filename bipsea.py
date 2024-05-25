"""CLI"""
import signal

import click

from const import __version__
from seedwords import entropy_to_words


SEED_FROM_VALUES = ["hex", "rand", "string", "words", "xprv"]
SEED_TO_VALUES = ["words", "xprv"]
TIMEOUT = 1


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
@click.option("-i", "--input", default="")
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
    default="24",
)
@click.option("-p", "--passphrase", default="")
def seed(from_, input, to, number, passphrase):
    if to == "words":
        entropy = None
        if from_ == "rand":
            pass
        elif from_ == "string":
            entropy = hashlib.sha256(input.encode("utf-8")).digest()
        words = entropy_to_words(int(number), entropy, passphrase)
        output = "\n".join(f"{i+1}) {w}" for i, w in enumerate(words))
    else:
        raise NotImplementedError
    click.echo(output)

    return "bob"

cli.add_command(seed)

@click.command(name="entropy", help="BIP-85 entropy")
@click.option("-a", "--application", required=True)
@click.option("-n", "--number", type=int, default=64, help="bytes")
def bip85(application, number):
    try:
        signal.alarm(TIMEOUT)
        seed = click.get_text_stream("stdin").read().strip()
        signal.alarm(0)
    except TimeoutError:
        click.echo("No input. Try bipsea seed -t xprv | bipsea entropy")
        return

cli.add_command(bip85)


if __name__ == "__main__":
    cli()
