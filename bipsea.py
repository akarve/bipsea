"""CLI"""
import hashlib
import select
import sys
import threading

import click

from const import __version__
from seedwords import entropy_to_words


SEED_FROM_VALUES = ["hex", "rand", "words", "xprv"]
SEED_TO_VALUES = ["words", "xprv"]
TIMEOUT = 1


class InputThread(threading.Thread):
    def run(self):
        self.seed = click.get_text_stream("stdin").read().strip()

def validate_number(ctx, param, value):
    from_ = ctx.params.get('from_')
    if from_ == 'words' and value is not None:
        raise click.BadParameter("Omit --number when you call `bipsea --from words`")

    return value

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
    default="24",
    callback=validate_number,
)
@click.option("-p", "--passphrase", default="")
def seed(from_, input, to, number, passphrase):
    if to == "words":
        entropy = None
        if from_ == "rand":
            pass
        elif from_ == "string":
            entropy = hashlib.sha256(input.encode("utf-8")).digest()
        elif from_ == "words":
            pass

        words = entropy_to_words(int(number), entropy, passphrase)
        output = "\n".join(f"{i+1}) {w}" for i, w in enumerate(words))
    else:
        raise NotImplementedError
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
        click.echo(
            "bipsea entropy received no input. Try `bipsea seed -t xprv | bipsea entropy -a foo`"
        )

cli.add_command(bip85)


if __name__ == "__main__":
    cli()
