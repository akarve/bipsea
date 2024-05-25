"""CLI"""

import click

from const import __version__
from seedwords import entropy_to_words


SEED_FROM_VALUES = ["hex", "rand", "string", "xprv"]
SEED_TO_VALUES = ["words", "xprv"]


@click.group()
@click.version_option(version=__version__, prog_name="bipsea")
def cli():
    pass


@click.command()
@click.option(
    "-f",
    "--from",
    "from_",
    type=click.Choice(SEED_FROM_VALUES, case_sensitive=True),
    required=True,
)
@click.option("-i", "--input", default="")
@click.option(
    "-t",
    "--to",
    type=click.Choice(SEED_TO_VALUES, case_sensitive=True),
    required=True,
)
@click.option("-n", "--number", type=click.Choice([str(i) for i in range(12, 25, 3)]), default="24")
@click.option("-p", "--passphrase", default="")
def seed(from_, input, to, number, passphrase):
    if to == "words":
        entropy = None
        if from_ == "rand":
            pass
        words = entropy_to_words(int(number), entropy, passphrase)
        output = "\n".join(f"{i+1}) {w}" for i, w in enumerate(words))
    else:
        raise NotImplementedError
    click.echo(output)


cli.add_command(seed)


@click.command(name="bip85")
@click.option("-a", "--application", required=True)
@click.option("-n", "--number", type=int, default=1)
def bip85(application, number):
    # Read from stdin
    seed = click.get_text_stream("stdin").read().strip()

    # Convert the seed to base85
    result = seed_to_base85(seed, application, number)

    click.echo(result)


cli.add_command(bip85)

if __name__ == "__main__":
    cli()
