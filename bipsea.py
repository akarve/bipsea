"""CLI"""

import click
from submodules import generate_words, generate_from_string, generate_to_85


@click.group()
def cli():
    pass


@cli.command()
@click.option("--from-randbits", is_flag=True, help="Generate from random bits")
def to_words(from_randbits):
    if from_randbits:
        result = generate_words()
        click.echo(result)


@cli.command()
@click.option("--n-words", default=12, help="Number of words to generate")
@click.option("--from-string", default="", help="Generate from a specific string")
def to_words(n_words, from_string):
    result = generate_from_string(n_words, from_string)
    click.echo(result)


@cli.command()
@click.option("--path", required=True, help="Derivation path")
@click.argument("input", type=click.File("rb"), default="-")  # default to stdin
def to_85(path, input):
    data = input.read()
    result = generate_to_85(path, data)
    click.echo(result)


if __name__ == "__main__":
    cli()
