"""Adapter functions to convert protocol types to Click constructs."""

from typing import Any

import click

from .app_protocol import Param


def param_to_click_option(param: Param) -> tuple[tuple[str, ...], dict[str, Any]]:
    """Convert a Param to click.option arguments.

    Returns:
        (flags, kwargs) tuple for use with click.option(*flags, **kwargs)
    """
    kwargs: dict[str, Any] = {"help": param.help}

    if param.required:
        kwargs["required"] = True
    if param.default is not None:
        kwargs["default"] = param.default

    # Type resolution: choices > range > raw type
    if param.choices is not None:
        kwargs["type"] = click.Choice(param.choices)
    elif param.range is not None:
        kwargs["type"] = click.IntRange(*param.range)
    else:
        kwargs["type"] = param.type

    return param.flags, kwargs
