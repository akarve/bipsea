from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, Tuple, runtime_checkable

import click


@dataclass(frozen=True)
class Param:
    name: str
    flags: tuple[str, ...]
    type: type
    required: bool = False
    default: Any = None
    range: Optional[Tuple[Optional[int], Optional[int]]] = None
    choices: Optional[list[str]] = None
    help: str = ""
    role: Optional[str] = None

    def click_option_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"help": self.help}
        if self.required:
            kwargs["required"] = True
        if self.default is not None:
            kwargs["default"] = self.default
        if self.choices is not None:
            kwargs["type"] = click.Choice(self.choices)
        elif self.range is not None and self.type is int:
            min_, max_ = self.range
            kwargs["type"] = click.IntRange(min_, max_)
        else:
            kwargs["type"] = self.type
        return kwargs


@dataclass(frozen=True)
class TestVector:
    master: str
    path: str
    entropy: str
    output: str


@runtime_checkable
class BIP85App(Protocol):
    name: str
    code: str

    @property
    def number_range(self) -> Optional[tuple[int, int]]: ...

    @property
    def params(self) -> list[Param]: ...

    def path_segments(self, index: int, **kwargs) -> list[str]: ...

    def parse_path(self, segments: list[str]) -> dict[str, Any]: ...

    def apply(self, entropy: bytes, **kwargs) -> dict[str, Any]: ...

    @property
    def vectors(self) -> list[TestVector]: ...
