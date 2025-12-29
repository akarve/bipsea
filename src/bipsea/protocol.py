from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class Param:
    name: str
    flag: str
    type: type
    required: bool = False
    default: Any = None
    range: Optional[tuple[int, int]] = None
    choices: Optional[list[str]] = None
    help: str = ""


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
