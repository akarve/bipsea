from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, Tuple, runtime_checkable


@dataclass(frozen=True)
class Param:
    """App parameter definition. Pure data, no framework coupling."""

    name: str
    flags: tuple[str, ...]
    type: type
    required: bool = False
    default: Any = None
    range: Optional[Tuple[Optional[int], Optional[int]]] = None
    choices: Optional[list[str]] = None
    help: str = ""
    role: Optional[str] = None


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
    def params(self) -> list[Param]: ...

    def path_segments(self, index: int, **kwargs) -> list[str]: ...

    def parse_path(self, segments: list[str]) -> dict[str, Any]: ...

    def apply(self, entropy: bytes, **kwargs) -> dict[str, Any]: ...

    @property
    def vectors(self) -> list[TestVector]: ...
