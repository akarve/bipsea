from __future__ import annotations

from typing import Dict

from .apps import APPS
from .protocol import BIP85App


def get_apps() -> Dict[str, BIP85App]:
    return APPS


def get_app(name: str) -> BIP85App:
    if name not in APPS:
        raise ValueError(f"Unknown app: {name}")
    return APPS[name]
