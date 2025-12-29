from __future__ import annotations

from typing import Dict

from .app_protocol import BIP85App
from .apps import APPS


def get_apps() -> Dict[str, BIP85App]:
    return APPS


def get_app(name: str) -> BIP85App:
    if name not in APPS:
        raise ValueError(f"Unknown app: {name}")
    return APPS[name]
