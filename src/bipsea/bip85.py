import logging
import math
import re
from typing import Dict, Union

from .apps import APPS
from .apps.mnemonic.app import INDEX_TO_LANGUAGE
from .bip32 import ExtendedKey
from .bip32 import derive_key as derive_key_bip32
from .bip32 import hmac_sha512
from .constants import HMAC_KEY, PURPOSE_CODES
from .drng import DRNG
from .util import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME)

__all__ = [
    "APPLICATIONS",
    "RANGES",
    "PURPOSE_CODES",
    "HMAC_KEY",
    "INDEX_TO_LANGUAGE",
    "DRNG",
    "apply_85",
    "to_entropy",
    "derive",
    "split_and_validate",
    "do_rolls",
]


APPLICATIONS = {app.name: app.code for app in APPS.values()}
APPLICATIONS["drng"] = "0'"


def _number_range(app):
    """Extract range from the param with role='number', if any."""
    for p in app.params:
        if p.role == "number" and p.range is not None:
            return p.range
    return None


RANGES = {name: rng for name, app in APPS.items() if (rng := _number_range(app))}

CODE_TO_APP = {app.code: app for app in APPS.values()}


def apply_85(derived_key: ExtendedKey, path: str) -> Dict[str, Union[bytes, str]]:
    """returns a dict with 'entropy': bytes and 'application': str"""
    segments = split_and_validate(path)
    purpose = segments[1]
    if purpose != PURPOSE_CODES["BIP-85"]:
        raise ValueError(f"Not a BIP85 path: {path}")
    if len(segments) < 4 or not all(s.endswith("'") for s in segments[1:]):
        raise ValueError(
            f"Paths should have 4+ segments, all hardened children: {path}"
        )
    app_code = segments[2]
    app_segments = segments[3:]

    if app_code not in CODE_TO_APP:
        raise NotImplementedError(f"Unsupported BIP-85 application {app_code}")

    app = CODE_TO_APP[app_code]
    entropy = to_entropy(derived_key.data[1:])
    kwargs = app.parse_path(app_segments)

    if app.name == "wif":
        kwargs["network"] = derived_key.get_network()

    return app.apply(entropy, **kwargs)


def to_entropy(data: bytes) -> bytes:
    return hmac_sha512(key=HMAC_KEY, data=data)


def derive(master: ExtendedKey, path: str, private: bool = True) -> ExtendedKey:
    if not master.is_private():
        raise ValueError("Derivations should begin with a private master key")

    return derive_key_bip32(master, split_and_validate(path), private)


def split_and_validate(path: str):
    segments = path.split("/")
    if segments[0] != "m":
        raise ValueError(f"Expected 'm' (xprv) at root of derivation path: {path}")
    pattern = r"^\d+['hH]?$"
    if not all(re.match(pattern, s) for s in segments[1:]):
        raise ValueError(f"Unexpected path segments: {path}")

    return segments


def do_rolls(entropy: bytes, sides: int, rolls: int, index: int) -> str:
    """sides > 1, 1 < rolls > 100"""
    max_width = len(str(sides - 1))
    history = []
    bits_per_roll = math.ceil(math.log(sides, 2))
    bytes_per_roll = math.ceil(bits_per_roll / 8)
    drng = DRNG(entropy)
    while len(history) < rolls:
        trial_int = int.from_bytes(drng.read(bytes_per_roll), "big")
        available_bits = 8 * bytes_per_roll
        excess_bits = available_bits - bits_per_roll
        trial_int >>= excess_bits
        if trial_int >= sides:
            continue
        else:
            history.append(f"{trial_int:0{max_width}d}")

    return ",".join(history)
