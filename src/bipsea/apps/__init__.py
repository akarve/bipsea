from __future__ import annotations

from typing import Dict

from bipsea.app_protocol import BIP85App
from bipsea.apps.base64.app import app as base64_app
from bipsea.apps.base85.app import app as base85_app
from bipsea.apps.dice.app import app as dice_app
from bipsea.apps.hex.app import app as hex_app
from bipsea.apps.mnemonic.app import app as mnemonic_app
from bipsea.apps.nostr.app import app as nostr_app
from bipsea.apps.wif.app import app as wif_app
from bipsea.apps.xprv.app import app as xprv_app

APPS: Dict[str, BIP85App] = {
    base64_app.name: base64_app,
    base85_app.name: base85_app,
    dice_app.name: dice_app,
    hex_app.name: hex_app,
    mnemonic_app.name: mnemonic_app,
    nostr_app.name: nostr_app,
    wif_app.name: wif_app,
    xprv_app.name: xprv_app,
}
