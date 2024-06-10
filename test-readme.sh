#!/bin/bash
set -e

MNEMONIC="elder major green sting survey canoe inmate funny bright jewel anchor volcano"

poetry run bipsea --version

poetry run bipsea --help
poetry run bipsea mnemonic --help
poetry run bipsea validate --help
poetry run bipsea xprv --help
poetry run bipsea derive --help

# poetry run bipsea mnemonic | poetry run bipsea validate | poetry run bipsea xprv | poetry run bipsea derive -a mnemonic -n 12

poetry run bipsea mnemonic -t spa -n 12 | poetry run bipsea validate -f spa

# poetry run bipsea mnemonic | poetry run bipsea validate | poetry run bipsea xprv

# poetry run bipsea validate -f free -m "123456123456123456" | poetry run bipsea xprv

# poetry run bipsea validate -f free -m "$(cat input.txt)"

# poetry run bipsea validate -m "$MNEMONIC" | poetry run bipsea xprv | poetry run bipsea derive -a base85

# poetry run bipsea validate -m "$MNEMONIC" | poetry run bipsea xprv | poetry run bipsea derive -a mnemonic -t jpn -n 12

# poetry run bipsea validate -m "$MNEMONIC" | poetry run bipsea xprv | poetry run bipsea derive -a drng -n 1000

# poetry run bipsea validate -m "$MNEMONIC" | poetry run bipsea xprv | poetry run bipsea derive -a dice -n 100 -s 6
