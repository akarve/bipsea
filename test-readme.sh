#!/bin/bash
set -e

MNEMONIC="elder major green sting survey canoe inmate funny bright jewel anchor volcano"
XPRV="xprv9s21ZrQH143K46aCaxAxmT97r6rx9XBFf1gjWTi65Eb3QHjEpuvobGPpXYSyoQqQw5SQhrZpwFKVRSjrFjKDs4shbu7BwTXfVaPV8yF2gc8"

poetry run bipsea --version
poetry run bipsea --help
poetry run bipsea mnemonic --help
poetry run bipsea validate --help
poetry run bipsea xprv --help
poetry run bipsea derive --help
poetry run bipsea mnemonic -t jpn -n 15
poetry run bipsea mnemonic -t eng -n 12 --pretty
poetry run bipsea validate -f free -m "123456123456123456"
poetry run bipsea validate -f free -m @"$(cat input.txt)"
poetry run bipsea validate -m "$MNEMONIC" | poetry run bipsea xprv
poetry run bipsea xprv -m "$MNEMONIC"
poetry run bipsea derive -x "$XPRV" -a mnemonic -t jpn -n 12
poetry run bipsea derive -x "$XPRV" -a mnemonic -t jpn -n 12 -i 1
poetry run bipsea derive -x "$XPRV" -a drng -n 1000
poetry run bipsea derive -x "$XPRV" -a dice -n 10 -s 6
poetry run bipsea derive -x "$XPRV" -a dice -n 6
