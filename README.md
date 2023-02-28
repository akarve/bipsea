# BIP-39 Mnemonic Seed Generator in Python

This is **BETA SOFTWARE**. Use it at your own risk.

Please carefully test and ensure that generated seeds work as
desired before trusting large quantities to it.

## Pre-requisites
* Python 3.x

### Installation
* Clone this repo
* `pip install -r requirements.txt`

## Usage

```python
# see commands
python seedwords.py --help
# generate 15 seed words at random (with checksum in final word)
python seedwords.py --wordcount 15
```

With ample commenting and the following:
* [x] Click CLI utility
* [x] Use Python `secrets` for strong random behavior where possible
* [ ] Unit tests

## Sources
* Implemented according to [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
* BIP39 word list from [bips/bip-0039](https://github.com/bitcoin/bips/tree/master/bip-0039).
