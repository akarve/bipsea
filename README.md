# BIP-39 Mnemonic Seed Generator in Python

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
* BIP39 word list from [bips/bip-0039](https://github.com/bitcoin/bips/tree/master/bip-0039).
