# `bipsea` unlimited entropy for Bitcoin 


### Installation
* Clone this repo
* `pip install -r requirements.txt`

## Usage

```sh
# see commands
python seedwords.py --help
# generate 15 seed words at random (with checksum in final word)
python seedwords.py --nwords 15
```

### Verifying the word list for yourself

```sh
curl -o english_source.txt https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt

shasum -a 256 english_source.txt
shasum -a 256 english.txt
```

## Project goals

* [x] Click CLI utility
* [x] Use Python `secrets` for strong random behavior where possible
* [x] Add Unit tests
* [x] Investigate [embit](https://github.com/diybitcoinhardware/embit/blob/master/src/embit/bip39.py)

## Sources

* Implemented according to [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
* BIP39 word list from [bips/bip-0039](https://github.com/bitcoin/bips/tree/master/bip-0039).
