# BIP-39 Mnemonic Seed Generator in Python

## Disclaimer

This is **BETA SOFTWARE**. Use it at your own risk.

Please carefully test and ensure that generated seeds work as
desired before trusting large quantities of coin to its mnemonics.

Or, better yet, read the code and see if you think it's correct
(*pull requests welcome*).

## Why another mnemonic generator?

I created this repo for myself because all prior code I found for
generating seed words was incomplete, opaque, and difficult to trust.

This repo is designed to be a correct, transparent, and trustworthy
implementation of BIP-39 that you can verify for yourself and then
use it to **generate or checksum your own seedwords offline**.

### What was wrong with prior seed generators?

* Outdated (e.g. Python 2)
* Poorly commented (or not commented at all)
* Incomplete (e.g. didn't include checksum calculation)
* Ran in a browser :(
* Didn't use a cryptographically strong source of entropy

> I later found Trezor's [mnemonic](https://github.com/trezor/python-mnemonic/tree/master)
> which is close to what I wanted but I still find this repo code easier to read
> (and use on the CLI). We now use mnemonic as an oracle for testing.

## Pre-requisites
* Python 3.x

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
