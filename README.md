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
use to **generate your own seedwords offline**.

### What was wrong with prior seed generators?

* Outdated (e.g. Python 2)
* Poorly commented (or not commented at all)
* Incomplete (e.g. didn't include checksum calculation)
* Ran in a browser :(
* Didn't use a cryptographically strong source of entropy

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
python seedwords.py --wordcount 15
```

## Project goals

* [x] Click CLI utility
* [x] Use Python `secrets` for strong random behavior where possible
* [ ] Add Unit tests
* [ ] Investigate [embit](https://github.com/diybitcoinhardware/embit/blob/master/src/embit/bip39.py)

## Sources
* Implemented according to [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
* BIP39 word list from [bips/bip-0039](https://github.com/bitcoin/bips/tree/master/bip-0039).

