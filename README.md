# `bipsea` — unlimited entropy for Bitcoin, passwords, and other cryptographic secrets

> "One Seed to rule them all,  
> One Key to find them,  
> One Path to bring them all,  
> And in cryptography bind them.  
> —[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)

bipsea is a from-scratch, open-source implementation of BIP-85 and BIP-32 designed
for readability and security.

You can use BIP-85 to generate private keys, seeds, passwords, and other cryptographic
assets offline.

# How is this useful?

BIP-85 is like a better password manager that enables you to protect and store
a _single_, potentially multi-factor, secret that can derive _all of your secrets_.

BIP-85 offers the following benefits:

* The security of many independent passwords **and** the operational efficiency
of a single master password.
* Uses Bitcoin's tried and true hierarchical deterministic wallet
tree (including primitives like ECDSA, SHA256, and hardened derivation)
* Generates infinite new Bitcoin wallet seed words and master keys
* Generates infinite possible passwords from a single master root key (xprv)
and a short _path_ (or _derivation_) string.

You can therefore safely store all derivations (and even some derived secrets)
in a hot password manager like Keychain because an attacker without your master
key can do nothing with the derivation.

# How does it work?

The root of your BIP-85 password tree is an ordinary Bitcoin master private key.
> In general, this _should not be a wallet seed with funds in it_.
> In any case, fresh seeds are free and easy to generate with bipsea.

The master key then uses the BIP-32 derivation tree with a clever trick: the
derivation path starts with includes a special purpose code (always `83696968'`
for BIP-85) followed by an _application_ code. BIP-85 offers a variety of application
codes including the following:

* `39'`, as in BIP-39, to generate seed words 
* `2'` for HD-Seed wallet import format ([WIF](https://en.bitcoin.it/wiki/Wallet_import_format))
* `32'`, as in BIP-32, to generate extended private keys (xprv) 
* `128169'` for 16 to 64 bytes of hex
* `707764'` for 20 to 86 characters of a base64 password
* `707785'` for 10 to 80 characters of a base85 password

bipsea also implements the BIP-85 (DRNG). It does not implement the RSA application
codes but you could potentially use the DRNG for this purpose.

## Example derivation path

Consider `m/83696968'/707764'/10'/0'`.

* `m` - the master private key is the root of all BIP-32 and BIP-85 derivations start this way
* `83696968'` - the purpose, BIP-85
* `707764'` - the application, base64 password 
* `10'` - the number of password characters we desire
* `0'` - the child index. Increment this number up to 2^<sup>31</sup> - 1 to get millions
of passwords

You may notice the trailing `'`. This indicates hardened derivation, recommended
for all BIP-85 applications. _Hardened_ derivation means that, even if both the
parent public key and the child private key are exposed, the parent private key remains secure.

## BIP-32 hierarchical deterministic wallet tree

![](imgs/derivation.png)

## How do I know the bipsea implementation is correct?

bipsea passes all BIP-32 and BIP-85 test vectors with the following provisos:
* Only generates seed phrases in English
* Fails a single partial test for derived entropy (but passes all others) from BIP-85
    * [ ] File this and other clarification issues against BIP-85

Run `make test` for details.

* `pip install bipsea`

# Developer

* `make install-dev`
* `make test`

See [Makefile](./Makefile) for more.

# References

* [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) hierarchical
deterministic wallets
* [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) for
generalized cryptographic entropy
* [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) generalized
BIP-32 paths
