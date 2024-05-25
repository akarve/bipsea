# `bipsea` — unlimited cryptographic entropy for Bitcoin, passwords, and other secrets

> _One Seed to rule them all,  
> One Key to find them,  
> One Path to bring them all,  
> And in cryptography bind them._  
> —[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)

bipsea is a standalone, unit-tested implementation of BIP-85 and BIP-32.
bipsea is designed for readability and security. bipsea does not rely on third-party
libraries from any wallet vendor. bipsea does use cryptographic primitives from
Python and [python-ecdsa](https://github.com/tlsfuzzer/python-ecdsa).

You can run bipsea offline to generate general-use passwords, Bitcoin seed words,
and more.

# How is this useful?

BIP-85 is in spirit the foundation for a next generation password manager
that enables you to protect and store a _single_ master secret that can derive
_millions of independent, multi-purpose secrets_. 

BIP-85 offers the following benefits:
* The security of many independent passwords **AND** the operational efficiency
of a single master password. (The master secret can be multi-factor.)
* Uses Bitcoin's well-tested hierarchical deterministic wallet
tree (including primitives like ECDSA and hardened children)
* Can generate infinitely many new Bitcoin wallet seed words and master keys
* Can generate infinitely many new passwords from a single master root key (xprv)
and a short derivation path.

Unlike a password manager, which protects many secrets with one secret,
BIP-85 _derives_ many secrets with one secret meaning you only need to back up 
the derivation paths, not the secrets themselves.

You can safely store all derivation paths in a hot password manager
like Keychain. You can store derived secrets in a hot password manager
with no risk to the master key.

> Note: bipsea alone is not password manager, but you could use it to implement one.

# How does it work?

The root of your BIP-85 password tree is a standard Bitcoin master private key (xprv).

> In general, you _should not use a wallet seed with funds in it_.
> In any case, fresh seeds are free and easy to generate with bipsea.

The master key then uses the BIP-32 derivation tree with a clever twist: the
derivation path includes a purpose code (`83696968'`) followed by an _application_
code. In this way, each unique derivation path produces a unique, independent,
and secure _derived entropy_ as a pure function of the master private key and the
derivation path.

BIP-85 specifies a variety of application codes including the following:

| application code | description |
|------------------|-------------|
| `39'`            | as in BIP-39, to generate seed words |
| `2'`             | for HD-Seed wallet import format ([WIF](https://en.bitcoin.it/wiki/Wallet_import_format)) |
| `32'`            | as in BIP-32, to generate extended private keys (xprv) |
| `128169'`        | for 16 to 64 bytes of random hex |
| `707764'`        | for 20 to 86 characters of a base64 password |
| `707785'`        | for 10 to 80 characters of a base85 password |

bipsea implements all of the above applications plus the BIP-85 discrete random
number generator (DRNG). bipsea does not implement the RSA application codes from
BIP-85 but you could potentially use the DRNG for RSA and similar applications.

## Notes for the curious and the paranoid

Technically speaking, BIP-85 derives the entropy for each application by computing
an HMAC of the private ECDSA key of the last hardened child. In this way
the entropy is hierarchical, deterministic, and irreversibly hardened as long as
ECDSA remains secure. The security of ECDSA is believed but not proven and may
never be proven as it may or may not even be possible to prove that P is not equal
to NP. Furthermore, ECDSA is [not post-quantum secure](https://blog.cloudflare.com/pq-2024)
in that if someone somewhere could perform the fantastic feat of producing sufficient
logical q-bits to run Shor's algorithm private keys could be reverse-engineered 
from public keys. As unlikely as the emergence of a quantum computer may seem,
the Chromium team is
[taking no chances](https://blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html)
and has begun to roll out quantum-resistant changes to SSL.

All of that to say even the hardest cryptography falls to the problem of induction:
just because no one broke ECDSA today, doesn't mean they can't break it tomorrow.

## Example derivation path

Consider `m/83696968'/707764'/10'/0'`. It produces the password
`dKLoepugzd` according to the following logic:

| path segment | description                               |
|--------------|-------------------------------------------|
| `m`          | master private key                        |
| `83696968'`  | purpose code for BIP-85                   |
| `707764'`    | application code for base64 password      |
| `10'`        | number of password characters             |
| `0'`         | index, 0 to 2³¹ - 1 for millions of unique passwords |

> `'` denotes hardened child derivation, recommended for all BIP-85 applications.
_Hardened_ derivation means that, even if both the parent public key and the child
private key are exposed, the parent private key remains secure.

## BIP-32 hierarchical deterministic wallet tree

![](imgs/derivation.png)

## How do I know the bipsea implementation is correct?

bipsea passes all BIP-32 and BIP-85 test vectors with the following provisos:
* Only generates seed phrases in English
* Fails a single partial test for derived entropy (but passes all others) from BIP-85

### TODO

* [ ] File the above and other clarification issues to BIP-85

Run `make test` for details.

```sh
pip install bipsea
```

# Developer

```
make install-dev
make test
```

See [Makefile](./Makefile) for more commands.


# Usage

## Generate Bitcoin seed words

```sh
bipsea --to-words --from-randbits
bipsea --to-words --n-words 18 --from-string "adfadfadfadf"
bipsea --to-85 --path "m/83696968'/707764'/10'/0'"

bipsea --to-words  --from-words "a b c" | bipsea --to-85 --path "m/83696968'/707764'/10'/0'"
```

## Generate BIP-85 password 

```sh
--from-string
```
deck of cards example
warn on low entropy

```sh
bipsea --from
```
> "The seed value is calculated as SHA256 over the rolls, when expressed as an ASCII string."
https://coldcard.com/docs/verifying-dice-roll-math/

# References

1. [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
hierarchical deterministic wallets
1. [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
generalized cryptographic entropy
1. [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
generalized BIP-32 paths
