[![Tests](https://github.com/akarve/bipsea/actions/workflows/ci.yaml/badge.svg)](https://github.com/akarve/bipsea/actions)

# `bipsea`: secure entropy for mnemonics, passwords, PINs, and other secrets

> _One Seed to rule them all,  
> One Key to find them,  
> One Path to bring them all,  
> And in cryptography bind them._  
> -[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)

bipsea is composable command-line utility that generates and validates Bitcoin
mnemonics and hierarchical secrets according to BIP-85.
bipsea is designed be usable, readable, and correct via extensive unit tests.
bipsea includes pure Python APIs for BIPs 32, 39, and 85.
**bipsea is currently for experimental purposes only.**

bipsea relies on cryptographic primitives from Python
and the [python-ecdsa](https://github.com/tlsfuzzer/python-ecdsa) module, which
is [vulnerable to side-channel attacks](https://github.com/tlsfuzzer/python-ecdsa?tab=readme-ov-file#security).
bipsea does not rely on third-party libraries from any wallet vendor.

You can run bipsea offline to generate passwords, seed mnemonics, and more.
Consider dedicated cold hardware that runs [Tails](https://tails.net),
has networking disabled, and disables
[Intel Management Engine](https://support.system76.com/articles/intel-me/)
and other possible hardware backdoors.


# Usage


## Installation

```sh
pip install bipsea
```


## Help

```sh
bipsea --help
```


## Commands

bipsea offers four commands that work together:

1. `mnemonic` creates BIP-39 seed mnemonics in 9 languages
1. `validate` validates BIP-39 in 9 languages
1. `xprv` derives a BIP-32 extended private key
1. `derive` applies BIP-85 to an xprv to derive child secrets


# Tutorial

You can compose bipsea commands with a pipe:

```sh
bipsea mnemonic | bipsea validate | bipsea xprv | bipsea derive -a mnemonic -n 12
```
    rotate link six joy boss sock unveil achieve charge sweet hidden regular

> Because `bipsea mnemonic` uses random bits from Python's secrets library,
> your output will, with extremely high probability, differ from the above output.

The above generates a fresh mnemonic, validates it against the english word list, converts
it to an xprv, and then derives a new secret according to BIP-85.


## But why would anyone turn one seed mnemonic into another?

We started with a mnemonic and got another one, so what?
As you'll see below you can derive not one  but millions of secrets, including
PINs, mnemonics, and passwords, from a single root secret. Thanks to BIP-85, bipsea
enables you to create millions of secure and independent derived secrets.

Even if a child secret were compromised, the parent and root secrets would remain
secure due to the irreversibility of hardened hierarchical derivation.
You can read more on these topics
[below](#how-are-bipsea-and-hierarchical-wallet-derivation-bip-85-useful).


## `bipsea mnemonic`

Suppose you want a 15-word seed phrase in Japanese.

```sh
bipsea mnemonic -t jpn -n 15
```
    おかわり おっと ゆにゅう いこつ ろうそく げつれい おかわり きらい ちたん にくまん でんわ ずぶぬれ くださる いらすと のみもの

Or 12 words in English.

```sh
bipsea mnemonic -n 12 --pretty
```
    1) beach
    2) tail
    3) trial
    4) design
    5) lyrics
    6) episode
    7) miracle
    8) strong
    9) slogan
    10) pole
    11) blood
    12) scene


## `bipsea validate`

BIP-39 mnemonics come from localized wordlists, have 12-24 words, and include a checksum.
`validate` checks the integrity of a mnemonic phrase, normalizes the input (NFKD),
then echoes the result so that you can pipe it to `bipsea xprv`.

```sh
bipsea mnemonic -t spa -n 12 | bipsea validate -f spa
```
    relleno peón exilio vara grave hora boda terapia dinero vulgar vulgar goloso


## `bipsea xprv`

```sh
bipsea mnemonic | bipsea validate | bipsea xprv
```
    xprv9s21ZrQH143K41bKPQ9XHbPoqfdCDmZLBorYHay5E273HTu5yAFm27sSWRoCpisgQNH9vfrL9yVvVg5rBEbMCk2UwQ8K7qCFnZAY7aXhuqV

`bipsea xprv` converts a mnemonic into a master node (the root of your wallet
chain) that serializes as an xprv or _extended private key_.


### xprv from dice rolls (or any string)

```
bipsea validate -f free -m "123456123456123456" | bipsea xprv
```
    Warning: Relative entropy of input seems low (0.42). Consider a more complex --mnemonic.
    xprv9s21ZrQH143K2Sxhvzbx2vvjLxPB2tJyfh5hm7ags5UWbKRHbm7x1wyCnqN4sdGTqxbq5tJJc3vV4vd51er6WgUiUC7ma1nKtfYRNTYaCeE

You can even load the input from a file.

```sh
bipsea validate -f free -m "$(cat input.txt)"
```

If you are now thinking, _I could use any string to derive a master key_,
then you're ready to learn about BIP-85 with `bipsea derive`.

> **Do not derive valuable keys or secrets from short, simple, or
> predictable strings**. You can only stretch entropy so far.
> **Weak entropy in, weak entropy out**.
> Common phrases are further susceptible to
[rainbow table attacks](https://en.wikipedia.org/wiki/Rainbow_table).


## `bipsea derive`

It's important to use a fixed, trusted, and cold-stored mnemonic so that `derive`
(or any BIP-85 implementation) produces repeatable results.
_If the root xprv changes, so do all of the child secrets._

In the following examples we derive all secrets from a single mnemonic.

```sh
MNEMONIC="elder major green sting survey canoe inmate funny bright jewel anchor volcano"
```

Below are several applications.
`bipsea derive --help` shows all available applications.


### base85 passwords
```
bipsea validate -m $MNEMONIC | bipsea xprv | bipsea derive -a base85
```
    iu?42{I|2Ct{39IpEP5zBn=0

`-a` or `--application` tells `derive` what to derive. In this case
we get `-n 20` characters of a base85 password.


### mnemonic phrases

```
bipsea validate -m "$MNEMONIC" | bipsea xprv | bipsea derive -a mnemonic -t jpn -n 12
```
    ちこく へいおん ふくざつ ゆらい あたりまえ けんか らくがき ずほう みじかい たんご いそうろう えいきょう

As with all applications, you can change the child index from it's default of zero
to get a fresh, repeatable secret.


### DRNG, enter the matrix

BIP-85 includes a discrete random number generator.

```sh
bipsea validate -m "$MNEMONIC" | bipsea xprv | bipsea derive -a drng -n 1000
```
    <1,000 bytes (2,000 hex characters) from the DRNG>


### PIN numbers from the DRNG with `-a dice`

bipsea implements cryptogaphic dice based on the BIP-85 DRNG. 

To simulate 100 6-sided die rolls:

```sh
bipsea validate -m "$MNEMONIC" | bipsea xprv | bipsea derive -a dice -n 100 -s 6
```
    4,2,5,3,4,4,4,5,0,3

> Die rolls start at 0 so that, for instance, you can get a proper 10-digit PIN.

For a 6-digit PIN roll a 10-sided virtual die.

    4,9,9,3,7,6


# Technical discussion

## How are bipsea and hierarchical wallet derivation (BIP-85) useful?

BIP-85 enables you to protect and store a _single_ master secret
that can derive _millions of independent, multi-purpose secrets_. 
The following benefits emerge:

1. Offers the security of numerous independent passwords with the operational efficiency
of a single master password. (The master secret can be multi-factor.)
1. Uses Bitcoin's well-tested hierarchical deterministic wallet
tree (including primitives like ECDSA and hardened children).
1. Generates millions of new mnemonics and master keys.
1. Generates millions of new passwords and random streams from a single master key.

Unlike a password manager, which protects many secrets with one hot secret,
BIP-85 _derives_ many secrets from one protected secret. Therefore you only need
to back up the derivation paths and the services they are for. You do not need to
back up the derived secrets.

You could safely store all derivation paths in a hot password manager like Apple Keychain.
You could even store the derived secrets in a hot password manager at no risk to
the master private key.

> bipsea alone is not password manager, but you could use it to implement one.
> See [BIP-?: General secrets keychain with semantic derivation paths](https://github.com/akarve/bip-keychain)
> for more.


## How does it work?

The root of your BIP-85 password tree is an extended master private key (xprv).

> In general, you _should not use a wallet seed with funds in it_.
> In any case, fresh seeds are free and easy to generate with bipsea.

Child keys are then derived according to BIP-32 hierarchical deterministic
wallets with a clever twist:
the derivation path includes a purpose code (`83696968'`) followed by an _application_
code. In this way, each unique derivation path produces unique, independent,
and secure _derived entropy namespace_ as a pure function of the master private key and
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
number generator (DRNG).


### Derivation

Consider `m/83696968'/707764'/10'/0'`. It produces a password such as
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


## ECDSA for the curious and paranoid

BIP-85 derives the entropy for each application by computing an HMAC of the private
ECDSA key of the last hardened child. Private child keys are pure functions of the
parent key, child index, and depth. In this way BIP-85 entropy is hierarchical,
deterministic, and irreversibly hardened as long as ECDSA remains secure.
ECDSA is believed to be secure but it may not even be possible to _prove_ the security
of _any_ cryptographic algorithm as such a proof would need to demonstrate strong
conjectures similar to "P is not equal to NP."

All of that to say **even the "most secure" algorithms are vulnerable to the**
**problem of induction**.

> Just because no one _has_ broken ECDSA  
> doesn't mean no one _will_ break ECDSA.

"break" means the ability to derive a private key from the corresponding
public key, a feat believed but not known to be infeasible in polynomial time
because it requires the attacker to compute the discrete logarithm of the public
key `p = Q*k`, where `Q` is the generator of the `SECP256k1` elliptic curve and
`k` is the private key. `SECP256k1` is a cyclic group under addition modulo `n`,
the order of the curve. We call computing `k` from `Q*k` the "discrete logarithm"
since, the same way `log(a^x) = x` the attacker must reduce the point `Q*k` to `k`.

ECDSA is not [post-quantum secure](https://blog.cloudflare.com/pq-2024).
If someone were to build a so-far elusive quantum computer with sufficiently many
logical q-bits to run Shor's algorithm to compute the discrete log of an ECDSA
private key, ECDSA would be broken.
As unlikely as a quantum computer may seem, the Chromium team is
[taking no chances](https://blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html)
and has begun to roll out quantum-resistant changes to SSL.


# Developer

```
make
make test
```

See [Makefile](./Makefile) for more commands.


## Is the bipsea implementation correct?

bipsea passes all BIP-32, BIP-39, and BIP-85 test vectors in all BIP-39 languages
plus its own unit tests.

There is a single BIP-85 vector, which we believe to be incorrect in the spec,
marked as an xfail and [filed to BIP-85](https://github.com/bitcoin/bips/pull/1600).


# References

1. [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
hierarchical deterministic wallets
1. [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
mnemonic seed words
1. [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
generalized BIP-32 paths
1. [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
generalized cryptographic entropy


# TODO

* [ ] Investigate switch to secure ECDSA libs with constant-time programming and
side-channel resistance.
    * [x] https://cryptography.io/en/latest/
        * Incomplete support for public key points
