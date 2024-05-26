# `bipsea`: unlimited entropy for Bitcoin, passwords, and other secrets

> _One Seed to rule them all,  
> One Key to find them,  
> One Path to bring them all,  
> And in cryptography bind them._  
> —[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)

bipsea is currently for experimental purposes only.
bipsea is a standalone, test-driven implementation of BIP-85 and BIP-32.
bipsea is designed for readability and correctness. bipsea offers a command-line
interface and an API.

bipsea relies on cryptographic primitives from Python (`secrets`, `hashlib`),
and the [python-ecdsa](https://github.com/tlsfuzzer/python-ecdsa) and is therefore
also [vulnerable to side-channel attacks](https://github.com/tlsfuzzer/python-ecdsa?tab=readme-ov-file#security).
bipsea does not rely on third-party libraries
from any wallet vendor.

You can run bipsea offline on to generate general-use passwords, Bitcoin seed words,
and more. Consider dedicated cold hardware that runs [Tails](https://tails.net),
never has network access, and disables
[Intel Management Engine](https://support.system76.com/articles/intel-me/)
and other possible backdoors.

# How is this useful?

BIP-85 is the foundation for a next generation password manager that enables you
to protect and store a _single_ master secret that can derive _millions of independent, multi-purpose secrets_. 

BIP-85 offers the following benefits:
* The security of numerous independent passwords with the operational efficiency
of a single master password. (The master secret can be multi-factor.)
* Uses Bitcoin's well-tested hierarchical deterministic wallet
tree (including primitives like ECDSA and hardened children)
* Can generate millions of new Bitcoin wallet seed words and master keys
* Can generate millions of new passwords from a single master root key (xprv)
and a short derivation path.

Unlike a password manager, which protects many secrets with one hot secret,
BIP-85 _derives_ many secrets from one protected secret. Therefore you only need
to back up the derivation paths and the services they are for. You do not need to
back up the derived secrets.

You could safely store all derivation paths in a hot password manager
like Keychain. You could even store the derived secrets in a hot password manager
at no risk to the master private key.

> Note: bipsea alone is not password manager, but you might use it to implement one.

# How does it work?

The root of your BIP-85 password tree is a standard Bitcoin master private key (xprv).

> In general, you _should not use a wallet seed with funds in it_.
> In any case, fresh seeds are free and easy to generate with bipsea.

The master key then uses the BIP-32 derivation tree with a clever twist: the
derivation path includes a purpose code (`83696968'`) followed by an _application_
code. In this way, each unique derivation path produces unique, independent,
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

## Example derivation

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

bipsea passes all BIP-32 and BIP-85 test vectors plus its own unit tests with the
following provisos:
* Only generates seed phrases in English
* Fails one partial test for derived entropy (but passes all others) from BIP-85

Run `make test` for details.

# Usage

```
pip install bipsea
```
```
bipsea --help
```

## `bipsea seed`

### New seed words

```sh
bipsea seed -n 12 --pretty
```
    1) crumble
    2) shallow
    3) hair
    4) federal
    5) cycle
    6) grid
    7) million
    8) twist
    9) turn
    10) verb
    11) orphan
    12) suggest

### xprv from existing seed words

```
bipsea seed -f words -i "airport letter idea forget broccoli prefer panda food delay struggle ridge salute above want dinner" -t xprv
```
    xprv9s21ZrQH143K3YwuXcacSSghcUfrrEyj9hTHU3a2gmr6SzPBaxmuTgKGBWtFdnnCjwGYMkU7mLvxba8FFPGLQUMvyACZTEdSCJ8uBwh5Aqs


## xprv from dice rolls (or any string)
```
bipsea seed -f string -i "123456123456123456" -t xprv
```

<pre><code style="color: #CCCC00">Warning: 144 bits in, 256 bits out. Input more entropy.</code></pre>

    xprv9s21ZrQH143K3Ee3pgdhHb9xdu3D1EPT8J45zZ5Th5xPvWT9sujnPDCpA8bZhjz73UkkNWR8WnNg39C3hEHeeXKWLEQKfx9gySgjzMowEwH

This is similar to how coldcard implements
[verifiable dice rolls](https://coldcard.com/docs/verifying-dice-roll-math/).
If you are now thinking, _I could use any string to derive a master key_,
then you're ready to learn about BIP-85 with `bipsea entropy`.

> **Do not get cute and derive valuable keys or secrets from short
> strings**. You can only stretch entropy so far.
> **Weak entropy in, weaker entropy out**.
> Short, common strings are also susceptible to
[rainbow table attacks](https://en.wikipedia.org/wiki/Rainbow_table).

## `bipsea entropy`

`bipsea entropy` requires you to pipe in an xprv.

### base64 password

```
bipsea seed -f string -i "yoooooooooooooooo" -t xprv -n 12 | bipsea entropy -a base85 -n 10
```
    aqn+dPu%^~

Increment the index to get a fresh password.

```
bipsea seed -f string -i "yoooooooooooooooo" -t xprv -n 12 | bipsea entropy -a base85 -n 10 -i 1
```
    p6Ft=F40(*

Alternatively you can pipe in an existing xprv:

```
echo "$XPRV" | bipsea entropy -a base85 -n 10
```

Or call `--input`:
```
bipsea seed -f string -i "yoooooooooooooooo" -t xprv -n 12 --input "$XPRV"
```
 
### Derived seed words

```
bipsea seed -t xprv | bipsea entropy -a words        
```
    loan height quality library maid defense minor token thought music claim actual hour ship robust burst live broccoli

Transform one set of seed words into millions of others (increment `-i`):

```
bipsea seed -f words -i "load kitchen smooth mass blood happy kidney orbit used process lady sudden" -t xprv | bipsea entropy -a words -n 12
```
    medal air cube edit offer pair source promote wrap pretty rare when

Run the command with `-i 1` for new words:

    run sea prison modify december any pottery melody aspect hero loan gown

### DRNG, enter the matrix

```
bipsea seed -t xprv | bipsea entropy -a drng -n 10000
```
    <10K hex chars from the DRNG>

# For the curious and paranoid

BIP-85 derives the entropy for each application by computing an HMAC of the private
ECDSA key of the last hardened child. Private child keys are pure functions of the
parent key and the child index. In this way BIP-85 entropy is hierarchical,
deterministic, and irreversibly hardened as long as ECDSA remains secure.
ECDSA is believed to be secure but it may not even be possible to _prove_ the security
of _any_ cryptographic algorithm as such a proof would need to demonstrate strong
conjectures similar to "P is not equal to NP."

All of that to say **even the hardest cryptography falls to the problem of induction**:
> Just because no one broke has yet broken ECDSA
> doesn't mean no one will break ECDSA.

ECDSA is not [post-quantum secure](https://blog.cloudflare.com/pq-2024).
If someone were to creates the elusive quant computer with sufficiently many
logical q-bits to run Shor's algorithm on large keys, then suddenly private
could be reverse-engineered from public keys. As unlikely as a quantum computer
may seem, the Chromium team is
[taking no chances](https://blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html)
and has begun to roll out quantum-resistant changes to SSL.

# Developer

```
make install
make install-go
make test
```

See [Makefile](./Makefile) for more commands.

# References

1. [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
hierarchical deterministic wallets
1. [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
generalized cryptographic entropy
1. [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
generalized BIP-32 paths

# TODO

* [x] File the above and other "TODO" issues to BIP-85
  * https://github.com/bitcoin/bips/pull/1600
* [ ] Investigate switch to secure ECDSA libs with constant-time programming and
side-channel resistance.
    * [ ] https://cryptography.io/en/latest/
