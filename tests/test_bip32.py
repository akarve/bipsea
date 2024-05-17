from bip32 import derive_key

TEST_VECTORS = [
    {
        "seed_hex": "000102030405060708090a0b0c0d0e0f",
        "chain": {
            "m": {
                "ext pub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                "ext prv": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            },
       },
    },
]


def test_vectors():
    for vector in TEST_VECTORS:
        seed = bytes.fromhex(vector["seed_hex"])
        for ch, tests in vector["chain"].items():
            for type_, expected in tests.items():
                if type_ == "ext pub":
                    assert str(derive_key(seed, ch)) == expected
                elif type_ == "ext prv":
                    assert str(derive_key(seed, ch, private=True)) == expected
                else:
                    raise ValueError(f"Unexpected: {type_}")
