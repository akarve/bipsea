"""convert entropy sources into a preseed bytes"""


def from_hex(input: str, passphrase: str = "") -> bytes:
    return bytes.fromhex(input + passphrase)


def from_string(string, passphrase=""):
    raise NotImplementedError


def from_extended_keys(keys, passphrase=""):
    raise NotImplementedError


def from_randbits(bits, passphrase=""):
    raise NotImplementedError


def from_words(seedwords, passphrase=""):
    raise NotImplementedError
