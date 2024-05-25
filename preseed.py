"""convert entropy sources into a preseed bytes"""


def from_hex(input: str, passphrase: str = "") -> bytes:
    return bytes.fromhex(input + passphrase)
