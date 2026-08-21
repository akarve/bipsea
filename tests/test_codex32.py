import pytest
from codex32 import Codex32String

from bipsea.apps.codex32.app import BECH32_CHARSET, MAX_HEADER_INDEX, app
from bipsea.drng import DRNG


def _header_index(header: str) -> int:
    value = 0
    for char in header:
        value = value << 5 | BECH32_CHARSET.index(char)
    return value


def test_path_round_trip():
    assert app.path_segments(520937584, payload_len=26) == [
        "0'",
        "26'",
        "520937584'",
    ]
    assert app.parse_path(["0'", "26'", "520937584'"]) == {
        "profile": 0,
        "payload_len": 26,
        "header_index": 520937584,
    }


@pytest.mark.parametrize(
    "segments",
    [
        ["0'", "26'"],
        ["0'", "26'", "520937584'", "0'"],
        ["0", "26'", "520937584'"],
    ],
)
def test_rejects_malformed_paths(segments):
    with pytest.raises(ValueError):
        app.parse_path(segments)


def test_rejects_unassigned_profile():
    with pytest.raises(ValueError, match="Unsupported codex32 profile"):
        app.parse_path(["1'", "26'", "520937584'"])
    with pytest.raises(ValueError, match="Unsupported codex32 profile"):
        app.apply(bytes(64), 26, 520937584, profile=1)


@pytest.mark.parametrize("payload_len", [25, 27, 104])
def test_rejects_invalid_profile_zero_payload_lengths(payload_len):
    with pytest.raises(ValueError, match="payload length"):
        app.path_segments(520937584, payload_len=payload_len)


@pytest.mark.parametrize("header_index", [-1, MAX_HEADER_INDEX])
def test_rejects_header_index_outside_30_bits(header_index):
    with pytest.raises(ValueError, match="Header index"):
        app.apply(bytes(64), 26, header_index)


@pytest.mark.parametrize(
    "header",
    [
        "qsecrs",
        "0secra",
        "2shard",
    ],
)
def test_rejects_invalid_or_noncanonical_headers(header):
    with pytest.raises(ValueError):
        app.apply(bytes(64), 26, _header_index(header))


def test_unshared_vector_decodes_to_expected_seed_and_zero_padding():
    vector = app.vectors[0]
    result = app.apply(bytes.fromhex(vector.entropy), 26, 520937584)
    parsed = Codex32String(result["application"])

    assert result["entropy"].hex() == vector.entropy
    assert result["application"] == vector.output
    assert parsed.data.hex() == "cba51fa2f647f538872fbfbb9271e420"
    assert parsed.pad_val == 0


def test_share_payload_keeps_the_requested_most_significant_bits():
    vector = app.vectors[1]
    entropy = bytes.fromhex(vector.entropy)
    result = app.apply(entropy, 26, 353105021)
    parsed = Codex32String(result["application"])

    raw = DRNG(entropy).read(17)
    payload_value = int.from_bytes(raw, "big") >> 6
    expected_payload = "".join(
        BECH32_CHARSET[(payload_value >> shift) & 31] for shift in range(125, -1, -5)
    )

    assert result["application"] == vector.output
    assert parsed.payload == expected_payload


@pytest.mark.parametrize(
    "payload_len,encoded_len",
    [
        (26, 48),
        (103, 127),
    ],
)
def test_regular_and_long_checksum_length_boundaries(payload_len, encoded_len):
    result = app.apply(bytes(64), payload_len, 520937584)

    assert len(result["application"]) == encoded_len
    assert str(Codex32String(result["application"])) == result["application"]
