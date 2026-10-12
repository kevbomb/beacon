from dataclasses import replace

import pytest

from beacon.protocol import (
    ControlIE, DataIE, Flags, InvalidIE, MessageType,
    decode_control, decode_data, encode_control, encode_data,
)

CONTROL_GOLDEN = bytes.fromhex("dd17 020000 01 01 00000001 00000002 00000003 0001 0001 01 03")
DATA_GOLDEN = bytes.fromhex("dd06 020000 02 4869")


def test_control_golden(control):
    assert encode_control(control) == CONTROL_GOLDEN
    assert decode_control(CONTROL_GOLDEN) == control
    assert len(CONTROL_GOLDEN) == 25


def test_data_golden():
    assert encode_data(DataIE(b"Hi")) == DATA_GOLDEN
    assert decode_data(DATA_GOLDEN) == DataIE(b"Hi")


@pytest.mark.parametrize("size", [0, 1, 250, 251])
def test_data_boundaries(size):
    data = DataIE(bytes(range(size)))
    raw = encode_data(data)
    assert raw[1] == size + 4
    assert decode_data(raw) == data


def test_network_byte_order():
    control = ControlIE(0x01020304, 0x11223344, 0x89ABCDEF, 0x0102, 0x0304, flags=Flags.NONE)
    raw = encode_control(control)
    assert raw[7:23] == bytes.fromhex("01020304 11223344 89abcdef 0102 0304")
    assert decode_control(raw) == control


@pytest.mark.parametrize("kind", list(MessageType))
def test_all_control_types(control, kind):
    value = replace(control, message_type=kind)
    assert decode_control(encode_control(value)) == value


def test_custom_oui(control):
    custom = b"\x02\xab\xcd"
    value = replace(control, oui=custom)
    raw = encode_control(value)
    with pytest.raises(InvalidIE, match="OUI"):
        decode_control(raw)
    assert decode_control(raw, expected_oui=custom) == value
    assert decode_control(raw, expected_oui=None) == value
    assert decode_data(encode_data(DataIE(b"test", custom)), expected_oui=custom).oui == custom


@pytest.mark.parametrize("raw", [b"", b"\xdd", CONTROL_GOLDEN[:-1], CONTROL_GOLDEN + b"x",
                                      b"\x01" + CONTROL_GOLDEN[1:], b"\xdd\x00",
                                      b"\xdd\x03\x02\x00\x00", DATA_GOLDEN])
def test_reject_malformed_control(raw):
    with pytest.raises(InvalidIE):
        decode_control(raw)


@pytest.mark.parametrize("raw", [b"", b"\xdd", DATA_GOLDEN[:-1], DATA_GOLDEN + b"x",
                                      b"\xdd\x03\x02\x00\x00", CONTROL_GOLDEN])
def test_reject_malformed_data(raw):
    with pytest.raises(InvalidIE):
        decode_data(raw)


def test_declared_control_length_is_exact():
    with pytest.raises(InvalidIE, match="23"):
        decode_control(bytes((221, 24)) + CONTROL_GOLDEN[2:] + b"x")


def test_every_truncated_prefix_is_rejected():
    for encoded, decoder in [(CONTROL_GOLDEN, decode_control), (DATA_GOLDEN, decode_data)]:
        for end in range(len(encoded)):
            with pytest.raises(InvalidIE):
                decoder(encoded[:end])
