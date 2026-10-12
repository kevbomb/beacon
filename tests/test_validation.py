from dataclasses import replace

import pytest

from beacon.protocol import DataIE, Flags, Fragment, InvalidIE, InvalidPacket, MessageType, encode_control, encode_data
from beacon.protocol.validation import validate_fragment


@pytest.mark.parametrize("field,value", [
    ("sender_id", -1), ("recipient_id", 2**32), ("message_id", True),
    ("message_id", 1.5), ("message_id", "3"), ("version", 2), ("version", True),
    ("packet_number", 0), ("packet_number", 2), ("total_packets", 0),
    ("total_packets", 65536), ("message_type", 0), ("message_type", 6),
    ("flags", 8), ("flags", -1), ("flags", 256), ("flags", Flags.NONE),
    ("flags", Flags.START), ("flags", Flags.END), ("oui", b"ab"),
    ("oui", b"abcd"), ("oui", bytearray(b"abc")),
])
def test_invalid_control_fields(control, field, value):
    with pytest.raises(InvalidIE):
        encode_control(replace(control, **{field: value}))


@pytest.mark.parametrize("payload", [b"x" * 252, "text", bytearray(b"x")])
def test_invalid_data(payload):
    with pytest.raises(InvalidIE):
        encode_data(DataIE(payload))


def test_control_and_data_oui_must_match(fragment):
    with pytest.raises(InvalidPacket, match="OUIs"):
        validate_fragment(replace(fragment, data=DataIE(b"Hi", b"abc")))


def test_nondata_is_not_a_data_fragment(control):
    with pytest.raises(InvalidPacket, match="only DATA"):
        validate_fragment(Fragment(replace(control, message_type=MessageType.ACK), DataIE(b"")))


def test_uint32_and_packet_count_limits(control):
    value = replace(control, sender_id=0, recipient_id=2**32 - 1, message_id=2**32 - 1,
                    packet_number=65535, total_packets=65535, flags=Flags.END)
    assert len(encode_control(value)) == 25
