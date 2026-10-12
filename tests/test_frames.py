import random
from dataclasses import replace

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.packet import Raw

from beacon.protocol import (
    Flags, InvalidPacket, MessageType, ProtocolError,
    UnsupportedMessageType, encode_control, encode_data,
)
from beacon.wireless.frames import DLT_IEEE802_11, build_beacon, decode_beacon


def prefix(fragment):
    raw = bytes(build_beacon(fragment))
    return raw[:raw.index(encode_control(fragment.control))]


def test_beacon_layers_and_actual_wire_bytes(fragment):
    frame = build_beacon(fragment)
    assert frame.haslayer(RadioTap)
    assert frame.haslayer(Dot11Beacon)
    assert frame[Dot11].addr1 == "ff:ff:ff:ff:ff:ff"
    assert bytes(frame).endswith(encode_control(fragment.control) + encode_data(fragment.data))
    assert decode_beacon(bytes(frame)) == fragment
    # Scapy's independently dissected vendor body must preserve the same bytes.
    parsed = RadioTap(bytes(frame))
    vendor = parsed.getlayer(Dot11Elt, ID=221)
    assert bytes(vendor)[:25] == encode_control(fragment.control)


def test_raw_80211_without_radiotap(fragment):
    assert decode_beacon(bytes(build_beacon(fragment)[Dot11]), linktype=DLT_IEEE802_11) == fragment


def test_fcs_is_removed_only_when_radiotap_says_present(fragment):
    dot11 = bytes(build_beacon(fragment)[Dot11])
    raw = bytes(RadioTap(present="Flags", Flags="FCS")) + dot11 + b"\x01\x02\x03\x04"
    assert decode_beacon(raw) == fragment


def test_unrelated_traffic_is_ignored(fragment):
    assert decode_beacon(prefix(fragment)) is None
    assert decode_beacon(bytes(RadioTap() / Dot11(type=2) / Raw(b"unrelated"))) is None
    unrelated = replace(fragment, control=replace(fragment.control, oui=b"abc"),
                        data=replace(fragment.data, oui=b"abc"))
    assert decode_beacon(bytes(build_beacon(unrelated))) is None
    assert decode_beacon(bytes(build_beacon(unrelated)), expected_oui=b"abc") == unrelated


def test_unrelated_vendor_ie_and_reversed_order(fragment):
    raw = (prefix(fragment) + bytes.fromhex("dd05 aabbcc 0102")
           + encode_data(fragment.data) + encode_control(fragment.control))
    assert decode_beacon(raw) == fragment


@pytest.mark.parametrize("elements", [
    "", "control", "data", "control control data", "control data data",
    "control unknown data", "control truncated data",
])
def test_missing_duplicate_unknown_and_truncated_ies(fragment, elements):
    mapping = {"control": encode_control(fragment.control), "data": encode_data(fragment.data),
               "unknown": bytes.fromhex("dd04 020000 ff"), "truncated": b"\xdd\xff"}
    raw = prefix(fragment) + b"".join(mapping[word] for word in elements.split())
    if not elements:
        assert decode_beacon(raw) is None
    else:
        with pytest.raises(ProtocolError):
            decode_beacon(raw)


@pytest.mark.parametrize("tail", [b"\xdd", b"\xdd\x02ab", b"\xdd\x03\x02\x00\x00"])
def test_malformed_tail(fragment, tail):
    with pytest.raises(ProtocolError):
        decode_beacon(bytes(build_beacon(fragment)) + tail)


@pytest.mark.parametrize("kind", [MessageType.ACK, MessageType.NACK, MessageType.HELLO, MessageType.CLOSE])
def test_control_only_nondata_reports_deferred_semantics(fragment, kind):
    control = replace(fragment.control, message_type=kind, flags=Flags.NONE)
    with pytest.raises(UnsupportedMessageType):
        decode_beacon(prefix(fragment) + encode_control(control))


@pytest.mark.parametrize("raw", [b"", b"\x00" * 7, bytes.fromhex("0100080000000000"),
                                bytes.fromhex("0000040000000000"), bytes.fromhex("0000ffff00000000"),
                                bytes.fromhex("00000800000000008000")])
def test_invalid_frame_headers(raw):
    with pytest.raises(InvalidPacket):
        decode_beacon(raw)


@pytest.mark.parametrize("flags", [0x01, 0x02, 0x08, 0x40, 0x80])
def test_invalid_beacon_fc_flags(fragment, flags):
    raw = bytearray(bytes(build_beacon(fragment)))
    raw[9] = flags
    with pytest.raises(InvalidPacket):
        decode_beacon(bytes(raw))


def test_unsupported_link_type(fragment):
    with pytest.raises(InvalidPacket, match="link type"):
        decode_beacon(bytes(build_beacon(fragment)), linktype=1)


@pytest.mark.parametrize("kwargs", [{"ssid": b"x" * 33}, {"channel": 0}, {"channel": 15},
                                    {"source_mac": "invalid"}, {"source_mac": "ff:ff:ff:ff:ff:ff"},
                                    {"sequence": 4096}])
def test_invalid_builder_parameters(fragment, kwargs):
    with pytest.raises(ValueError):
        build_beacon(fragment, **kwargs)


def test_random_ie_corruption_never_leaks_parser_exceptions(fragment):
    rng = random.Random(28)
    base = prefix(fragment)
    for _ in range(200):
        tail = rng.randbytes(rng.randrange(80))
        try:
            result = decode_beacon(base + tail)
            assert result is None
        except ProtocolError:
            pass
