"""Scapy beacon construction and strict decoding of original frame bytes."""

import re
import struct

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.packet import Packet

from beacon.protocol.constants import (
    CONTROL_IE_TYPE, DATA_IE_TYPE, EXPERIMENTAL_OUI, VENDOR_IE_ID, MessageType,
)
from beacon.protocol.errors import InvalidIE, InvalidPacket, UnsupportedMessageType
from beacon.protocol.information_elements import decode_control, decode_data, encode_control, encode_data
from beacon.protocol.models import Fragment
from beacon.protocol.validation import validate_fragment, validate_oui

DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127


def build_beacon(
    fragment: Fragment, *, source_mac: str = "02:00:00:00:00:01",
    ssid: bytes = b"Beacon-local-test", channel: int = 1, sequence: int = 0,
) -> Packet:
    """Build an offline radiotap beacon; never opens an interface or transmits."""
    validate_fragment(fragment)
    if not isinstance(source_mac, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", source_mac):
        raise ValueError("source_mac must be a six-byte colon-separated MAC address")
    if int(source_mac[:2], 16) & 1:
        raise ValueError("source_mac must be a unicast address")
    if not isinstance(ssid, bytes) or len(ssid) > 32:
        raise ValueError("ssid must be at most 32 bytes")
    if isinstance(channel, bool) or not isinstance(channel, int) or not 1 <= channel <= 14:
        raise ValueError("example frames support 2.4 GHz channel numbers 1 through 14")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 4095:
        raise ValueError("sequence must be an integer from 0 through 4095")
    control, data = encode_control(fragment.control), encode_data(fragment.data)
    return (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=source_mac,
                addr3=source_mac, SC=sequence << 4)
        / Dot11Beacon(timestamp=0, beacon_interval=100, cap="ESS")
        / Dot11Elt(ID=0, info=ssid)
        / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
        / Dot11Elt(ID=3, info=bytes((channel,)))
        / Dot11Elt(ID=VENDOR_IE_ID, info=control[2:])
        / Dot11Elt(ID=VENDOR_IE_ID, info=data[2:])
    )


def decode_beacon(
    raw: bytes, *, linktype: int = DLT_IEEE802_11_RADIO,
    expected_oui: bytes = EXPERIMENTAL_OUI,
) -> Fragment | None:
    """Decode one DATA beacon. Return None for unrelated, structurally valid traffic.

    Validate the raw IE boundaries rather than reserializing Scapy's tolerant
    dissection. Raw 802.11 input (linktype 105) is assumed to omit the FCS.
    """
    validate_oui(expected_oui)
    if not isinstance(raw, bytes):
        raise InvalidPacket("frame must be bytes")
    if linktype == DLT_IEEE802_11_RADIO:
        if len(raw) < 8 or raw[0] != 0:
            raise InvalidPacket("missing or unsupported radiotap header")
        length = int.from_bytes(raw[2:4], "little")
        if not 8 <= length <= len(raw):
            raise InvalidPacket("invalid radiotap header length")
        try:
            radiotap = RadioTap(raw[:length])
            has_fcs = bool(int(radiotap.Flags or 0) & 0x10)
        except (ValueError, TypeError, AttributeError, IndexError, struct.error) as exc:
            raise InvalidPacket("malformed radiotap header") from exc
        raw = raw[length:]
        if has_fcs:
            if len(raw) < 4:
                raise InvalidPacket("missing radiotap-indicated FCS")
            raw = raw[:-4]
    elif linktype != DLT_IEEE802_11:
        raise InvalidPacket(f"unsupported PCAP link type: {linktype}")
    if len(raw) < 2:
        raise InvalidPacket("missing IEEE 802.11 frame control")
    if raw[0] & 0xFC != 0x80:
        return None
    if raw[0] & 0x03 or raw[1] & 0xCB:
        raise InvalidPacket("unsupported beacon version, protection, fragmentation, or DS/order flags")
    if len(raw) < 36:
        raise InvalidPacket("truncated beacon MAC header or fixed parameters")
    if raw[22] & 0x0F:
        raise InvalidPacket("fragmented IEEE 802.11 beacon is not supported")
    elements = raw[36:]
    control_bytes = data_bytes = None
    cursor = 0
    while cursor < len(elements):
        if len(elements) - cursor < 2:
            raise InvalidIE("truncated IE header")
        element_id, size = elements[cursor:cursor + 2]
        end = cursor + 2 + size
        if end > len(elements):
            raise InvalidIE("truncated IE body")
        encoded = elements[cursor:end]
        body = encoded[2:]
        cursor = end
        if element_id != VENDOR_IE_ID:
            continue
        if len(body) < 3:
            raise InvalidIE("vendor IE is missing its OUI")
        if body[:3] != expected_oui:
            continue
        if len(body) < 4:
            raise InvalidIE("Beacon IE is missing its internal type")
        if body[3] == CONTROL_IE_TYPE:
            if control_bytes is not None:
                raise InvalidPacket("multiple Beacon Control IEs in one frame")
            control_bytes = encoded
        elif body[3] == DATA_IE_TYPE:
            if data_bytes is not None:
                raise InvalidPacket("multiple Beacon Data IEs in one frame")
            data_bytes = encoded
        else:
            raise InvalidIE(f"unknown Beacon internal IE type: {body[3]:#04x}")
    if control_bytes is None and data_bytes is None:
        return None
    if control_bytes is None:
        raise InvalidPacket("missing Beacon Control IE")
    control = decode_control(control_bytes, expected_oui=expected_oui)
    if control.message_type != MessageType.DATA:
        raise UnsupportedMessageType(f"{control.message_type.name} semantics are deferred")
    if data_bytes is None:
        raise InvalidPacket("missing Beacon Data IE")
    fragment = Fragment(control, decode_data(data_bytes, expected_oui=expected_oui))
    validate_fragment(fragment)
    return fragment
