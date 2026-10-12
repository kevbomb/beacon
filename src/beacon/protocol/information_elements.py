"""Strict serialization of complete IE 221 elements, including ID and length."""

import struct

from .constants import (
    CONTROL_BODY_SIZE, CONTROL_IE_TYPE, DATA_IE_TYPE, EXPERIMENTAL_OUI,
    VENDOR_IE_ID, Flags, MessageType,
)
from .errors import InvalidIE
from .models import ControlIE, DataIE
from .validation import validate_control, validate_data, validate_oui

_CONTROL = struct.Struct("!3sBBIIIHHBB")


def _body(encoded: bytes, internal_type: int, expected_oui: bytes | None) -> bytes:
    if not isinstance(encoded, bytes) or len(encoded) < 2:
        raise InvalidIE("missing IE envelope")
    if encoded[0] != VENDOR_IE_ID:
        raise InvalidIE("expected vendor-specific IE 221")
    if encoded[1] != len(encoded) - 2:
        raise InvalidIE("IE length does not match available bytes")
    body = encoded[2:]
    if len(body) < 4:
        raise InvalidIE("vendor IE is missing its OUI/type prefix")
    if expected_oui is not None:
        validate_oui(expected_oui)
        if body[:3] != expected_oui:
            raise InvalidIE("unexpected OUI")
    if body[3] != internal_type:
        raise InvalidIE(f"expected internal IE type {internal_type:#04x}")
    return body


def encode_control(control: ControlIE) -> bytes:
    validate_control(control)
    body = _CONTROL.pack(
        control.oui, CONTROL_IE_TYPE, control.version, control.sender_id,
        control.recipient_id, control.message_id, control.packet_number,
        control.total_packets, control.message_type, control.flags,
    )
    return bytes((VENDOR_IE_ID, len(body))) + body


def decode_control(encoded: bytes, *, expected_oui: bytes | None = EXPERIMENTAL_OUI) -> ControlIE:
    body = _body(encoded, CONTROL_IE_TYPE, expected_oui)
    if len(body) != CONTROL_BODY_SIZE:
        raise InvalidIE("Control IE body must be exactly 23 bytes")
    oui, _, version, sender, recipient, message, number, total, kind, flags = _CONTROL.unpack(body)
    control = ControlIE(sender, recipient, message, number, total, kind, flags, oui, version)
    validate_control(control)
    return ControlIE(sender, recipient, message, number, total, MessageType(kind), Flags(flags), oui, version)


def encode_data(data: DataIE) -> bytes:
    validate_data(data)
    body = data.oui + bytes((DATA_IE_TYPE,)) + data.payload
    return bytes((VENDOR_IE_ID, len(body))) + body


def decode_data(encoded: bytes, *, expected_oui: bytes | None = EXPERIMENTAL_OUI) -> DataIE:
    body = _body(encoded, DATA_IE_TYPE, expected_oui)
    data = DataIE(body[4:], body[:3])
    validate_data(data)
    return data
