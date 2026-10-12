"""Field validation shared by encoders, decoders, and reassembly."""

from .constants import MAX_PACKETS, MAX_PAYLOAD_SIZE, PROTOCOL_VERSION, Flags, MessageType
from .errors import InvalidIE, InvalidPacket, UnsupportedMessageType
from .models import ControlIE, DataIE, Fragment


def validate_oui(oui: bytes) -> None:
    if not isinstance(oui, bytes) or len(oui) != 3:
        raise InvalidIE("OUI must be exactly three bytes")


def validate_uint(value: int, bits: int, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise InvalidIE(f"{field} must be an unsigned {bits}-bit integer")


def validate_control(control: ControlIE) -> None:
    validate_oui(control.oui)
    validate_uint(control.version, 8, "version")
    if control.version != PROTOCOL_VERSION:
        raise InvalidIE(f"unsupported protocol version: {control.version}")
    for name in ("sender_id", "recipient_id", "message_id"):
        validate_uint(getattr(control, name), 32, name)
    validate_uint(control.packet_number, 16, "packet_number")
    validate_uint(control.total_packets, 16, "total_packets")
    if not 1 <= control.packet_number <= control.total_packets <= MAX_PACKETS:
        raise InvalidIE("packet numbering must satisfy 1 <= packet_number <= total_packets <= 65535")
    validate_uint(control.message_type, 8, "message_type")
    try:
        MessageType(control.message_type)
    except ValueError as exc:
        raise InvalidIE(f"unknown message type: {control.message_type}") from exc
    validate_uint(control.flags, 8, "flags")
    if int(control.flags) & ~int(Flags.START | Flags.END | Flags.COMPRESSED):
        raise InvalidIE("unknown flag bits")
    if control.message_type == MessageType.DATA:
        if bool(control.flags & Flags.START) != (control.packet_number == 1):
            raise InvalidIE("START must appear exactly on DATA packet 1")
        if bool(control.flags & Flags.END) != (control.packet_number == control.total_packets):
            raise InvalidIE("END must appear exactly on the final DATA packet")


def validate_data(data: DataIE) -> None:
    validate_oui(data.oui)
    if not isinstance(data.payload, bytes) or len(data.payload) > MAX_PAYLOAD_SIZE:
        raise InvalidIE("Data IE payload must be bytes of length 0 through 251")


def validate_fragment(fragment: Fragment) -> None:
    validate_control(fragment.control)
    validate_data(fragment.data)
    if fragment.control.message_type != MessageType.DATA:
        raise UnsupportedMessageType("only DATA has implemented fragment/reassembly semantics")
    if fragment.control.oui != fragment.data.oui:
        raise InvalidPacket("Control and Data IE OUIs differ")
