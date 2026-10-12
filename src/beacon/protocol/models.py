"""Immutable protocol values; codecs and receivers validate at their boundaries."""

from dataclasses import dataclass

from .constants import EXPERIMENTAL_OUI, PROTOCOL_VERSION, Flags, MessageType


@dataclass(frozen=True, slots=True)
class ControlIE:
    sender_id: int
    recipient_id: int
    message_id: int
    packet_number: int
    total_packets: int
    message_type: MessageType = MessageType.DATA
    flags: Flags = Flags.START | Flags.END
    oui: bytes = EXPERIMENTAL_OUI
    version: int = PROTOCOL_VERSION


@dataclass(frozen=True, slots=True)
class DataIE:
    payload: bytes
    oui: bytes = EXPERIMENTAL_OUI


@dataclass(frozen=True, slots=True)
class Fragment:
    control: ControlIE
    data: DataIE


@dataclass(frozen=True, slots=True)
class Message:
    sender_id: int
    recipient_id: int
    message_id: int
    text: str
    compressed: bool
    total_packets: int
