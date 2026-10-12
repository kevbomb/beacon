"""Wire constants; these values do not depend on Scapy."""

from enum import IntEnum, IntFlag

VENDOR_IE_ID = 221
EXPERIMENTAL_OUI = b"\x02\x00\x00"
PROTOCOL_VERSION = 1
CONTROL_IE_TYPE = 0x01
DATA_IE_TYPE = 0x02
CONTROL_BODY_SIZE = 23
MAX_PAYLOAD_SIZE = 251
MAX_PACKETS = 0xFFFF
BROADCAST_ID = 0xFFFFFFFF


class MessageType(IntEnum):
    DATA = 0x01
    ACK = 0x02
    NACK = 0x03
    HELLO = 0x04
    CLOSE = 0x05


class Flags(IntFlag):
    NONE = 0
    START = 0x01
    END = 0x02
    COMPRESSED = 0x04
