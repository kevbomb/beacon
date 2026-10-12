"""Chat addressing and message preparation, independent of UI and Scapy."""

import secrets
from dataclasses import dataclass

from beacon.protocol import BROADCAST_ID, Flags, Fragment, Message, Reassembler, ReassemblyLimits, fragment_message
from beacon.protocol.validation import validate_fragment, validate_uint

MAX_CHAT_BYTES = 64 * 1024


def new_sender_id() -> int:
    return secrets.randbelow(BROADCAST_ID - 1) + 1


def parse_id(value: str) -> int:
    value = value.strip()
    if value.lower() in ("all", "broadcast", "*"):
        return BROADCAST_ID
    try:
        number = int(value, 16 if value.lower().startswith("0x") else 10)
    except ValueError as exc:
        raise ValueError("Use a decimal ID, a 0x-prefixed hexadecimal ID, or 'all'") from exc
    validate_uint(number, 32, "peer ID")
    return number


def format_id(value: int) -> str:
    return "all" if value == BROADCAST_ID else f"0x{value:08X}"


def display_text(text: str) -> str:
    """Render received text without letting control characters act on a terminal."""
    return "".join(f"\\x{ord(char):02x}" if (ord(char) < 32 and char not in "\n\t")
                   or 127 <= ord(char) <= 159 else char for char in text)


@dataclass(frozen=True, slots=True)
class Outgoing:
    message: Message
    fragments: tuple[Fragment, ...]


class ChatSession:
    def __init__(self, sender_id: int, *, compress: bool = True):
        validate_uint(sender_id, 32, "sender ID")
        if sender_id == BROADCAST_ID:
            raise ValueError("Choose a local ID other than the broadcast ID")
        self.sender_id = sender_id
        self.compress = compress
        self.receiver = Reassembler(limits=ReassemblyLimits(
            max_wire_bytes=MAX_CHAT_BYTES, max_decoded_bytes=MAX_CHAT_BYTES,
        ))
        self._next_id = secrets.randbits(32)

    def prepare(self, text: str, recipient_id: int = BROADCAST_ID) -> Outgoing:
        validate_uint(recipient_id, 32, "recipient ID")
        if recipient_id == self.sender_id:
            raise ValueError("Choose another peer ID or 'all'")
        if not text or not text.strip():
            raise ValueError("Enter a message")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("Message contains invalid Unicode") from exc
        if size > MAX_CHAT_BYTES:
            raise ValueError("Chat messages must be at most 64 KiB of UTF-8 text")
        message_id = self._next_id
        self._next_id = (message_id + 1) & 0xFFFFFFFF
        fragments = tuple(fragment_message(text, sender_id=self.sender_id, recipient_id=recipient_id,
                                           message_id=message_id, compress=self.compress))
        message = Message(self.sender_id, recipient_id, message_id, text,
                          bool(fragments[0].control.flags & Flags.COMPRESSED), len(fragments))
        return Outgoing(message, fragments)

    def receive(self, fragment: Fragment) -> Message | None:
        validate_fragment(fragment)
        control = fragment.control
        if control.sender_id == self.sender_id or control.recipient_id not in (self.sender_id, BROADCAST_ID):
            return None
        return self.receiver.add(fragment)
