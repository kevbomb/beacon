"""Encode text, optionally compress it, then fragment the encoded bytes."""

import zlib

from .constants import EXPERIMENTAL_OUI, MAX_PACKETS, MAX_PAYLOAD_SIZE, Flags
from .errors import InvalidPacket
from .models import ControlIE, DataIE, Fragment
from .validation import validate_control


def fragment_message(
    text: str, *, sender_id: int, recipient_id: int, message_id: int,
    compress: bool = True, oui: bytes = EXPERIMENTAL_OUI,
) -> list[Fragment]:
    """Return DATA fragments; IDs are allocated by the caller, not this function."""
    validate_control(ControlIE(sender_id, recipient_id, message_id, 1, 1, oui=oui))
    if not isinstance(text, str):
        raise InvalidPacket("message text must be a string")
    try:
        wire = text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise InvalidPacket("message contains invalid Unicode (an unpaired surrogate)") from exc
    compressed = False
    if compress:
        candidate = zlib.compress(wire)
        if len(candidate) < len(wire):
            wire, compressed = candidate, True
    total = max(1, (len(wire) + MAX_PAYLOAD_SIZE - 1) // MAX_PAYLOAD_SIZE)
    if total > MAX_PACKETS:
        raise InvalidPacket("encoded message requires more than 65535 fragments")
    fragments = []
    for index in range(total):
        flags = Flags.COMPRESSED if compressed else Flags.NONE
        if index == 0:
            flags |= Flags.START
        if index == total - 1:
            flags |= Flags.END
        control = ControlIE(sender_id, recipient_id, message_id, index + 1, total, flags=flags, oui=oui)
        payload = wire[index * MAX_PAYLOAD_SIZE:(index + 1) * MAX_PAYLOAD_SIZE]
        fragments.append(Fragment(control, DataIE(payload, oui)))
    return fragments
