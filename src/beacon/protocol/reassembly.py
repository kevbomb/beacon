"""Bounded, out-of-order DATA reassembly without network or timer threads."""

import math
import time
import zlib
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from .constants import EXPERIMENTAL_OUI, MAX_PACKETS, Flags
from .errors import InvalidPacket, ReassemblyError, ResourceLimitError
from .models import ControlIE, Fragment, Message
from .validation import validate_fragment, validate_oui

MessageKey = tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class ReassemblyLimits:
    max_wire_bytes: int = 1024 * 1024
    max_decoded_bytes: int = 1024 * 1024
    max_fragments: int = 8192
    max_pending_messages: int = 128
    max_buffered_bytes: int = 8 * 1024 * 1024
    max_recent_messages: int = 1024
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        for name in (
            "max_wire_bytes", "max_decoded_bytes", "max_fragments",
            "max_pending_messages", "max_buffered_bytes", "max_recent_messages",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_fragments > MAX_PACKETS:
            raise ValueError("max_fragments cannot exceed 65535")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive and finite")


@dataclass(slots=True)
class _Pending:
    control: ControlIE
    updated_at: float
    parts: dict[int, bytes] = field(default_factory=dict)
    byte_count: int = 0


def _metadata(control: ControlIE) -> tuple:
    return (
        control.oui, control.version, control.total_packets,
        control.message_type, bool(control.flags & Flags.COMPRESSED),
    )


class Reassembler:
    """Single-owner receiver. Use one instance per configured OUI.

    `add` returns a completed Message or None. Expected malformed input raises a
    ProtocolError subclass. This object is not thread-safe; serialize access.
    """

    def __init__(
        self, *, limits: ReassemblyLimits | None = None,
        oui: bytes = EXPERIMENTAL_OUI, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        validate_oui(oui)
        self.limits = limits or ReassemblyLimits()
        self.oui = oui
        self._clock = clock
        self._pending: dict[MessageKey, _Pending] = {}
        self._recent: OrderedDict[MessageKey, float] = OrderedDict()
        self._buffered_bytes = 0

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def buffered_bytes(self) -> int:
        return self._buffered_bytes

    @property
    def recent_count(self) -> int:
        return len(self._recent)

    def _drop(self, key: MessageKey) -> None:
        state = self._pending.pop(key, None)
        if state is not None:
            self._buffered_bytes -= state.byte_count

    def _remember(self, key: MessageKey, now: float) -> None:
        self._recent[key] = now + self.limits.timeout_seconds
        self._recent.move_to_end(key)
        while len(self._recent) > self.limits.max_recent_messages:
            self._recent.popitem(last=False)

    def _expire(self, now: float) -> int:
        expired = [key for key, state in self._pending.items()
                   if now - state.updated_at >= self.limits.timeout_seconds]
        for key in expired:
            self._drop(key)
        for key, deadline in list(self._recent.items()):
            if now >= deadline:
                del self._recent[key]
        return len(expired)

    def expire(self) -> int:
        """Discard expired state and return the number of expired pending messages."""
        return self._expire(self._clock())

    def _decode(self, wire: bytes, compressed: bool) -> str:
        limit = self.limits.max_decoded_bytes
        if compressed:
            decoder = zlib.decompressobj()
            try:
                decoded = decoder.decompress(wire, limit + 1)
            except zlib.error as exc:
                raise ReassemblyError("invalid zlib stream") from exc
            if len(decoded) > limit or decoder.unconsumed_tail:
                raise ResourceLimitError("decompressed message exceeds max_decoded_bytes")
            if not decoder.eof:
                raise ReassemblyError("truncated zlib stream")
            if decoder.unused_data:
                raise ReassemblyError("trailing bytes or concatenated zlib streams")
        else:
            decoded = wire
            if len(decoded) > limit:
                raise ResourceLimitError("message exceeds max_decoded_bytes")
        try:
            return decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ReassemblyError("assembled message is not valid UTF-8") from exc

    def add(self, fragment: Fragment) -> Message | None:
        validate_fragment(fragment)
        control = fragment.control
        if control.oui != self.oui:
            raise InvalidPacket("fragment OUI does not match this receiver")
        now = self._clock()
        self._expire(now)
        key = (control.sender_id, control.recipient_id, control.message_id)
        if key in self._recent:
            return None
        try:
            if control.total_packets > self.limits.max_fragments:
                raise ResourceLimitError("message exceeds max_fragments")
            state = self._pending.get(key)
            if state is None:
                if len(self._pending) >= self.limits.max_pending_messages:
                    raise ResourceLimitError("receiver exceeds max_pending_messages")
                state = _Pending(control, now)
                self._pending[key] = state
            elif _metadata(state.control) != _metadata(control):
                raise ReassemblyError("inconsistent message metadata")
            payload = fragment.data.payload
            if control.packet_number in state.parts:
                if state.parts[control.packet_number] != payload:
                    raise ReassemblyError("conflicting duplicate fragment")
                return None
            if state.byte_count + len(payload) > self.limits.max_wire_bytes:
                raise ResourceLimitError("message exceeds max_wire_bytes")
            if self._buffered_bytes + len(payload) > self.limits.max_buffered_bytes:
                raise ResourceLimitError("receiver exceeds max_buffered_bytes")
            state.parts[control.packet_number] = payload
            state.byte_count += len(payload)
            state.updated_at = now
            self._buffered_bytes += len(payload)
            if len(state.parts) < control.total_packets:
                return None
            wire = b"".join(state.parts[number] for number in range(1, control.total_packets + 1))
            compressed = bool(control.flags & Flags.COMPRESSED)
            text = self._decode(wire, compressed)
            self._drop(key)
            self._remember(key, now)
            return Message(control.sender_id, control.recipient_id, control.message_id,
                           text, compressed, control.total_packets)
        except ReassemblyError:
            self._drop(key)
            self._remember(key, now)
            raise
