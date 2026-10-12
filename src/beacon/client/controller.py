"""One worker owns the radio and reassembler; UI threads exchange queued events."""

import queue
import threading
import time
from dataclasses import dataclass

from beacon.protocol import BROADCAST_ID, Message, ProtocolError
from beacon.wireless.base import RadioConfig
from .session import ChatSession


@dataclass(frozen=True, slots=True)
class ChatEvent:
    kind: str
    text: str = ""
    message: Message | None = None


def _transport_factory(config):
    from beacon.wireless.live import ScapyTransport
    return ScapyTransport(config)


class ChatController:
    """Shared asynchronous controller for both terminal and desktop clients."""

    def __init__(self, sender_id: int, *, compress: bool = True, transport_factory=None):
        self.sender_id = sender_id
        self.compress = compress
        self._session = ChatSession(sender_id, compress=compress)
        self._factory = transport_factory or _transport_factory
        self._events = queue.Queue(maxsize=128)
        self._frames = queue.Queue(maxsize=512)
        self._outgoing = queue.Queue(maxsize=16)
        self._stop = threading.Event()
        self._connected = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self._discarded = 0

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def connect(self, config: RadioConfig) -> None:
        with self._lock:
            if self.is_running:
                raise ValueError("Wait for the current connection to close")
            self._stop.clear()
            self._frames = queue.Queue(maxsize=512)
            self._outgoing = queue.Queue(maxsize=16)
            self._session = ChatSession(self.sender_id, compress=self.compress)
            self._discarded = 0
            self._thread = threading.Thread(target=self._run, args=(config,), daemon=True, name="beacon-radio")
            self._thread.start()

    def disconnect(self, *, wait: bool = False) -> None:
        with self._lock:
            self._connected.clear()
            self._stop.set()
        if wait and self._thread is not None:
            self._thread.join(timeout=10)

    def send_message(self, text: str, recipient_id: int = BROADCAST_ID) -> int:
        with self._lock:
            if not self.is_connected or self._stop.is_set():
                raise ValueError("Connect before sending a message")
            outgoing = self._session.prepare(text, recipient_id)
            try:
                self._outgoing.put_nowait(outgoing)
            except queue.Full as exc:
                raise ValueError("Send queue is full; wait for queued messages to finish") from exc
            return outgoing.message.message_id

    def poll(self) -> list[ChatEvent]:
        events = []
        while True:
            try:
                events.append(self._events.get_nowait())
            except queue.Empty:
                return events

    def _emit(self, event: ChatEvent) -> None:
        try:
            self._events.put_nowait(event)
        except queue.Full:
            # Bound application-owned messages when a UI cannot keep up.
            try:
                self._events.get_nowait()
            except queue.Empty:
                pass
            self._events.put_nowait(event)

    def _on_frame(self, raw: bytes, linktype: int) -> None:
        if self._stop.is_set():
            return
        if len(raw) > 8192:
            self._discarded += 1
            return
        try:
            self._frames.put_nowait((raw, linktype))
        except queue.Full:
            self._discarded += 1

    def _drain_frames(self, decode) -> None:
        for _ in range(64):
            try:
                raw, linktype = self._frames.get_nowait()
            except queue.Empty:
                break
            try:
                fragment = decode(raw, linktype=linktype)
                if fragment is not None:
                    message = self._session.receive(fragment)
                    if message is not None:
                        self._emit(ChatEvent("received", message=message))
            except ProtocolError:
                self._discarded += 1
        expired = self._session.receiver.expire()
        if expired:
            self._emit(ChatEvent("status", f"{expired} incomplete message(s) expired"))

    def _run(self, config: RadioConfig) -> None:
        transport = None
        sending = None
        try:
            from beacon.wireless.frames import decode_beacon
            transport = self._factory(config)
            description = transport.start(self._on_frame)
            with self._lock:
                if self._stop.is_set():
                    return
                self._connected.set()
            self._emit(ChatEvent("connected", description))
            report_at = time.monotonic()
            while not self._stop.is_set():
                transport.check()
                self._drain_frames(decode_beacon)
                if self._discarded and time.monotonic() >= report_at:
                    self._emit(ChatEvent("status", f"Discarded {self._discarded} invalid or excess frame(s)"))
                    self._discarded = 0
                    report_at = time.monotonic() + 1
                try:
                    sending = self._outgoing.get_nowait()
                except queue.Empty:
                    self._stop.wait(0.02)
                    continue
                for fragment in sending.fragments:
                    if self._stop.is_set():
                        break
                    transport.send(fragment)
                    self._drain_frames(decode_beacon)
                    self._stop.wait(config.interval)
                else:
                    self._emit(ChatEvent("sent", "Sent to adapter; delivery unconfirmed", sending.message))
                    sending = None
        except Exception as exc:
            detail = str(exc) or type(exc).__name__
            if isinstance(exc, PermissionError):
                detail += ". Launch Beacon with sudo to access the monitor interface."
            self._emit(ChatEvent("error", detail, sending.message if sending else None))
            sending = None
        finally:
            with self._lock:
                self._connected.clear()
                self._stop.set()
                if sending is not None:
                    self._emit(ChatEvent("error", "Send interrupted by disconnect", sending.message))
                while True:
                    try:
                        unsent = self._outgoing.get_nowait()
                    except queue.Empty:
                        break
                    self._emit(ChatEvent("error", "Queued message was not sent", unsent.message))
            if transport is not None:
                try:
                    transport.close()
                except Exception as exc:
                    self._emit(ChatEvent("error", f"Radio cleanup failed: {exc}"))
            self._emit(ChatEvent("disconnected", "Disconnected"))
