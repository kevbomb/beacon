import time
import threading

from beacon.client.controller import ChatController
from beacon.wireless.base import RadioConfig
from beacon.wireless.frames import build_beacon


def wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("Timed out waiting for chat event")


class RadioHub:
    def __init__(self):
        self.radios = []
        self.frames = []

    def factory(self, config):
        hub = self
        class Radio:
            closed = False

            def start(self, callback):
                self.callback = callback
                hub.radios.append(self)
                return "Test radio channel 1"

            def send(self, fragment):
                frame = bytes(build_beacon(fragment))
                hub.frames.append(frame)
                for peer in hub.radios:
                    if not peer.closed:
                        peer.callback(frame, 127)

            def check(self):
                pass

            def close(self):
                self.closed = True
        return Radio()


def test_two_clients_exchange_actual_beacon_bytes_and_filter_recipients():
    hub = RadioHub()
    clients = [ChatController(identifier, compress=False, transport_factory=hub.factory) for identifier in (1, 2, 3)]
    histories = [[], [], []]
    def collect():
        for history, client in zip(histories, clients):
            history.extend(client.poll())
    try:
        for client in clients:
            client.connect(RadioConfig("test", interval=0.001))
        wait_for(lambda: all(client.is_connected for client in clients))
        text = "hello café 🌍 " * 70
        clients[0].send_message(text, 2)
        def received():
            collect()
            return any(event.kind == "received" for event in histories[1])
        wait_for(received)
        clients[1].send_message("reply to everyone")
        def reply_received():
            collect()
            return any(event.kind == "received" for event in histories[0]) and any(event.kind == "received" for event in histories[2])
        wait_for(reply_received)
        assert [event.message.text for event in histories[1] if event.kind == "received"] == [text]
        assert [event.message.text for event in histories[2] if event.kind == "received"] == ["reply to everyone"]
        assert len(hub.frames) > 1
        assert not any(event.kind == "error" for history in histories for event in history)
    finally:
        for client in clients:
            client.disconnect(wait=True)
    assert all(radio.closed for radio in hub.radios)


def test_startup_failure_is_visible_and_closes_transport():
    closed = []
    class Broken:
        def start(self, callback):
            raise PermissionError("permission denied")
        def close(self):
            closed.append(True)
    client = ChatController(1, transport_factory=lambda config: Broken())
    client.connect(RadioConfig("test"))
    wait_for(lambda: not client.is_running)
    events = client.poll()
    assert any(event.kind == "error" and "sudo" in event.text for event in events)
    assert events[-1].kind == "disconnected"
    assert closed and not client.is_connected


def test_bad_frames_do_not_stop_receiving(fragment):
    hub = RadioHub()
    client = ChatController(2, transport_factory=hub.factory)
    history = []
    try:
        client.connect(RadioConfig("test", interval=0.001))
        wait_for(lambda: client.is_connected)
        hub.radios[0].callback(b"bad frame", 127)
        hub.radios[0].callback(bytes(build_beacon(fragment)), 127)
        def received():
            history.extend(client.poll())
            return any(event.kind == "received" for event in history)
        wait_for(received)
        assert client.is_connected
        assert [event.message.text for event in history if event.kind == "received"] == ["Hi"]
    finally:
        client.disconnect(wait=True)


def test_transmit_failure_reports_current_and_queued_messages():
    started, release = threading.Event(), threading.Event()
    class FailingRadio:
        closed = False
        def start(self, callback):
            return "test"
        def check(self):
            pass
        def send(self, fragment):
            started.set()
            assert release.wait(3)
            raise OSError("adapter disconnected")
        def close(self):
            self.closed = True
    radio = FailingRadio()
    client = ChatController(1, transport_factory=lambda config: radio)
    try:
        client.connect(RadioConfig("test"))
        wait_for(lambda: client.is_connected)
        client.send_message("first")
        assert started.wait(3)
        client.send_message("second")
        release.set()
        wait_for(lambda: not client.is_running)
        events = client.poll()
        errors = [event for event in events if event.kind == "error"]
        assert [event.message.text for event in errors] == ["first", "second"]
        assert not any(event.kind == "sent" for event in events)
        assert radio.closed and not client.is_connected
    finally:
        release.set()
        client.disconnect(wait=True)
