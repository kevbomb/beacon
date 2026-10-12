"""Exercise both presentation layers without opening any wireless sockets."""

import io
from types import SimpleNamespace

import pytest

from beacon import __main__ as launcher
from beacon.client import cli, gui
from beacon.client.controller import ChatEvent
from beacon.client.options import parser_for
from beacon.client.session import ChatSession


class FakeController:
    def __init__(self, sender_id, *, compress=True):
        self.session = ChatSession(sender_id, compress=compress)
        self.is_running = self.is_connected = False
        self.events = []
        self.sent = []

    def connect(self, config):
        self.config = config
        self.is_running = self.is_connected = True
        self.events.append(ChatEvent("connected", "Test adapter"))

    def send_message(self, text, recipient):
        message = self.session.prepare(text, recipient).message
        self.sent.append(message)
        self.events.append(ChatEvent("sent", message=message))
        return message.message_id

    def poll(self):
        events, self.events = self.events, []
        return events

    def disconnect(self, *, wait=False):
        if self.is_running:
            self.events.append(ChatEvent("disconnected", "Disconnected"))
        self.is_running = self.is_connected = False


def test_terminal_commands_and_unicode_chat(monkeypatch, capsys):
    controller = FakeController(1)
    monkeypatch.setattr(cli, "ChatController", lambda *args, **kwargs: controller)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("/id\n/to 2\nHello 🌍\n/to all\nHi everyone\n/quit\n"))
    assert cli.main(["--iface", "mon0", "--id", "1"]) == 0
    assert [(message.recipient_id, message.text) for message in controller.sent] == [
        (2, "Hello 🌍"), (0xFFFFFFFF, "Hi everyone"),
    ]
    output = capsys.readouterr().out
    assert "Your ID: 0x00000001" in output
    assert "unconfirmed] Hello 🌍" in output
    assert "DISCONNECTED" in output
    assert not controller.is_running


def test_terminal_does_not_lose_an_error_as_worker_exits(monkeypatch, capsys):
    class FailingController(FakeController):
        def poll(self):
            # Simulate the radio stopping just after the first queue drain.
            events = super().poll()
            if self.is_running:
                self.is_running = self.is_connected = False
                self.events.append(ChatEvent("error", "Adapter unplugged"))
            return events
    controller = FailingController(1)
    monkeypatch.setattr(cli, "ChatController", lambda *args, **kwargs: controller)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
    assert cli.main(["--iface", "mon0", "--id", "1"]) == 1
    assert "Adapter unplugged" in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["cli", "gui"])
def test_module_dispatch_preserves_client_help(mode, capsys):
    with pytest.raises(SystemExit) as error:
        launcher.main([mode, "--help"])
    assert error.value.code == 0
    assert "--tx-iface" in capsys.readouterr().out


@pytest.fixture
def window():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Desktop unavailable (use xvfb-run on Linux): {exc}")
    root.withdraw()
    args = parser_for("test").parse_args(["--iface", "mon0", "--id", "1", "--to", "2"])
    app = gui.ChatWindow(root, args, controller_factory=FakeController)
    root.after_cancel(app._poll_id)
    try:
        yield app
    finally:
        if app.controller:
            app.controller.disconnect()
        root.after_cancel(app._poll_id)
        root.destroy()


def test_desktop_connect_send_receive_and_disconnect(window):
    window.toggle_connection()
    window._poll()
    assert window.status.get() == "Connected"
    assert not window.send_button.instate(["disabled"])
    window.compose.insert("1.0", "Hello from the desktop 🌍")
    assert window._enter(SimpleNamespace(state=0)) == "break"
    assert window.controller.sent[0].recipient_id == 2
    assert window.compose.get("1.0", "end-1c") == ""
    reply = ChatSession(2).prepare("Hello from the terminal", 1).message
    window.controller.events.append(ChatEvent("received", message=reply))
    window.root.after_cancel(window._poll_id)
    window._poll()
    transcript = window.transcript.get("1.0", "end-1c")
    assert "Hello from the desktop 🌍" in transcript
    assert "Hello from the terminal" in transcript
    assert "unconfirmed" in transcript
    assert window._enter(SimpleNamespace(state=1)) is None
    window.toggle_connection()
    window.root.after_cancel(window._poll_id)
    window._poll()
    assert window.status.get() == "Disconnected"
    assert window.send_button.instate(["disabled"])


def test_desktop_validation_preserves_unsent_text(window):
    window.toggle_connection()
    window.recipient.set("invalid")
    window.compose.insert("1.0", "Keep this message")
    window.send()
    assert window.compose.get("1.0", "end-1c") == "Keep this message"
    assert not window.controller.sent
    assert "Message not queued" in window.transcript.get("1.0", "end-1c")


def test_desktop_rejects_missing_interface(window):
    window.rx.set("")
    window.toggle_connection()
    assert window.controller is None
    assert "Choose a monitor interface" in window.transcript.get("1.0", "end-1c")
