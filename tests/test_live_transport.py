from types import SimpleNamespace

import pytest
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11FCS, RadioTap

from beacon.wireless import live
from beacon.wireless.base import RadioConfig
from beacon.wireless.frames import build_beacon, decode_beacon


@pytest.fixture
def radio(monkeypatch):
    sockets, sent, sniffers = [], [], []

    class Socket:
        closed = False

        def __init__(self, **kwargs):
            self.iface = kwargs["iface"]
            sockets.append(self)

        def close(self):
            self.closed = True

    class Sniffer:
        running = False

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            sniffers.append(self)

        def start(self):
            self.running = True
            self.kwargs["started_callback"]()

        def stop(self, **kwargs):
            self.running = False

        def join(self, **kwargs):
            pass

    monkeypatch.setattr(live.conf, "L2listen", Socket)
    monkeypatch.setattr(live.conf, "L2socket", Socket)
    monkeypatch.setattr(live, "AsyncSniffer", Sniffer)
    monkeypatch.setattr(live, "sendp", lambda frame, **kwargs: sent.append((frame, kwargs)))
    monkeypatch.setattr(live, "inspect_interface", lambda name: live.InterfaceInfo(name, "02:00:00:00:00:01", 6, 2437))
    return SimpleNamespace(sockets=sockets, sent=sent, sniffers=sniffers)


@pytest.mark.parametrize("tx", [None, "mon1"])
def test_live_backend_uses_scapy_and_preserves_frame_bytes(radio, fragment, tx):
    captured = []
    backend = live.ScapyTransport(RadioConfig("mon0", tx, channel=6))
    assert "channel 6" in backend.start(lambda *args: captured.append(args))
    backend.send(fragment)
    packet, kwargs = radio.sent[0]
    assert decode_beacon(bytes(packet)) == fragment
    assert packet[Dot11].addr2 == "02:00:00:00:00:01"
    assert kwargs["socket"].iface == (tx or "mon0")
    assert radio.sniffers[0].kwargs["store"] is False
    radio.sniffers[0].kwargs["prn"](packet)
    assert captured == [(bytes(packet), 127)]
    backend.check()
    backend.close()
    assert all(socket.closed for socket in radio.sockets)
    assert not radio.sniffers[0].running


def test_transmit_socket_failure_closes_receive_socket(radio, monkeypatch):
    def failure(**kwargs):
        raise PermissionError("No access")
    monkeypatch.setattr(live.conf, "L2socket", failure)
    with pytest.raises(PermissionError):
        live.ScapyTransport(RadioConfig("mon0")).start(lambda *args: None)
    assert radio.sockets[0].closed


def test_wrong_channel_rejected_before_opening_sockets(radio):
    with pytest.raises(RuntimeError, match="not 1"):
        live.ScapyTransport(RadioConfig("mon0", channel=1)).start(lambda *args: None)
    assert not radio.sockets


def test_dual_adapters_must_share_frequency(radio, monkeypatch):
    monkeypatch.setattr(live, "inspect_interface", lambda name: live.InterfaceInfo(name, "02:00:00:00:00:01", 1 if name == "a" else 6, 2412 if name == "a" else 2437))
    with pytest.raises(RuntimeError, match="same channel"):
        live.ScapyTransport(RadioConfig("a", "b")).start(lambda *args: None)
    assert not radio.sockets


def test_stopped_receiver_is_reported(radio):
    backend = live.ScapyTransport(RadioConfig("mon0"))
    backend.start(lambda *args: None)
    radio.sniffers[0].running = False
    with pytest.raises(RuntimeError, match="reception stopped"):
        backend.check()
    backend.close()


@pytest.mark.parametrize("mode", ["monitor", "managed"])
def test_linux_interface_inspection(monkeypatch, mode):
    monkeypatch.setattr(live.sys, "platform", "linux")
    output = f"Interface mon0\n\taddr 02:00:00:00:00:01\n\ttype {mode}\n\tchannel 36 (5180 MHz), width: 20 MHz\n"
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(live.subprocess, "run", run)
    if mode == "monitor":
        info = live.inspect_interface("mon0")
        assert (info.channel, info.frequency_mhz) == (36, 5180)
    else:
        with pytest.raises(RuntimeError, match="not in monitor"):
            live.inspect_interface("mon0")
    assert calls == [["iw", "dev", "mon0", "info"]]


def test_five_ghz_beacon_uses_ofdm_and_no_ds_element(fragment):
    packet = build_beacon(fragment, channel=36, frequency_mhz=5180)
    assert decode_beacon(bytes(packet)) == fragment
    element = packet.getlayer(Dot11Elt)
    ids = []
    while isinstance(element, Dot11Elt):
        ids.append(element.ID)
        element = element.payload
    assert 3 not in ids
    with pytest.raises(ValueError, match="do not match"):
        build_beacon(fragment, channel=36, frequency_mhz=5200)


@pytest.mark.parametrize("radiotap", [True, False])
def test_capture_with_fcs_decodes_original_bytes(radio, fragment, radiotap):
    captured = []
    backend = live.ScapyTransport(RadioConfig("mon0"))
    backend.start(lambda raw, linktype: captured.append(decode_beacon(raw, linktype=linktype)))
    frame = Dot11FCS(bytes(build_beacon(fragment)[Dot11]) + b"\x00\x00\x00\x00")
    if radiotap:
        frame = RadioTap(bytes(RadioTap(present="Flags", Flags="FCS") / frame))
    try:
        radio.sniffers[0].kwargs["prn"](frame)
        assert captured == [fragment]
    finally:
        backend.close()
