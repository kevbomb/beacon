"""Linux monitor-mode transport using Scapy L2 sockets and AsyncSniffer."""

import re
import subprocess
import sys
import threading
from dataclasses import dataclass

from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11FCS, RadioTap, conf, sendp

from .base import RadioConfig
from .frames import DLT_IEEE802_11, DLT_IEEE802_11_RADIO, build_beacon


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    name: str
    mac: str
    channel: int
    frequency_mhz: int


def inspect_interface(name: str) -> InterfaceInfo:
    """Read adapter state with iw. Never reconfigure an interface or its channel."""
    if sys.platform != "linux":
        raise RuntimeError("Live wireless chat currently requires Linux (including Kali).")
    try:
        result = subprocess.run(["iw", "dev", name, "info"], capture_output=True,
                                text=True, timeout=5, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError("Install iw to inspect the monitor interface (sudo apt install iw).") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Timed out inspecting interface {name}.") from exc
    if result.returncode:
        raise RuntimeError(f"Cannot inspect {name}: {result.stderr.strip() or 'interface not found'}")
    if not re.search(r"^\s*type monitor\s*$", result.stdout, re.MULTILINE):
        raise RuntimeError(f"{name} is not in monitor mode. Configure it before connecting.")
    mac = re.search(r"^\s*addr ([0-9a-fA-F:]{17})\s*$", result.stdout, re.MULTILINE)
    channel = re.search(r"channel (\d+) \((\d+) MHz\)", result.stdout)
    if mac is None or channel is None:
        raise RuntimeError(f"{name} has no readable MAC/channel. Set a channel before connecting.")
    info = InterfaceInfo(name, mac[1], int(channel[1]), int(channel[2]))
    if not (2412 <= info.frequency_mhz <= 2484 or 5000 < info.frequency_mhz < 5925):
        raise RuntimeError("This live backend supports 2.4 GHz and 5 GHz channels.")
    return info


class ScapyTransport:
    def __init__(self, config: RadioConfig):
        self.config = config
        self._rx = self._tx = self._sniffer = None
        self._info = None
        self._sequence = 0

    def start(self, on_frame) -> str:
        rx_info = inspect_interface(self.config.rx_iface)
        tx_name = self.config.tx_iface or self.config.rx_iface
        tx_info = rx_info if tx_name == rx_info.name else inspect_interface(tx_name)
        if rx_info.frequency_mhz != tx_info.frequency_mhz:
            raise RuntimeError("Receive and transmit interfaces must be on the same channel/frequency.")
        if self.config.channel is not None and self.config.channel != rx_info.channel:
            raise RuntimeError(f"{rx_info.name} is on channel {rx_info.channel}, not {self.config.channel}.")
        self._info = tx_info
        ready = threading.Event()

        def receive(packet):
            if RadioTap in packet:
                layer, linktype = packet[RadioTap], DLT_IEEE802_11_RADIO
            elif Dot11 in packet:
                layer, linktype = packet[Dot11], DLT_IEEE802_11
            else:
                return
            raw = layer.original or bytes(layer)
            if isinstance(layer, Dot11FCS):
                raw = raw[:-4]
            on_frame(raw, linktype)

        try:
            self._rx = conf.L2listen(iface=rx_info.name)
            self._tx = conf.L2socket(iface=tx_info.name)
            self._sniffer = AsyncSniffer(
                opened_socket=self._rx, store=False,
                lfilter=lambda packet: Dot11Beacon in packet,
                prn=receive, started_callback=ready.set,
            )
            self._sniffer.start()
            if not ready.wait(5):
                self._sniffer.join(timeout=0)
                raise RuntimeError("Scapy did not start receiving within 5 seconds.")
        except Exception:
            self.close()
            raise
        return f"RX {rx_info.name} / TX {tx_info.name} · channel {rx_info.channel} ({rx_info.frequency_mhz} MHz)"

    def send(self, fragment) -> None:
        if self._tx is None or self._info is None:
            raise RuntimeError("Radio is disconnected")
        frame = build_beacon(fragment, source_mac=self._info.mac, ssid=b"Beacon-chat",
                             channel=self._info.channel, frequency_mhz=self._info.frequency_mhz,
                             sequence=self._sequence)
        self._sequence = (self._sequence + 1) % 4096
        sendp(frame, socket=self._tx, verbose=False)

    def check(self) -> None:
        if self._sniffer is None or not self._sniffer.running:
            if self._sniffer is not None:
                self._sniffer.join(timeout=0)
            raise RuntimeError("Wireless reception stopped. Check the adapter and reconnect.")

    def close(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        try:
            if sniffer is not None:
                if sniffer.running:
                    try:
                        sniffer.stop(join=False)
                    except Exception:
                        pass
                try:
                    sniffer.join(timeout=2)
                except Exception:
                    pass
        finally:
            for name in ("_rx", "_tx"):
                socket = getattr(self, name)
                setattr(self, name, None)
                if socket is not None:
                    try:
                        socket.close()
                    except OSError:
                        pass
