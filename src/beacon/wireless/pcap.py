"""Offline PCAP files. Packet errors are reported without aborting later records."""

import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.utils import RawPcapReader, RawPcapWriter

from beacon.protocol import EXPERIMENTAL_OUI, Message, ProtocolError, Reassembler, ReassemblyLimits
from .frames import DLT_IEEE802_11_RADIO, decode_beacon


class PcapFileError(ValueError):
    """The capture container cannot be read reliably."""


@dataclass(frozen=True, slots=True)
class PacketError:
    packet_number: int
    error_type: str
    detail: str


@dataclass(slots=True)
class DecodeReport:
    packet_count: int = 0
    ignored_count: int = 0
    pending_count: int = 0
    expired_count: int = 0
    messages: list[Message] = field(default_factory=list)
    errors: list[PacketError] = field(default_factory=list)


def _records(reader):
    while True:
        position = reader.f.tell()
        record = next(reader, None)
        if record is None:
            if type(reader) is RawPcapReader and reader.f.tell() != position:
                raise PcapFileError("truncated PCAP record header")
            return
        yield record


def write_pcap(path: str | Path, frames: Iterable[Packet | bytes], *, linktype: int = DLT_IEEE802_11_RADIO) -> Path:
    """Write deterministic timestamps and unmodified frame bytes to a classic PCAP."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with RawPcapWriter(str(target), linktype=linktype, sync=True) as writer:
        writer.write_header(None)
        for index, frame in enumerate(frames):
            writer.write_packet(bytes(frame), sec=1_720_000_000 + index, usec=0)
    return target


def decode_pcap(
    path: str | Path, *, oui: bytes = EXPERIMENTAL_OUI,
    limits: ReassemblyLimits | None = None,
) -> DecodeReport:
    """Decode classic PCAP/PCAPNG using capture time for reproducible expiration.

    Backwards timestamps are clamped to the latest observed time. A truncated or
    malformed packet is reported, then scanning continues at the next record.
    """
    report = DecodeReport()
    capture_time = 0.0
    receiver = Reassembler(oui=oui, limits=limits, clock=lambda: capture_time)
    try:
        with RawPcapReader(str(path)) as reader:
            for index, (raw, metadata) in enumerate(_records(reader), start=1):
                report.packet_count = index
                if hasattr(metadata, "sec"):
                    resolution = 1_000_000_000 if reader.nano else 1_000_000
                    timestamp = metadata.sec + metadata.usec / resolution
                else:
                    high, low = metadata.tshigh, metadata.tslow
                    timestamp = capture_time if high is None else ((high << 32) + low) / metadata.tsresol
                capture_time = max(capture_time, timestamp)
                report.expired_count += receiver.expire()
                linktype = getattr(metadata, "linktype", getattr(reader, "linktype", None))
                try:
                    if len(raw) < getattr(metadata, "caplen", len(raw)):
                        raise PcapFileError(f"truncated PCAP record {index}")
                    if len(raw) < metadata.wirelen:
                        report.errors.append(PacketError(index, "InvalidPacket", "capture truncated the original frame"))
                        continue
                    fragment = decode_beacon(raw, linktype=linktype, expected_oui=oui)
                    if fragment is None:
                        report.ignored_count += 1
                        continue
                    message = receiver.add(fragment)
                    if message is not None:
                        report.messages.append(message)
                except ProtocolError as exc:
                    report.errors.append(PacketError(index, type(exc).__name__, str(exc)))
    except (Scapy_Exception, EOFError, struct.error) as exc:
        raise PcapFileError(f"invalid PCAP container: {exc}") from exc
    report.pending_count = receiver.pending_count
    return report
