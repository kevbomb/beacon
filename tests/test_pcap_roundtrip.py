import importlib.util
import struct
from pathlib import Path

import pytest
from scapy.layers.dot11 import Dot11
from scapy.utils import PcapNgWriter, RawPcapWriter, rdpcap

from beacon.protocol import fragment_message
from beacon.wireless.frames import DLT_IEEE802_11, build_beacon
from beacon.wireless.pcap import PcapFileError, decode_pcap, write_pcap


def frames(text="café 🌍" * 100, **kwargs):
    return [build_beacon(part) for part in fragment_message(text, sender_id=11, recipient_id=12,
                                                          message_id=13, **kwargs)]


@pytest.mark.parametrize("compress", [False, True])
def test_roundtrip_from_disk(tmp_path, compress):
    text = "café 🌍" * 100
    packets = frames(text, compress=compress)
    path = write_pcap(tmp_path / "chat.pcap", reversed(packets))
    report = decode_pcap(path)
    assert report.packet_count == len(packets)
    assert not report.errors
    assert report.pending_count == report.expired_count == 0
    assert [msg.text for msg in report.messages] == [text]
    assert (report.messages[0].sender_id, report.messages[0].recipient_id, report.messages[0].message_id) == (11, 12, 13)
    # A separate Scapy reader recognizes the written capture as 802.11 beacons.
    assert all(packet[Dot11].subtype == 8 for packet in rdpcap(str(path)))


def test_malformed_packet_does_not_abort_next_record(tmp_path):
    packet = frames("good")[0]
    path = write_pcap(tmp_path / "mixed.pcap", [bytes(packet)[:-1], packet, packet])
    report = decode_pcap(path)
    assert report.packet_count == 3
    assert len(report.errors) == 1
    assert report.errors[0].packet_number == 1
    assert [msg.text for msg in report.messages] == ["good"]


def test_missing_fragment_reports_incomplete(tmp_path):
    report = decode_pcap(write_pcap(tmp_path / "missing.pcap", frames(compress=False)[:-1]))
    assert not report.messages
    assert report.pending_count == 1


def test_raw_80211_capture(tmp_path):
    path = write_pcap(tmp_path / "raw.pcap", [packet[Dot11] for packet in frames()], linktype=DLT_IEEE802_11)
    assert decode_pcap(path).messages[0].text == "café 🌍" * 100


def test_pcapng_capture(tmp_path):
    path = tmp_path / "chat.pcapng"
    with PcapNgWriter(str(path)) as writer:
        for packet in frames():
            packet.time = 1_720_000_000
            writer.write(packet)
    report = decode_pcap(path)
    assert not report.errors
    assert report.messages[0].text == "café 🌍" * 100


def test_capture_time_drives_expiry(tmp_path):
    path = tmp_path / "expired.pcap"
    packets = frames("x" * 300, compress=False)
    with RawPcapWriter(str(path), linktype=127) as writer:
        writer.write_header(None)
        writer.write_packet(bytes(packets[0]), sec=100, usec=0)
        writer.write_packet(bytes(packets[1]), sec=131, usec=0)
    report = decode_pcap(path)
    assert not report.messages
    assert report.expired_count == 1
    assert report.pending_count == 1


def test_empty_capture(tmp_path):
    report = decode_pcap(write_pcap(tmp_path / "empty.pcap", []))
    assert report.packet_count == 0
    assert not report.errors


@pytest.mark.parametrize("content", [b"", b"not a pcap", bytes.fromhex("d4c3b2a1")])
def test_invalid_container(tmp_path, content):
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(PcapFileError):
        decode_pcap(path)


@pytest.mark.parametrize("tail", [b"partial header", struct.pack("<IIII", 1, 0, 100, 100) + b"short"])
def test_truncated_container_record(tmp_path, tail):
    path = write_pcap(tmp_path / "truncated.pcap", [])
    with path.open("ab") as stream:
        stream.write(tail)
    with pytest.raises(PcapFileError):
        decode_pcap(path)


def test_capture_snaplen_truncation_is_a_packet_error(tmp_path):
    path = tmp_path / "snaplen.pcap"
    raw = bytes(frames("ok")[0])
    with RawPcapWriter(str(path), linktype=127) as writer:
        writer.write_header(None)
        writer.write_packet(raw[:-1], sec=1, usec=0, wirelen=len(raw))
    report = decode_pcap(path)
    assert len(report.errors) == 1
    assert not report.messages


def test_output_is_deterministic(tmp_path):
    packets = frames()
    first = write_pcap(tmp_path / "a.pcap", packets).read_bytes()
    second = write_pcap(tmp_path / "b.pcap", packets).read_bytes()
    assert first == second


def test_example_generator_validates_all_captures(tmp_path):
    script = Path(__file__).resolve().parents[1] / "examples" / "generate_pcaps.py"
    spec = importlib.util.spec_from_file_location("generate_pcaps", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.generate(tmp_path)
    assert len(manifest) == 7
    assert manifest["malformed_then_valid.pcap"]["expected_errors"]
    assert (tmp_path / "manifest.json").exists()
