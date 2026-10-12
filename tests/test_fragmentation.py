import random
import zlib

import pytest

from beacon.protocol import Flags, InvalidPacket, Reassembler, fragment_message
from beacon.protocol.constants import MAX_PACKETS, MAX_PAYLOAD_SIZE


@pytest.mark.parametrize("size,count", [(0, 1), (1, 1), (250, 1), (251, 1), (252, 2), (502, 2), (503, 3)])
def test_boundaries_and_flags(size, count):
    text = "x" * size
    parts = fragment_message(text, sender_id=1, recipient_id=2, message_id=3, compress=False)
    assert len(parts) == count
    assert b"".join(part.data.payload for part in parts) == text.encode()
    for index, part in enumerate(parts, start=1):
        assert part.control.packet_number == index
        assert part.control.total_packets == count
        assert bool(part.control.flags & Flags.START) == (index == 1)
        assert bool(part.control.flags & Flags.END) == (index == count)
        assert not part.control.flags & Flags.COMPRESSED
        assert len(part.data.payload) <= 251


def test_utf8_character_can_span_fragments():
    text = "a" * 250 + "🌍" + "café\n"
    parts = fragment_message(text, sender_id=1, recipient_id=2, message_id=3, compress=False)
    with pytest.raises(UnicodeDecodeError):
        parts[0].data.payload.decode("utf-8")
    receiver = Reassembler()
    assert receiver.add(parts[0]) is None
    assert receiver.add(parts[1]).text == text


@pytest.mark.parametrize("text", ["", "Hi", "café", "A" * 10000])
def test_compress_only_if_smaller(text):
    parts = fragment_message(text, sender_id=1, recipient_id=2, message_id=3)
    expected_compression = len(zlib.compress(text.encode())) < len(text.encode())
    assert all(bool(part.control.flags & Flags.COMPRESSED) == expected_compression for part in parts)
    wire = b"".join(part.data.payload for part in parts)
    assert (zlib.decompress(wire) if expected_compression else wire) == text.encode()


def test_compressed_message_can_span_multiple_fragments():
    rng = random.Random(17)
    text = "".join(rng.choice("0123456789abcdef") for _ in range(12000))
    parts = fragment_message(text, sender_id=1, recipient_id=2, message_id=3)
    assert len(parts) > 1
    assert all(part.control.flags & Flags.COMPRESSED for part in parts)
    receiver = Reassembler()
    completed = [result for part in reversed(parts) if (result := receiver.add(part)) is not None]
    assert [result.text for result in completed] == [text]


@pytest.mark.parametrize("text", [b"bytes", None, "\ud800"])
def test_invalid_text(text):
    with pytest.raises(InvalidPacket):
        fragment_message(text, sender_id=1, recipient_id=2, message_id=3)


def test_packet_number_overflow():
    with pytest.raises(InvalidPacket, match="65535"):
        fragment_message("a" * (MAX_PACKETS * MAX_PAYLOAD_SIZE + 1), sender_id=1,
                         recipient_id=2, message_id=3, compress=False)
