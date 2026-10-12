import random
import zlib
from dataclasses import replace

import pytest

from beacon.protocol import (
    ControlIE, DataIE, Flags, Fragment, InvalidPacket, Reassembler,
    ReassemblyError, ReassemblyLimits, ResourceLimitError, fragment_message,
)


def parts(text="x" * 600, **kwargs):
    return fragment_message(text, sender_id=kwargs.get("sender_id", 1),
                            recipient_id=kwargs.get("recipient_id", 2),
                            message_id=kwargs.get("message_id", 3), compress=False)


def payload_fragment(payload, *, compressed=False):
    flags = Flags.START | Flags.END | (Flags.COMPRESSED if compressed else Flags.NONE)
    return Fragment(ControlIE(1, 2, 3, 1, 1, flags=flags), DataIE(payload))


def test_out_of_order_missing_and_duplicate():
    fragments = parts()
    receiver = Reassembler()
    assert receiver.add(fragments[2]) is None
    assert receiver.add(fragments[0]) is None
    before = receiver.buffered_bytes
    assert receiver.add(fragments[0]) is None
    assert receiver.buffered_bytes == before
    message = receiver.add(fragments[1])
    assert message.text == "x" * 600
    assert (message.sender_id, message.recipient_id, message.message_id) == (1, 2, 3)
    assert receiver.buffered_bytes == receiver.pending_count == 0
    for fragment in fragments:
        assert receiver.add(fragment) is None


def test_interleaved_messages_use_full_identity():
    streams = [parts(sender_id=1), parts(sender_id=2), parts(recipient_id=3), parts(message_id=4)]
    receiver = Reassembler()
    messages = []
    for index in range(3):
        for stream in streams:
            if result := receiver.add(stream[index]):
                messages.append(result)
    assert {(msg.sender_id, msg.recipient_id, msg.message_id) for msg in messages} == {
        (1, 2, 3), (2, 2, 3), (1, 3, 3), (1, 2, 4),
    }


def test_conflicting_duplicate_invalidates_message():
    first = parts()[0]
    receiver = Reassembler()
    receiver.add(first)
    with pytest.raises(ReassemblyError, match="duplicate"):
        receiver.add(replace(first, data=DataIE(b"changed")))
    assert receiver.pending_count == receiver.buffered_bytes == 0
    assert receiver.add(first) is None
    assert receiver.pending_count == 0


@pytest.mark.parametrize("change", [{"total_packets": 4}, {"flags": Flags.START | Flags.COMPRESSED}])
def test_metadata_conflict_discards_state(change):
    first = parts()[0]
    receiver = Reassembler()
    receiver.add(first)
    with pytest.raises(ReassemblyError, match="metadata"):
        receiver.add(replace(first, control=replace(first.control, **change)))
    assert receiver.pending_count == receiver.buffered_bytes == 0


def test_expiry_and_duplicate_does_not_keep_state_alive():
    now = [0.0]
    receiver = Reassembler(clock=lambda: now[0])
    first = parts()[0]
    receiver.add(first)
    now[0] = 29.0
    receiver.add(first)
    now[0] = 30.0
    assert receiver.expire() == 1
    assert receiver.pending_count == receiver.buffered_bytes == 0


def test_new_fragment_extends_idle_timeout():
    now = [0.0]
    receiver = Reassembler(clock=lambda: now[0])
    fragments = parts()
    receiver.add(fragments[0])
    now[0] = 29.0
    receiver.add(fragments[1])
    now[0] = 30.0
    assert receiver.expire() == 0
    assert receiver.add(fragments[2]).text == "x" * 600


def test_completed_keys_expire_and_recent_cache_is_bounded():
    now = [0.0]
    receiver = Reassembler(clock=lambda: now[0], limits=ReassemblyLimits(max_recent_messages=2))
    first = parts("one", message_id=1)[0]
    assert receiver.add(first)
    assert receiver.add(first) is None
    now[0] = 30.0
    assert receiver.add(first)
    for identifier in (2, 3):
        assert receiver.add(parts("other", message_id=identifier)[0])
    assert receiver.recent_count == 2
    assert receiver.add(first)  # Oldest cache entry was evicted.


@pytest.mark.parametrize("limits", [
    ReassemblyLimits(max_fragments=2), ReassemblyLimits(max_wire_bytes=250),
    ReassemblyLimits(max_buffered_bytes=250),
])
def test_resource_rejections_release_state(limits):
    receiver = Reassembler(limits=limits)
    with pytest.raises(ResourceLimitError):
        receiver.add(parts()[0])
    assert receiver.pending_count == receiver.buffered_bytes == 0


def test_message_wire_limit_accumulates_across_fragments():
    receiver = Reassembler(limits=ReassemblyLimits(max_wire_bytes=300))
    fragments = parts()
    receiver.add(fragments[0])
    with pytest.raises(ResourceLimitError, match="max_wire_bytes"):
        receiver.add(fragments[1])
    assert receiver.buffered_bytes == 0


def test_pending_limit_preserves_other_messages():
    receiver = Reassembler(limits=ReassemblyLimits(max_pending_messages=1))
    first = parts()
    receiver.add(first[0])
    with pytest.raises(ResourceLimitError, match="max_pending_messages"):
        receiver.add(parts(message_id=4)[0])
    assert receiver.pending_count == 1
    assert receiver.buffered_bytes == 251
    receiver.add(first[1])
    assert receiver.add(first[2]).text == "x" * 600


def test_global_buffer_limit_preserves_other_messages():
    receiver = Reassembler(limits=ReassemblyLimits(max_buffered_bytes=300))
    receiver.add(parts()[0])
    with pytest.raises(ResourceLimitError, match="max_buffered_bytes"):
        receiver.add(parts(message_id=4)[0])
    assert receiver.pending_count == 1
    assert receiver.buffered_bytes == 251


@pytest.mark.parametrize("payload", [b"not zlib", zlib.compress(b"hello")[:-1],
                                     zlib.compress(b"hello") + b"trailing",
                                     zlib.compress(b"one") + zlib.compress(b"two")])
def test_malformed_compressed_streams(payload):
    receiver = Reassembler()
    with pytest.raises(ReassemblyError):
        receiver.add(payload_fragment(payload, compressed=True))
    assert receiver.pending_count == receiver.buffered_bytes == 0


@pytest.mark.parametrize("compressed", [False, True])
def test_invalid_utf8(compressed):
    payload = zlib.compress(b"\xff") if compressed else b"\xff"
    with pytest.raises(ReassemblyError, match="UTF-8"):
        Reassembler().add(payload_fragment(payload, compressed=compressed))


@pytest.mark.parametrize("compressed", [False, True])
def test_exact_decoded_limit(compressed):
    payload = zlib.compress(b"x" * 100) if compressed else b"x" * 100
    fragment = payload_fragment(payload, compressed=compressed)
    assert Reassembler(limits=ReassemblyLimits(max_decoded_bytes=100)).add(fragment).text == "x" * 100
    with pytest.raises(ResourceLimitError):
        Reassembler(limits=ReassemblyLimits(max_decoded_bytes=99)).add(fragment)


def test_decompression_bomb_is_bounded():
    fragment = payload_fragment(zlib.compress(b"x" * 100000), compressed=True)
    receiver = Reassembler(limits=ReassemblyLimits(max_decoded_bytes=1024))
    with pytest.raises(ResourceLimitError, match="decompressed"):
        receiver.add(fragment)
    assert receiver.pending_count == receiver.buffered_bytes == 0


def test_custom_oui_receiver():
    fragments = fragment_message("custom", sender_id=1, recipient_id=2, message_id=3, oui=b"abc")
    with pytest.raises(InvalidPacket, match="OUI"):
        Reassembler().add(fragments[0])
    assert Reassembler(oui=b"abc").add(fragments[0]).text == "custom"


@pytest.mark.parametrize("kwargs", [{"max_fragments": 65536}, {"max_pending_messages": 0},
                                    {"max_buffered_bytes": -1}, {"max_wire_bytes": True},
                                    {"timeout_seconds": 0}, {"timeout_seconds": float("inf")}])
def test_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        ReassemblyLimits(**kwargs)


def test_randomized_unicode_and_arrival_order():
    rng = random.Random(38)
    for message_id in range(30):
        text = "".join(rng.choice("ab é中🌍\n\x00") for _ in range(rng.randrange(1000)))
        fragments = fragment_message(text, sender_id=1, recipient_id=2, message_id=message_id,
                                     compress=bool(message_id % 2))
        arrivals = fragments + rng.choices(fragments, k=10)
        rng.shuffle(arrivals)
        receiver = Reassembler()
        completed = [result for part in arrivals if (result := receiver.add(part)) is not None]
        assert len(completed) == 1
        assert completed[0].text == text
