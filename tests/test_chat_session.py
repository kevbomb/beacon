import pytest

from beacon.client.session import ChatSession, MAX_CHAT_BYTES, display_text, format_id, parse_id
from beacon.protocol import BROADCAST_ID


@pytest.mark.parametrize("recipient", [2, BROADCAST_ID])
def test_chat_between_two_peers_with_reordered_fragments(recipient):
    sender, receiver = ChatSession(1, compress=False), ChatSession(2)
    text = "A chat message: café 🌍\n" * 50
    outgoing = sender.prepare(text, recipient)
    received = [message for part in reversed(outgoing.fragments) if (message := receiver.receive(part))]
    assert len(received) == 1
    assert received[0].text == text
    assert received[0].sender_id == 1
    assert all(receiver.receive(part) is None for part in outgoing.fragments)


def test_address_filter_and_loopback():
    sender, receiver, other = ChatSession(1), ChatSession(2), ChatSession(3)
    part = sender.prepare("private recipient", 2).fragments[0]
    assert receiver.receive(part).text == "private recipient"
    assert other.receive(part) is None
    assert sender.receive(part) is None
    assert other.receiver.pending_count == sender.receiver.pending_count == 0


def test_each_send_gets_a_new_message_id():
    session = ChatSession(1)
    first, second = session.prepare("same text"), session.prepare("same text")
    assert first.message.message_id != second.message.message_id
    receiver = ChatSession(2)
    assert receiver.receive(first.fragments[0])
    assert receiver.receive(second.fragments[0])


@pytest.mark.parametrize("text,recipient", [("", 2), (" \n", 2), ("hi", 1), ("hi", -1),
                                           ("x" * (MAX_CHAT_BYTES + 1), 2), ("\ud800", 2)],
                         ids=["empty", "whitespace", "self", "negative", "oversized", "surrogate"])
def test_invalid_chat_input(text, recipient):
    with pytest.raises(ValueError):
        ChatSession(1).prepare(text, recipient)


@pytest.mark.parametrize("value,expected", [("all", BROADCAST_ID), ("0xABCD", 43981), ("0002", 2), ("0", 0)])
def test_peer_ids(value, expected):
    assert parse_id(value) == expected
    assert parse_id(format_id(expected)) == expected


@pytest.mark.parametrize("value", ["", "peer", "-1", "4294967296"])
def test_invalid_peer_ids(value):
    with pytest.raises(ValueError):
        parse_id(value)


def test_received_terminal_controls_are_visible_text():
    assert display_text("hello\x1b[2J\rworld\n🌍") == "hello\\x1b[2J\\x0dworld\n🌍"
