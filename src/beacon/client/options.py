"""Command-line options shared by GUI startup and terminal chat."""

import argparse

from beacon.protocol import BROADCAST_ID
from .session import new_sender_id, parse_id


def parser_for(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--iface", help="Existing monitor interface used for reception and, by default, transmission")
    parser.add_argument("--tx-iface", help="Optional separate monitor interface for transmission")
    parser.add_argument("--channel", type=int, help="Require this channel; defaults to the adapter's current channel")
    parser.add_argument("--id", type=parse_id, default=None, help="Your unique peer ID (decimal or 0x-prefixed hex)")
    parser.add_argument("--to", type=parse_id, default=BROADCAST_ID, help="Recipient ID or all (default: all)")
    parser.add_argument("--no-compress", action="store_true", help="Disable optional zlib compression")
    return parser


def local_id(args, parser) -> int:
    value = new_sender_id() if args.id is None else args.id
    if value == BROADCAST_ID:
        parser.error("--id must identify one peer; it cannot be all/0xFFFFFFFF")
    return value
