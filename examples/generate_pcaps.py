"""Generate reproducible offline examples and verify each file after writing it."""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from beacon.protocol import BROADCAST_ID, Flags, Message, fragment_message
from beacon.wireless.frames import build_beacon
from beacon.wireless.pcap import decode_pcap, write_pcap


def generate(output_dir: Path) -> dict:
    def case(text, message_id, *, sender_id=1, compress=True):
        fragments = fragment_message(text, sender_id=sender_id, recipient_id=BROADCAST_ID,
                                     message_id=message_id, compress=compress)
        frames = [build_beacon(part, source_mac=f"02:00:00:00:00:{sender_id:02x}", sequence=i % 4096)
                  for i, part in enumerate(fragments)]
        expected = Message(sender_id, BROADCAST_ID, message_id, text,
                           bool(fragments[0].control.flags & Flags.COMPRESSED), len(fragments))
        return frames, expected

    single, single_message = case("Hello, Beacon! 🌍", 1)
    empty, empty_message = case("", 2)
    fragmented, fragmented_message = case("Beacon over Wi-Fi — café 🌍\n" * 35, 3, compress=False)
    compressed, compressed_message = case("A repeated message benefits from compression.\n" * 200, 4)
    peer_a, message_a = case("Peer A: " + "A" * 600, 5, compress=False)
    peer_b, message_b = case("Peer B: " + "B" * 400, 5, sender_id=2, compress=False)
    interleaved = [peer_a[0], peer_b[0], *peer_a[1:], *peer_b[1:]]
    reordered = list(reversed(fragmented)) + [fragmented[0], fragmented[-1]]
    cases = {
        "single": (single, [single_message], 0),
        "empty": (empty, [empty_message], 0),
        "fragmented": (fragmented, [fragmented_message], 0),
        "compressed": (compressed, [compressed_message], 0),
        "interleaved": (interleaved, [message_a, message_b], 0),
        "reordered_duplicates": (reordered, [fragmented_message], 0),
        "malformed_then_valid": ([bytes(single[0])[:-1], single[0]], [single_message], 1),
    }
    manifest = {}
    for name, (frames, expected, error_count) in cases.items():
        path = write_pcap(output_dir / f"{name}.pcap", frames)
        report = decode_pcap(path)
        if (report.messages != expected or len(report.errors) != error_count
                or report.pending_count or report.expired_count or report.ignored_count):
            raise RuntimeError(f"PCAP validation failed for {path}: {report}")
        manifest[path.name] = {
            "packet_count": report.packet_count,
            "messages": [asdict(message) for message in expected],
            "expected_errors": [asdict(error) for error in report.errors],
        }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[1] / "artifacts" / "pcaps")
    args = parser.parse_args()
    manifest = generate(args.output_dir)
    for name, item in manifest.items():
        print(f"Validated {name}: {item['packet_count']} packets, {len(item['messages'])} messages, "
              f"{len(item['expected_errors'])} expected errors")


if __name__ == "__main__":
    main()
