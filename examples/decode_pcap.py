"""Decode Beacon DATA messages from an offline PCAP/PCAPNG file."""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from beacon.wireless.pcap import PcapFileError, decode_pcap


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        report = decode_pcap(args.path)
    except (OSError, PcapFileError) as exc:
        parser.exit(2, f"Cannot read capture: {exc}\n")
    print(json.dumps(asdict(report), ensure_ascii=True, indent=2))
    return int(bool(report.errors or report.pending_count or report.expired_count))


if __name__ == "__main__":
    raise SystemExit(main())
