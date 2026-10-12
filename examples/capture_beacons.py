"""Passively capture Wi-Fi beacon frames with Scapy on a monitor-mode interface."""

import argparse
import math
from pathlib import Path

from scapy.all import Dot11Beacon, sniff, wrpcap
from scapy.error import Scapy_Exception


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", required=True, help="Existing monitor-mode interface, e.g. wlan0mon")
    parser.add_argument("--timeout", type=float, default=15, help="Maximum capture duration in seconds (default: 15)")
    parser.add_argument("--count", type=int, default=100, help="Maximum number of beacon frames (default: 100)")
    parser.add_argument("--output", type=Path, default=Path("monitor-test.pcap"), help="Output PCAP path (default: monitor-test.pcap)")
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be positive and finite")
    if args.count <= 0:
        parser.error("--count must be positive")

    print(f"Listening on {args.iface} for up to {args.timeout:g} seconds or {args.count} beacon frames...", flush=True)
    try:
        packets = sniff(
            iface=args.iface,
            timeout=args.timeout,
            count=args.count,
            lfilter=lambda packet: packet.haslayer(Dot11Beacon),
            prn=lambda packet: packet.summary(),
        )
    except (OSError, ValueError, Scapy_Exception) as exc:
        parser.exit(2, f"Capture failed: {exc}\n")

    print(f"Captured {len(packets)} Wi-Fi beacon frames")
    if not packets:
        print("No PCAP written. Check the interface, monitor mode, and channel.")
        return 1
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(args.output), packets)
    except (OSError, Scapy_Exception) as exc:
        parser.exit(2, f"Cannot write capture: {exc}\n")
    print(f"Saved {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
