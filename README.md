# Beacon

Beacon is a Python protocol engine for peer-to-peer text carried in vendor-specific
IEEE 802.11 beacon Information Elements (IE 221). This initial phase implements
the binary protocol, fragmentation, bounded reassembly, offline Scapy frames, and
PCAP validation. It does not transmit, capture from an adapter, or provide a GUI.

## Install and run (PowerShell)

From this directory, with Python 3.11 or newer:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe examples\generate_pcaps.py
.\.venv\Scripts\python.exe examples\decode_pcap.py artifacts\pcaps\fragmented.pcap
```

On Linux (and macOS), from the project directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/python examples/generate_pcaps.py
.venv/bin/python examples/decode_pcap.py artifacts/pcaps/fragmented.pcap
```

Activation is optional. Scapy and pytest are installed inside this project's
virtual environment. Offline frame generation and PCAP reading need no wireless
hardware, administrator privileges, or live packet-capture driver. A Scapy warning
about missing libpcap/Npcap concerns live capture and does not prevent these tasks.

Validation in the development workspace: 159 tests passed on Windows with Python
3.14.2, Scapy 2.8.0, and pytest 9.1.1; all seven generated PCAP examples were reopened
and validated. Linux execution has not yet been verified in this workspace. The
included GitHub Actions workflow runs the tests on Ubuntu and Windows with Python
3.11 and 3.14 when this project is hosted as a repository; that workflow has not yet
run. The protocol package itself imports no Scapy or platform-specific modules.

`generate_pcaps.py` writes deterministic captures plus `manifest.json`, reopens
every capture, and checks recovered text and metadata. `decode_pcap.py` prints
JSON including messages, per-packet errors, ignored frames, and incomplete message
counts. It exits nonzero for errors or incomplete reassembly. PCAP output is under
`artifacts/pcaps/`; use `--output-dir` to choose another directory.

## Architecture

- `beacon.protocol`: Python-only models, codecs, validation, fragmentation, and
  reassembly. It never imports Scapy and does not access a network interface.
- `beacon.wireless`: offline Scapy frame construction, strict decoding of raw IE
  bytes, and PCAP file I/O. The future adapter backend belongs at this boundary.
- `beacon.client`: reserved for a future chat client; no interface is implemented.
- `examples`: executable offline demonstrations, separate from the library.

```python
from beacon.protocol import Reassembler, fragment_message
from beacon.wireless.frames import build_beacon, decode_beacon

fragments = fragment_message("Hello, 🌍", sender_id=1, recipient_id=2, message_id=1)
receiver = Reassembler()
for fragment in fragments:
    packet = decode_beacon(bytes(build_beacon(fragment)))
    message = receiver.add(packet)
    if message is not None:
        print(message.text)
```

See [PROTOCOL.md](PROTOCOL.md) for the normative v1 wire layout, approved design
decisions, receiver limits, and deferred control-message behavior. IDs are supplied
by the caller. The receiver returns addressed messages without applying local
recipient filtering; a future client/backend must apply that policy.

## Scope of future wireless work

Associated and disconnected operation, a single adapter where hardware supports
it, and optional dual adapters remain requirements. Monitor-mode reception,
injection, channel coordination, and managed/monitor concurrency depend on the
OS, driver, and hardware and have not been tested in this offline phase. The
transport remains beacon frames; there is no TCP/IP fallback. No encryption or
authentication is provided in v1.

References: [Scapy 802.11 API](https://scapy.readthedocs.io/en/stable/api/scapy.layers.dot11.html)
and [PCAP utilities](https://scapy.readthedocs.io/en/stable/api/scapy.utils.html).
