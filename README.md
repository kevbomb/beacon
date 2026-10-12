# Beacon

Beacon provides **terminal and graphical desktop chat clients** for text carried
in vendor-specific IEEE 802.11 beacon Information Elements (IE 221). Both clients
use the same Python protocol engine and Scapy wireless backend. They can chat
with each other. The transport uses beacon frames, with no TCP/IP fallback.

Live chat currently runs on Linux, including Kali, with an existing monitor-mode
interface and a driver/adapter that supports injection. Offline protocol and PCAP
tools also run on Windows and macOS. Scapy is installed with the project; the GUI
uses Tkinter.

## Install on Kali

From a terminal in your graphical desktop session:

```bash
sudo apt update
sudo apt install python3-venv python3-tk iw
git clone https://github.com/kevbomb/beacon.git
cd beacon
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

If you already have the repository, update it from inside its directory:

```bash
git pull --ff-only
.venv/bin/python -m pip install -e .
```

The explicit virtual-environment Python path ensures `sudo` uses the installed
Scapy dependency. Installation itself does not require `sudo`.

## Chat using your monitor-mode adapter

Run `iw dev` to find your monitor interface and its current channel. Replace
`wlan0mon` below with that interface. Both peers must use the same channel and
different peer IDs. Start one client on each of two computers within radio range.

Terminal client on the first computer:

```bash
sudo .venv/bin/python -m beacon cli --iface wlan0mon --id 1 --to 2
```

Graphical client on the second computer:

```bash
sudo --preserve-env=DISPLAY,XAUTHORITY .venv/bin/python -m beacon gui --iface wlan0mon --id 2 --to 1
```

In the GUI, review the connection fields and click **Connect**, then type a
message. Enter sends; Shift+Enter adds a newline. The terminal sends each entered
line and supports `/to ID`, `/to all`, `/id`, `/help`, and `/quit`. Disconnecting,
quitting, or closing standard input cancels outstanding sends and reports unsent
messages. Either computer can use either client. You can launch the GUI without
arguments and fill in its connection fields.

The GUI needs a graphical session with Tkinter and display access. If it reports
`Cannot open the desktop`, run it from a terminal in that session; the terminal
client works without a desktop. Installed commands `beacon-cli` and `beacon-gui`
provide the same clients. Use `python -m beacon cli --help` or
`python -m beacon gui --help` for options.

Recipient `all` broadcasts to other Beacon peers. IDs accept decimal or
`0x`-prefixed hexadecimal. Omitting `--id` generates a fresh random ID, shown in
the client; explicit IDs are useful for repeatable tests. There is no automatic
peer discovery or persistent identity. Logical recipient filtering is **not
privacy**: v1 messages are unencrypted and unauthenticated.

Messages are UTF-8, limited to 64 KiB of text per chat message. Compression is
used only when it makes the message smaller; `--no-compress` disables it. Long
messages are fragmented and reassembled automatically. “Unconfirmed” means the
frames were submitted to the local adapter; it does not prove the other peer
received them. Missing fragments expire. ACKs and retransmission are not yet
implemented, so packet loss can lose a message.

### Channels, association, and adapters

Beacon reads the existing interface state with `iw`; it does not switch monitor
mode, tune channels, disconnect a network, or stop NetworkManager. Supported
bands are 2.4 GHz and 5 GHz. `--channel 6` checks that the adapter is already on
channel 6; it does not change the channel. Keep both peers on that channel for
the session. If you need to tune a dedicated, disconnected monitor adapter:

```bash
sudo iw dev wlan0mon set channel 6
```

- One monitor interface handles both reception and transmission by default,
  where its adapter/driver supports both operations.
- Internet association is not required. To stay associated on the same physical
  adapter, the hardware/driver must support concurrent managed and monitor
  interfaces. Pass the monitor interface to Beacon and use the managed network's
  channel. Channel changes by the network can interrupt chat.
- A separate adapter can keep your normal Wi-Fi connection while the Alfa handles
  Beacon. Optionally, `--iface wlan0mon --tx-iface wlan1mon` uses separate monitor
  interfaces for reception and transmission; both must be on the same frequency.

Automated tests simulate adapters and exchange actual serialized Scapy frames.
They do not establish that your Alfa model/driver can inject or receive these
frames. Confirm a hardware test by seeing the message arrive on the other peer.

## Tests and offline PCAP examples

No wireless adapter or elevated privileges are needed for offline work:

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/python examples/generate_pcaps.py
.venv/bin/python examples/decode_pcap.py artifacts/pcaps/fragmented.pcap
```

On Windows, with Python 3.11 or newer:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe examples\generate_pcaps.py
.\.venv\Scripts\python.exe examples\decode_pcap.py artifacts\pcaps\fragmented.pcap
```

Activation is optional. Offline Scapy warnings about missing Npcap/libpcap do not
prevent frame generation or PCAP reading. GUI widget tests skip when no display
or Tkinter is available; on headless Linux, install `xvfb` and use
`xvfb-run -a .venv/bin/python -m pytest` to include them. GitHub Actions runs the
suite on Ubuntu and Windows with Python 3.11 and 3.14, using Xvfb on Ubuntu.

`generate_pcaps.py` writes seven deterministic captures and `manifest.json`, then
reopens every capture to validate recovered text and metadata. `decode_pcap.py`
prints JSON with messages, per-packet errors, ignored frames, and incomplete
message counts; errors or incomplete reassembly cause a nonzero exit. Use
`--output-dir` with the generator to change the output directory.

### Passive Scapy capture

To check reception independently of either client:

```bash
sudo .venv/bin/python examples/capture_beacons.py --iface wlan0mon
.venv/bin/python examples/decode_pcap.py monitor-test.pcap
```

The capture example uses Scapy `sniff()` and `wrpcap()`, stopping after 15 seconds
or 100 beacon frames by default. `--timeout`, `--count`, and `--output` customize
it. Ordinary access-point beacons increase `ignored_count`; chat frames from a
running Beacon peer can produce decoded messages. Partial captures of fragmented
messages may report incomplete reassembly. Captures overwrite the selected output
file. Exit codes are 1 for no beacons (no file written) and 2 for argument or I/O
errors. Git ignores the default `monitor-test.pcap`.

## Architecture

- `beacon.protocol`: Python-only codecs, validation, fragmentation, and bounded
  reassembly. It imports no Scapy or platform-specific modules.
- `beacon.wireless`: Scapy frame construction, raw-byte decoding, PCAP I/O, and
  the Linux monitor-mode backend. `base.py` defines the transport boundary.
- `beacon.client.session`: local addressing and message preparation.
- `beacon.client.controller`: a shared background radio worker and bounded event
  queues; neither UI performs blocking radio operations.
- `beacon.client.cli` / `beacon.client.gui`: terminal and Tk desktop interfaces.
- `examples`: offline demonstrations and a passive capture diagnostic.

```python
from beacon.protocol import Reassembler, fragment_message
from beacon.wireless.frames import build_beacon, decode_beacon

fragments = fragment_message("Hello, 🌍", sender_id=1, recipient_id=2, message_id=1)
receiver = Reassembler()
for fragment in fragments:
    message = receiver.add(decode_beacon(bytes(build_beacon(fragment))))
    if message is not None:
        print(message.text)
```

See [PROTOCOL.md](PROTOCOL.md) for the unchanged v1 wire format, experimental
OUI marker, receiver limits, and deferred control-message semantics. The library
returns all addressed messages; the chat session filters for its own ID and
broadcast recipients and suppresses local echoes.

References: [Scapy 802.11 API](https://scapy.readthedocs.io/en/stable/api/scapy.layers.dot11.html),
[Scapy send/receive API](https://scapy.readthedocs.io/en/stable/api/scapy.sendrecv.html),
and [Linux iw documentation](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html).
