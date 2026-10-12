# Beacon protocol v1

This document records the approved initial protocol decisions. All offsets below
are relative to the IE body. Multibyte Beacon integers use **big-endian** byte
order; surrounding IEEE 802.11 fields retain their standard encoding.

## Vendor-specific envelope

Both elements use `ID = 221 (0xDD)` followed by a one-byte body length and exactly
that many body bytes. The length excludes the ID and length bytes. The maximum
body length is 255 bytes.

The default OUI-field value is `02:00:00`, an arbitrary configurable marker for
local experiments. This project does not own this OUI, claim an IEEE registration,
or claim this value is an officially reserved experimental OUI. Sender and
receiver must agree on the configured three-byte value; unrelated OUIs are ignored.

## Control IE (internal type 0x01)

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 3 | OUI |
| 3 | 1 | Internal IE type: `0x01` |
| 4 | 1 | Protocol version: `0x01` |
| 5 | 4 | Sender ID |
| 9 | 4 | Recipient ID |
| 13 | 4 | Message ID |
| 17 | 2 | Packet Number |
| 19 | 2 | Total Packets |
| 21 | 1 | Message Type |
| 22 | 1 | Flags |

The body is exactly 23 bytes (`length = 0x17`); the complete IE is 25 bytes.
IDs are unsigned 32-bit values supplied by the caller. Recipient ID `0xFFFFFFFF`
means logical broadcast; all other recipient values address that logical peer.
No sender-ID allocation, persistence, authentication, or MAC-to-ID mapping is
defined. Beacon receiver MAC addresses remain broadcast for unicast logical IDs.

| Message Type | Value |
| --- | --- |
| DATA | `0x01` |
| ACK | `0x02` |
| NACK | `0x03` |
| HELLO | `0x04` |
| CLOSE | `0x05` |

| Flag | Value | DATA meaning |
| --- | --- | --- |
| START | `0x01` | Present exactly on packet 1 |
| END | `0x02` | Present exactly on packet N |
| COMPRESSED | `0x04` | Entire message was zlib-compressed before fragmentation |

Unknown versions, message types, and flag bits are rejected. Packet numbering is
one-based: `1 <= Packet Number <= Total Packets <= 65535`. Both START and END are
set for a single-packet DATA message. ACK, NACK, HELLO, and CLOSE support Control IE
serialization, decoding, and structural validation only. Their flag meanings,
payload formats, ACK correlation, retransmission rules, and session state
transitions are deferred. No reliability behavior is implied by recognizing them.

Example: sender 1, recipient 2, message 3, one uncompressed DATA packet:

```text
dd 17 02 00 00 01 01 00 00 00 01 00 00 00 02 00 00 00 03 00 01 00 01 01 03
```

## Data IE (internal type 0x02)

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 3 | OUI |
| 3 | 1 | Internal IE type: `0x02` |
| 4 | 0–251 | Payload bytes |

The body is 4–255 bytes; the complete IE is 6–257 bytes. An empty payload still
has the OUI/type prefix. A Data IE carries arbitrary bytes, not independently
decodable UTF-8. Example for `Hi`:

```text
dd 06 02 00 00 02 48 69
```

## DATA framing and fragmentation

One beacon frame carries one DATA fragment: exactly one matching Control IE and
one matching Data IE, in that order when emitted. The receiver also accepts their
reverse order because the types identify them unambiguously. Standard beacon IEs
and vendor IEs with other OUIs may coexist. Multiple matching Control or Data IEs,
missing required IEs, and unknown internal types under the configured OUI are
rejected. Aggregating multiple Beacon fragments within one beacon is not v1.

1. Encode the complete string with strict UTF-8.
2. If compression is enabled, try a standard zlib stream. Use it only if its byte
   length is strictly less than the UTF-8 byte length. Raw DEFLATE/gzip are not used.
3. Split the resulting bytes into chunks of at most 251 bytes. The sender fills
   every nonfinal chunk. Receivers need not require full-sized chunks.
4. Emit packets numbered 1 through N, applying START/END by position. COMPRESSED,
   IDs, version, Total Packets, and Message Type are consistent across the message.

An empty string emits one uncompressed fragment with empty payload and START|END.
Packet count cannot exceed 65535. Fragmentation operates on bytes, so it may split
a UTF-8 character or zlib sequence; text decoding occurs only after reassembly.
The IEEE 802.11 sequence number is independent of Beacon's packet/message IDs.

## Reassembly and duplicate handling

Reassembly state is keyed by `(sender_id, recipient_id, message_id)` within a
receiver configured for one OUI/version. Out-of-order arrival is supported, even
when START arrives last. An identical duplicate has no effect and does not extend
the pending message's idle deadline. Conflicting duplicate payloads or inconsistent
metadata invalidate the entire pending message. Its key is temporarily suppressed.

Once all numbered fragments arrive, concatenate them in order, decompress if
flagged, and decode strict UTF-8. Zlib must reach end-of-stream with no trailing
bytes or second stream. Malformed/truncated zlib, invalid UTF-8, and excess decoded
size are errors. The result contains text, IDs, compression status, and packet count.
Completed keys are temporarily suppressed to avoid duplicate delivery.

Callers must avoid reusing a message key during the receiver's pending/recent
window. This is bounded duplicate suppression, not an exactly-once delivery or
replay-protection guarantee. There is no cryptographic integrity or authentication;
ordinary UTF-8 payload corruption can remain undetected. No checksum, encryption,
or authentication fields are added to the specified wire format.

## Local receiver limits

Limits are configurable implementation policy, not wire-format restrictions:

| Policy | Default |
| --- | --- |
| Encoded bytes per message | 1 MiB |
| Decoded UTF-8 bytes per message | 1 MiB |
| Fragments per pending message | 8192 |
| Pending messages | 128 |
| Buffered payload bytes across pending messages | 8 MiB |
| Recent completed/rejected keys | 1024 |
| Pending idle timeout / recent-key lifetime | 30 seconds |

Expired pending state is discarded. Recent entries expire or are removed oldest
first when their cap is reached. Limits bound pending fragment count as well as
payload bytes; Python object overhead is not included in the byte counters. On
capacity failure the affected message is rejected; unrelated pending messages are
preserved. The reassembler uses a monotonic clock, checked on `add()`/`expire()`;
it creates no timer threads. A decoded message is removed from buffered accounting
before being returned. Application-owned returned messages are outside these limits.

## Validation and PCAP behavior

Codecs validate exact envelope/body lengths, integer ranges, OUI and internal type,
version, known types/flags, and numbering. DATA validation additionally checks flag
positions and the Control/Data OUI match. Strict raw IE parsing prevents Scapy's
tolerant packet dissection from hiding a truncated element.

Unrelated frames/OUIs return no Beacon fragment. Structurally malformed beacon
frames produce typed errors, including malformed IE boundaries where the owner
cannot be determined. The offline DATA decoder recognizes but reports unsupported
non-DATA control traffic; it never interprets it as chat text. A malformed packet
does not abort scanning subsequent complete PCAP records. Corrupt PCAP container
headers/records cannot always be recovered; these produce a file error.

The frame decoder accepts raw IEEE 802.11 or radiotap+802.11 beacon bytes.
PCAP support accepts link types 105 (IEEE 802.11) and 127 (radiotap), classic PCAP
and PCAPNG through Scapy. Radiotap FCS presence is respected when flagged, but FCS
verification is not implemented. Raw 802.11 input assumes no trailing FCS.
Generated captures use radiotap without an FCS and include SSID, supported rates,
and channel IEs followed by the Beacon IEs. Offline examples use synthetic
source/BSSID addresses. Live transmission uses the transmit interface's MAC.
5 GHz frames use OFDM supported rates and omit the 2.4 GHz DS channel IE; the
adapter's tuned channel determines the actual transmit frequency.

## Chat client policy

The terminal and desktop clients share one session/controller implementation and
use the same DATA wire format described above. They introduce no payload wrappers,
names, timestamps, encryption, or new control-message semantics.

The client generates a random local ID in `1..0xFFFFFFFE` unless the user supplies
one. Explicit local ID 0 is accepted; broadcast cannot identify a local peer.
IDs are not persisted or checked for collisions. Each connection starts at a
random 32-bit Message ID and increments it for each prepared message, wrapping at
32 bits. Users must choose distinct peer IDs. This is application policy, not a
wire-level allocation or authentication scheme.

The session accepts messages addressed to its local ID or broadcast and ignores
its own sender ID to suppress captured local transmissions. Chat input must be
nonempty and at most 64 KiB of UTF-8 text. The session applies 64 KiB encoded and
decoded reassembly limits; other receiver limits remain as above. The general
protocol library still supports empty messages and configurable limits.

The controller processes frames in a background worker and bounds queued sends
(16), captured frames (512, at most 8192 bytes each), and UI events (128). Excess
capture frames and the oldest UI events can be dropped under load. Malformed and
unsupported frames are discarded without stopping reception. Outgoing fragments
are paced at a default 20 ms interval. Disconnect cancels outstanding sends.

Scapy handles live layer-2 reception/injection on existing Linux monitor
interfaces. One interface is the default; separate RX/TX interfaces must share a
frequency. Channel checks are startup checks, not continuous channel coordination.
No association or IP address is required. Maintaining managed association on the
same physical adapter depends on driver support for simultaneous managed/monitor
interfaces and a shared channel. These clients do not configure that hardware
state. A displayed send is unconfirmed adapter submission, not proof of receipt.

## Deferred work

ACK/NACK correlation, retransmission, HELLO/CLOSE behavior, peer discovery,
persistent identity, automatic channel coordination/interface configuration, and
6 GHz support remain deferred. TCP/IP is not a fallback transport. Automated
protocol, UI, and simulated-adapter tests do not prove over-the-air injection,
reception, or managed/monitor concurrency on any particular hardware.
