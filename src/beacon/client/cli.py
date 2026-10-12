"""Terminal chat over Beacon vendor-specific Wi-Fi beacon elements."""

import queue
import sys
import threading
import time

from beacon.wireless.base import RadioConfig
from .controller import ChatController
from .options import local_id, parser_for
from .session import display_text, format_id, parse_id

HELP = "Commands: /to ID|all, /id, /help, /quit. Other lines send a message."


def main(argv=None) -> int:
    parser = parser_for(__doc__)
    args = parser.parse_args(argv)
    if not args.iface:
        parser.error("--iface is required for terminal chat")
    sender_id = local_id(args, parser)
    try:
        config = RadioConfig(args.iface, args.tx_iface, args.channel)
    except ValueError as exc:
        parser.error(str(exc))
    controller = ChatController(sender_id, compress=not args.no_compress)
    recipient = args.to
    lines = queue.Queue(maxsize=16)
    stop_input = threading.Event()

    def read_input():
        for line in sys.stdin:
            while not stop_input.is_set():
                try:
                    lines.put(line.rstrip("\r\n"), timeout=0.1)
                    break
                except queue.Full:
                    pass
            if stop_input.is_set():
                return
        while not stop_input.is_set():
            try:
                lines.put(None, timeout=0.1)
                return
            except queue.Full:
                pass

    print(f"Beacon · local ID {format_id(sender_id)} · recipient {format_id(recipient)}")
    print("Delivery is unconfirmed. Both peers must be on the same channel.")
    print(HELP)
    controller.connect(config)
    input_started = False
    failed = False
    quitting = False
    try:
        while True:
            # Snapshot before draining so final errors cannot be lost at shutdown.
            running = controller.is_running
            for event in controller.poll():
                if event.kind == "received":
                    message = event.message
                    print(f"\n[{format_id(message.sender_id)} -> {format_id(message.recipient_id)}] {display_text(message.text)}", flush=True)
                elif event.kind == "sent":
                    print(f"\n[you -> {format_id(event.message.recipient_id)}; unconfirmed] {display_text(event.message.text)}", flush=True)
                else:
                    print(f"\n{event.kind.upper()}: {display_text(event.text)}", flush=True)
                    if event.message is not None:
                        print(f"Unsent: {display_text(event.message.text)}", flush=True)
                if event.kind == "error":
                    failed = True
                if event.kind == "connected" and not input_started:
                    threading.Thread(target=read_input, daemon=True, name="beacon-input").start()
                    input_started = True
                    if sys.stdin.isatty():
                        print("> ", end="", flush=True)
            if not running:
                break
            if quitting:
                time.sleep(0.02)
                continue
            try:
                line = lines.get(timeout=0.05)
            except queue.Empty:
                continue
            try:
                if line is None or line.strip() == "/quit":
                    quitting = True
                    controller.disconnect()
                elif line.strip() == "/help":
                    print(HELP)
                elif line.strip() == "/id":
                    print(f"Your ID: {format_id(sender_id)}")
                elif line.startswith("/to "):
                    recipient = parse_id(line[4:])
                    print(f"Recipient: {format_id(recipient)}")
                elif line.startswith("/"):
                    print(HELP)
                elif line.strip():
                    controller.send_message(line, recipient)
                if sys.stdin.isatty() and not quitting:
                    print("> ", end="", flush=True)
            except ValueError as exc:
                print(f"ERROR: {exc}", flush=True)
    except KeyboardInterrupt:
        print("\nDisconnecting...")
    finally:
        stop_input.set()
        controller.disconnect(wait=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
