"""Tk desktop chat client using the same controller as terminal chat."""

import sys
import time

from .controller import ChatController
from .options import local_id, parser_for
from .session import display_text, format_id, parse_id
from beacon.wireless.base import RadioConfig


class ChatWindow:
    def __init__(self, root, args, *, controller_factory=ChatController):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText

        self.root = root
        self._factory = controller_factory
        self.controller = None
        self._closing = False
        self._close_started = 0.0
        self.tk = tk
        root.title("Beacon · Wi-Fi chat")
        root.geometry("1020x720")
        root.minsize(820, 580)
        root.configure(bg="#0b1220")
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#0b1220")
        style.configure("Panel.TFrame", background="#142033")
        style.configure("TLabel", background="#0b1220", foreground="#e2e8f0", font=("TkDefaultFont", 10))
        style.configure("Panel.TLabel", background="#142033", foreground="#e2e8f0")
        style.configure("Muted.TLabel", foreground="#94a3b8")
        style.configure("Title.TLabel", font=("TkDefaultFont", 24, "bold"))
        style.configure("TButton", padding=(12, 8))
        style.configure("Accent.TButton", background="#0f766e", foreground="white")
        style.map("Accent.TButton", background=[("active", "#115e59"), ("disabled", "#334155")])
        style.configure("TEntry", fieldbackground="#f8fafc", foreground="#0f172a", padding=6)
        style.configure("TCheckbutton", background="#142033", foreground="#e2e8f0")

        self.rx = tk.StringVar(root, args.iface or "")
        self.tx = tk.StringVar(root, args.tx_iface or "")
        self.channel = tk.StringVar(root, "" if args.channel is None else str(args.channel))
        self.identity = tk.StringVar(root, format_id(args.id))
        self.recipient = tk.StringVar(root, format_id(args.to))
        self.compress = tk.BooleanVar(root, not args.no_compress)
        self.status = tk.StringVar(root, "Disconnected")

        header = ttk.Frame(root, padding=(22, 18))
        header.pack(fill="x")
        ttk.Label(header, text="Beacon", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Wi-Fi chat", style="Muted.TLabel").pack(side="left", padx=14)
        self.status_label = ttk.Label(header, textvariable=self.status, style="Muted.TLabel")
        self.status_label.pack(side="right")

        content = ttk.Frame(root, padding=(20, 0, 20, 18))
        content.pack(fill="both", expand=True)
        sidebar = ttk.Frame(content, style="Panel.TFrame", padding=16, width=240)
        sidebar.pack(side="left", fill="y", padx=(0, 16))
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="CONNECTION", style="Panel.TLabel", font=("TkDefaultFont", 11, "bold")).pack(anchor="w", pady=(0, 16))
        self.settings = []
        for title, variable in (("Your peer ID", self.identity), ("Receive interface", self.rx),
                                ("Transmit interface (blank = same)", self.tx), ("Channel (blank = current)", self.channel)):
            ttk.Label(sidebar, text=title, style="Panel.TLabel").pack(anchor="w", pady=(8, 4))
            entry = ttk.Entry(sidebar, textvariable=variable)
            entry.pack(fill="x")
            self.settings.append(entry)
        compression = ttk.Checkbutton(sidebar, text="Compress when smaller", variable=self.compress)
        compression.pack(anchor="w", pady=(18, 12))
        self.settings.append(compression)
        self.connect_button = ttk.Button(sidebar, text="Connect", style="Accent.TButton", command=self.toggle_connection)
        self.connect_button.pack(fill="x", pady=(6, 16))
        ttk.Label(sidebar, text="Use existing monitor interfaces.\nBoth peers need the same channel\nand different peer IDs.",
                  style="Panel.TLabel", wraplength=205, justify="left").pack(anchor="w", pady=(0, 14))
        ttk.Label(sidebar, text="Messages are unencrypted.\nDelivery is unconfirmed.", style="Panel.TLabel",
                  wraplength=205, justify="left").pack(anchor="w")

        chat = ttk.Frame(content)
        chat.pack(side="left", fill="both", expand=True)
        self.transcript = ScrolledText(chat, wrap="word", state="disabled", bg="#101b2c", fg="#e2e8f0",
                                       insertbackground="white", relief="flat", padx=16, pady=16,
                                       font=("TkDefaultFont", 11))
        self.transcript.pack(fill="both", expand=True)
        for name, color in (("received", "#67e8f9"), ("sent", "#5eead4"), ("error", "#fda4af"), ("status", "#94a3b8")):
            self.transcript.tag_configure(name, foreground=color)

        recipient_row = ttk.Frame(chat, padding=(0, 12, 0, 6))
        recipient_row.pack(fill="x")
        ttk.Label(recipient_row, text="To").pack(side="left", padx=(0, 8))
        ttk.Entry(recipient_row, textvariable=self.recipient, width=20).pack(side="left")
        ttk.Label(recipient_row, text="all or a peer ID", style="Muted.TLabel").pack(side="left", padx=10)
        self.compose = tk.Text(chat, height=4, wrap="word", bg="#f8fafc", fg="#0f172a",
                               insertbackground="#0f172a", relief="flat", padx=10, pady=10,
                               font=("TkDefaultFont", 11))
        self.compose.pack(fill="x")
        self.compose.bind("<Return>", self._enter)
        footer = ttk.Frame(chat, padding=(0, 8, 0, 0))
        footer.pack(fill="x")
        ttk.Label(footer, text="Enter to send · Shift+Enter for a new line", style="Muted.TLabel").pack(side="left")
        self.send_button = ttk.Button(footer, text="Send", command=self.send, style="Accent.TButton", state="disabled")
        self.send_button.pack(side="right")
        self._append("Ready", "Enter your monitor interface and connect to start chatting.", "status")
        root.protocol("WM_DELETE_WINDOW", self.close)
        self._poll_id = root.after(50, self._poll)

    def _append(self, title, text, tag):
        self.transcript.configure(state="normal")
        self.transcript.insert("end", f"{time.strftime('%H:%M:%S')}  {title}\n", tag)
        self.transcript.insert("end", display_text(text) + "\n\n")
        # Keep long-running sessions bounded without saving conversation logs.
        if int(self.transcript.index("end-1c").split(".")[0]) > 1500:
            self.transcript.delete("1.0", "301.0")
        if len(self.transcript.get("1.0", "end-1c")) > 200000:
            self.transcript.delete("1.0", "end-100000c")
        self.transcript.configure(state="disabled")
        self.transcript.see("end")

    def _set_busy(self, busy):
        for widget in self.settings:
            widget.configure(state="disabled" if busy else "normal")
        self.send_button.configure(state="normal" if self.controller and self.controller.is_connected else "disabled")

    def toggle_connection(self):
        if self.controller and self.controller.is_running:
            self.controller.disconnect()
            self.status.set("Disconnecting…")
            self.send_button.configure(state="disabled")
            return
        try:
            identity = parse_id(self.identity.get())
            channel = int(self.channel.get()) if self.channel.get().strip() else None
            config = RadioConfig(self.rx.get().strip(), self.tx.get().strip() or None, channel)
            self.controller = self._factory(identity, compress=self.compress.get())
            self.controller.connect(config)
        except ValueError as exc:
            self._append("Check connection settings", str(exc), "error")
            return
        self._set_busy(True)
        self.connect_button.configure(text="Disconnect")
        self.status.set("Connecting…")

    def _enter(self, event):
        if event.state & 0x0001:  # Shift+Enter keeps the normal Text newline behavior.
            return None
        self.send()
        return "break"

    def send(self):
        if not self.controller or not self.controller.is_connected:
            self._append("Not connected", "Connect before sending a message.", "error")
            return
        text = self.compose.get("1.0", "end-1c")
        try:
            self.controller.send_message(text, parse_id(self.recipient.get()))
        except ValueError as exc:
            self._append("Message not queued", str(exc), "error")
            return
        self.compose.delete("1.0", "end")
        self.compose.focus_set()

    def _poll(self):
        if self.controller:
            for event in self.controller.poll():
                if event.kind == "received":
                    message = event.message
                    self._append(f"{format_id(message.sender_id)} → {format_id(message.recipient_id)}", message.text, "received")
                elif event.kind == "sent":
                    self._append(f"You → {format_id(event.message.recipient_id)} · unconfirmed", event.message.text, "sent")
                else:
                    self._append(event.kind.capitalize(), event.text, "error" if event.kind == "error" else "status")
                    if event.message:
                        self._append("Unsent message", event.message.text, "error")
                if event.kind == "connected":
                    self.status.set("Connected")
                    self._set_busy(True)
                    self.compose.focus_set()
                elif event.kind == "disconnected":
                    self.status.set("Disconnected")
                    self.connect_button.configure(text="Connect")
                    self._set_busy(False)
        if self._closing and (not self.controller or not self.controller.is_running):
            self.root.destroy()
            return
        if self._closing and time.monotonic() - self._close_started > 12:
            self.root.destroy()
            return
        self._poll_id = self.root.after(50, self._poll)

    def close(self):
        self._closing = True
        self._close_started = time.monotonic()
        if self.controller:
            self.controller.disconnect()
        self.status.set("Disconnecting…")
        self.send_button.configure(state="disabled")
        self.connect_button.configure(state="disabled")


def main(argv=None) -> int:
    parser = parser_for(__doc__)
    args = parser.parse_args(argv)
    args.id = local_id(args, parser)
    try:
        import tkinter as tk
    except ImportError:
        parser.exit(2, "Tkinter is missing. On Kali: sudo apt install python3-tk\n")
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        parser.exit(2, f"Cannot open the desktop: {exc}\nUse a graphical session with DISPLAY/XAUTHORITY available.\n")
    ChatWindow(root, args)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
