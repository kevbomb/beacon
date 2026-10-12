"""Transport boundary shared by the clients and wireless implementation."""

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from beacon.protocol import Fragment


@dataclass(frozen=True, slots=True)
class RadioConfig:
    rx_iface: str
    tx_iface: str | None = None
    channel: int | None = None
    interval: float = 0.02

    def __post_init__(self):
        for value in (self.rx_iface, self.tx_iface or self.rx_iface):
            if not isinstance(value, str) or not value.strip() or any(char.isspace() for char in value):
                raise ValueError("Choose a monitor interface, for example wlan0mon")
        if self.channel is not None and (type(self.channel) is not int or not 1 <= self.channel <= 196):
            raise ValueError("Channel must be between 1 and 196, or left automatic")
        if not math.isfinite(self.interval) or not 0.001 <= self.interval <= 1:
            raise ValueError("Packet interval must be between 0.001 and 1 second")


class Transport(Protocol):
    def start(self, on_frame: Callable[[bytes, int], None]) -> str: ...
    def send(self, fragment: Fragment) -> None: ...
    def check(self) -> None: ...
    def close(self) -> None: ...
