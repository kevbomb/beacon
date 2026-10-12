"""Expected failures for untrusted protocol input."""


class ProtocolError(ValueError):
    """Base class for malformed or unsupported Beacon input."""


class InvalidIE(ProtocolError):
    """An information element has invalid fields or encoding."""


class InvalidPacket(ProtocolError):
    """A frame or DATA fragment violates packet-level constraints."""


class UnsupportedMessageType(InvalidPacket):
    """A recognized control message has no implemented DATA semantics."""


class ReassemblyError(ProtocolError):
    """Fragments conflict or assembled bytes cannot be decoded."""


class ResourceLimitError(ReassemblyError):
    """A configured receiver resource limit would be exceeded."""
