"""Closed failures exposed by the public protocol."""


class ProtocolError(Exception):
    """Base class for deterministic protocol failures."""


class InvariantViolation(ProtocolError):
    """Raised when a domain object would violate a constitutional invariant."""


class TargetRejected(ProtocolError):
    """Raised before transport when a target cannot be safely admitted."""


class CollectionFailed(ProtocolError):
    """Raised when bounded observation cannot complete."""


class ReviewNotFound(ProtocolError):
    """Raised when an immutable Review does not exist."""


class ReviewAlreadyExists(ProtocolError):
    """Raised when an insert would overwrite a Review identity."""
