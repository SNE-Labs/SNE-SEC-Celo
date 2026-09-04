"""Canonical JSON and digests for durable public records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from .errors import InvariantViolation


def to_primitive(value: Any) -> Any:
    """Convert a supported object to a JSON primitive without lossy numbers."""

    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: to_primitive(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise InvariantViolation("naive datetime is not canonical")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, float):
        raise InvariantViolation("floating-point values are forbidden in canonical records")
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, bytes):
        return {"$bytes_sha256": hashlib.sha256(value).hexdigest(), "$length": len(value)}
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise InvariantViolation("canonical object keys must be strings")
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_primitive(item) for item in value]
    raise InvariantViolation(f"unsupported canonical type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        to_primitive(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise InvariantViolation("stored datetime is not timezone-aware")
    return parsed.astimezone(UTC)
