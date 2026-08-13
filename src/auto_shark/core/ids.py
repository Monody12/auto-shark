"""Stable identifiers derived from versioned canonical locators."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Optional

ID_SCHEMA_VERSION = 1


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def stable_id(namespace: str, payload: Mapping[str, Any]) -> str:
    """Return a deterministic SHA-256 ID scoped by namespace and schema version."""
    if not namespace or any(char.isspace() for char in namespace):
        raise ValueError("namespace must be a non-empty token without whitespace")
    envelope = {
        "id_schema_version": ID_SCHEMA_VERSION,
        "namespace": namespace,
        "payload": payload,
    }
    return hashlib.sha256(_canonical_json(envelope)).hexdigest()


@dataclass(frozen=True)
class EvidenceLocator:
    capture_sha256: str
    source_kind: str
    frame_start: Optional[int] = None
    frame_end: Optional[int] = None
    protocol_message: Optional[str] = None
    direction: Optional[str] = None
    byte_offset: Optional[int] = None
    byte_length: Optional[int] = None
    field_name: Optional[str] = None

    def __post_init__(self) -> None:
        digest = self.capture_sha256.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("capture_sha256 must be a 64-character hexadecimal digest")
        if not self.source_kind:
            raise ValueError("source_kind is required")
        for name in ("frame_start", "frame_end", "byte_offset", "byte_length"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} cannot be negative")
        if (
            self.frame_start is not None
            and self.frame_end is not None
            and self.frame_end < self.frame_start
        ):
            raise ValueError("frame_end cannot precede frame_start")

    def payload(self) -> Mapping[str, Any]:
        value = asdict(self)
        value["capture_sha256"] = self.capture_sha256.lower()
        return value


def evidence_id(locator: EvidenceLocator) -> str:
    return stable_id("evidence", locator.payload())


def candidate_id(kind: str, normalized_value: str) -> str:
    if not kind or not normalized_value:
        raise ValueError("candidate kind and normalized value are required")
    return stable_id("candidate", {"kind": kind, "normalized_value": normalized_value})
