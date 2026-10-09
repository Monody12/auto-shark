"""Global keyword search across every stored blob (bodies, streams, files).

The CTF reflex this replaces is ``strings x.pcap | grep flag`` plus hunting
the encoded forms by hand. A needle is searched raw (case-insensitive), as
hex, and as base64 in all three substring phases; every hit carries the
originating evidence so the player can jump to the right page.
"""

from __future__ import annotations

import base64
import binascii
import codecs
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .project import inspect_project
from .storage import Database

MAX_BLOBS = 2000
MAX_BLOB_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_MATCHES = 200
CONTEXT_BYTES = 48

_GREP_SCHEMA = "auto-shark.grep/v1"


def needle_variants(needle: str) -> list[tuple[str, bytes]]:
    """Return the (label, bytes) forms of one search needle."""

    raw = needle.encode("utf-8", errors="replace")
    # "raw" searches case-insensitively, covering every casing of the needle.
    variants: list[tuple[str, bytes]] = [("raw", raw.lower())]
    if len(raw) >= 2:
        variants.append(("hex-lower", binascii.hexlify(raw)))
        variants.append(("hex-upper", binascii.hexlify(raw).upper()))
        stripped = raw.lstrip()  # hex of leading whitespace breaks searches
        if stripped and stripped != raw:
            variants.append(("hex-lower", binascii.hexlify(stripped)))
        # Base64 substrings depend on alignment inside the encoded stream:
        # prepend 0-2 junk bytes and drop the first encoded block to cover
        # every phase, the standard trick for grepping inside base64.
        encoded = base64.b64encode(raw).rstrip(b"=")
        if len(encoded) >= 4:
            variants.append(("base64", encoded))
            encoded_url = base64.urlsafe_b64encode(raw).rstrip(b"=")
            variants.append(("base64url", encoded_url))
        for shift in (1, 2):
            prefix = bytes([0x41]) * shift
            phase = base64.b64encode(prefix + raw)
            # Drop the partial first quad so the needle's own encoding aligns.
            trimmed = phase[4:].rstrip(b"=")
            if len(trimmed) >= 4:
                variants.append((f"base64-phase{shift}", trimmed))
    if any(character.isalpha() for character in needle):
        # Classic CTF disguise (e.g. picoCTF's ROT13 instructions file);
        # searched case-insensitively like the raw form.
        rot13 = codecs.encode(needle, "rot13").encode("utf-8")
        if rot13.lower() != raw.lower():
            variants.append(("rot13", rot13.lower()))
    return variants


@dataclass(frozen=True)
class GrepMatch:
    variant: str
    sha256: str
    source_kind: str
    frame_start: Optional[int]
    frame_end: Optional[int]
    offset: int
    context: str


def _printable_context(data: bytes, start: int, end: int) -> str:
    window = data[max(0, start - CONTEXT_BYTES) : end + CONTEXT_BYTES]
    text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in window)
    return text


def grep_project(
    project_root: Path,
    needle: str,
    *,
    max_blobs: int = MAX_BLOBS,
    max_blob_bytes: int = MAX_BLOB_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_matches: int = MAX_MATCHES,
) -> dict:
    if not needle:
        raise ValueError("search needle must not be empty")
    if min(max_blobs, max_blob_bytes, max_total_bytes, max_matches) <= 0:
        raise ValueError("search limits must be positive")
    root = Path(project_root)
    project = inspect_project(root)
    database = Database(project.root / "project.sqlite")
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT b.id, b.sha256, b.relative_path, b.byte_length, "
            "COALESCE(MIN(e.source_kind), 'blob') source_kind, "
            "MIN(e.frame_start) frame_start, MAX(e.frame_end) frame_end "
            "FROM blob b LEFT JOIN evidence e ON e.blob_id = b.id "
            "GROUP BY b.id ORDER BY b.byte_length DESC LIMIT ?",
            (max_blobs,),
        ).fetchall()
    variants = needle_variants(needle)
    matches: list[GrepMatch] = []
    scanned_bytes = 0
    blobs_scanned = 0
    match_limited = False
    blob_limited = False
    for row in rows:
        if len(matches) >= max_matches:
            match_limited = True
            break
        if scanned_bytes >= max_total_bytes:
            blob_limited = True
            break
        relative = Path(str(row["relative_path"]))
        path = root / relative
        if not path.is_file():
            continue
        try:
            with path.open("rb") as stream:
                data = stream.read(min(max_blob_bytes, max_total_bytes - scanned_bytes) + 1)
        except OSError:
            continue
        truncated_blob = len(data) > max_blob_bytes
        data = data[:max_blob_bytes]
        scanned_bytes += len(data)
        blobs_scanned += 1
        lowered = data.lower()
        for label, form in variants:
            if not form:
                continue
            if label.startswith("raw") or label.startswith("rot13"):
                # Challenge strings use arbitrary casing (PaSsZiPWorD) and
                # ROT13 files keep the original's casing; these variants
                # search case-insensitively, encoded forms exactly.
                search_space = lowered
                search_form = form.lower()
            else:
                search_space = data
                search_form = form
            start = 0
            while True:
                index = search_space.find(search_form, start)
                if index < 0:
                    break
                matches.append(
                    GrepMatch(
                        variant=label,
                        sha256=str(row["sha256"]),
                        source_kind=str(row["source_kind"]),
                        frame_start=row["frame_start"],
                        frame_end=row["frame_end"],
                        offset=index,
                        context=_printable_context(data, index, index + len(form)),
                    )
                )
                if len(matches) >= max_matches:
                    match_limited = True
                    break
                start = index + 1
            if match_limited:
                break
        if truncated_blob:
            blob_limited = True
    return {
        "schema_version": _GREP_SCHEMA,
        "needle": needle,
        "variants": [label for label, _ in variants],
        "blobs_total": len(rows),
        "blobs_scanned": blobs_scanned,
        "scanned_bytes": scanned_bytes,
        "matches": [vars(match) for match in matches],
        "match_limited": match_limited,
        "blob_limited": blob_limited,
    }
