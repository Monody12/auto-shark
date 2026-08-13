"""Streaming flag-pattern search with chunk-boundary overlap."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

FLAG_PATTERN = re.compile(rb"(?i:(?:flag|ctf|key|answer))\{[^{}\r\n]{1,256}\}")
MAX_MATCH_BYTES = 290


@dataclass(frozen=True)
class ByteMatch:
    offset: int
    value: bytes


@dataclass(frozen=True)
class FlagScanResult:
    matches: tuple[ByteMatch, ...]
    scanned_bytes: int
    input_truncated: bool
    candidate_limited: bool


def scan_flag_matches(
    path: Path,
    *,
    start_offset: int = 0,
    max_bytes: int,
    max_matches: int,
    chunk_size: int = 1024 * 1024,
) -> FlagScanResult:
    if start_offset < 0:
        raise ValueError("start offset cannot be negative")
    if min(max_bytes, max_matches, chunk_size) <= 0:
        raise ValueError("scan limits must be positive")
    matches: list[ByteMatch] = []
    carry = b""
    scanned = 0
    candidate_limited = False
    file_length = Path(path).stat().st_size
    with Path(path).open("rb") as stream:
        stream.seek(start_offset)
        while True:
            remaining = max_bytes - scanned
            if remaining <= 0:
                break
            chunk = stream.read(min(chunk_size, remaining))
            if not chunk:
                break
            combined = carry + chunk
            carry_length = len(carry)
            base_offset = scanned - carry_length
            for match in FLAG_PATTERN.finditer(combined):
                if match.end() > carry_length:
                    matches.append(ByteMatch(base_offset + match.start(), match.group()))
                    if len(matches) >= max_matches:
                        candidate_limited = True
                        break
            scanned += len(chunk)
            if candidate_limited:
                break
            carry = combined[-MAX_MATCH_BYTES:]
    return FlagScanResult(
        matches=tuple(matches),
        scanned_bytes=scanned,
        input_truncated=start_offset + scanned < file_length,
        candidate_limited=candidate_limited,
    )


def find_flag_matches(path: Path, *, chunk_size: int = 1024 * 1024) -> list[ByteMatch]:
    file_length = Path(path).stat().st_size
    if file_length == 0:
        return []
    result = scan_flag_matches(
        path,
        max_bytes=file_length,
        max_matches=max(1, file_length),
        chunk_size=chunk_size,
    )
    return list(result.matches)
