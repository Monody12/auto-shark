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


def find_flag_matches(path: Path, *, chunk_size: int = 1024 * 1024) -> list[ByteMatch]:
    if chunk_size <= 0:
        raise ValueError("chunk size must be positive")
    matches: list[ByteMatch] = []
    carry = b""
    processed = 0
    with Path(path).open("rb") as stream:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            combined = carry + chunk
            carry_length = len(carry)
            base_offset = processed - carry_length
            for match in FLAG_PATTERN.finditer(combined):
                if match.end() > carry_length:
                    matches.append(ByteMatch(base_offset + match.start(), match.group()))
            processed += len(chunk)
            carry = combined[-MAX_MATCH_BYTES:]
    return matches
