"""Bounded-memory hashing helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

DEFAULT_CHUNK_SIZE = 1024 * 1024


def hash_stream(stream: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE) -> tuple[str, int]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    length = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
        length += len(chunk)
    return digest.hexdigest(), length


def hash_file(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> tuple[str, int]:
    with Path(path).open("rb") as stream:
        return hash_stream(stream, chunk_size)
