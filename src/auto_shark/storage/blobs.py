"""Atomic content-addressed blob storage."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class BlobRecord:
    sha256: str
    byte_length: int
    path: Path


class BlobStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def put_bytes(self, data: bytes) -> BlobRecord:
        from io import BytesIO

        return self.put_stream(BytesIO(data))

    def put_stream(self, source: BinaryIO, chunk_size: int = 1024 * 1024) -> BlobRecord:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        staging = self.root / ".staging"
        staging.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix="blob-", dir=str(staging))
        digest = hashlib.sha256()
        length = 0
        try:
            with os.fdopen(descriptor, "wb") as target:
                while True:
                    chunk = source.read(chunk_size)
                    if not chunk:
                        break
                    digest.update(chunk)
                    length += len(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            sha256 = digest.hexdigest()
            destination = self.root / "sha256" / sha256[:2] / sha256
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.replace(temporary_name, destination)
            except OSError:
                if not destination.is_file():
                    raise
                Path(temporary_name).unlink(missing_ok=True)
            return BlobRecord(sha256=sha256, byte_length=length, path=destination)
        except BaseException:
            Path(temporary_name).unlink(missing_ok=True)
            raise
