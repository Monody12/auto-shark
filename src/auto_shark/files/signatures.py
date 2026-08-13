"""Bounded signature scanning and structural-end validation."""

from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional


@dataclass(frozen=True)
class FileCandidate:
    format: str
    media_type: str
    extension: str
    start_offset: int
    byte_length: int
    structural_status: str
    validation_detail: str
    prefix_length: int
    trailing_offset: Optional[int]
    trailing_length: int


@dataclass(frozen=True)
class DiscoveryResult:
    candidates: tuple[FileCandidate, ...]
    file_length: int
    scanned_bytes: int
    scan_truncated: bool
    candidate_limit_reached: bool


_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png", "image/png", ".png"),
    (b"\xff\xd8\xff", "jpeg", "image/jpeg", ".jpg"),
    (b"PK\x03\x04", "zip", "application/zip", ".zip"),
    (b"%PDF-", "pdf", "application/pdf", ".pdf"),
    (b"Rar!\x1a\x07\x00", "rar4", "application/vnd.rar", ".rar"),
    (b"Rar!\x1a\x07\x01\x00", "rar5", "application/vnd.rar", ".rar"),
    (b"\x1f\x8b\x08", "gzip", "application/gzip", ".gz"),
    (b"MZ", "pe", "application/vnd.microsoft.portable-executable", ".exe"),
)


def _read_at(stream: BinaryIO, offset: int, length: int, limit: int) -> bytes:
    if offset < 0 or length < 0 or offset + length > limit:
        return b""
    stream.seek(offset)
    return stream.read(length)


def _find_offsets(
    stream: BinaryIO,
    signatures: tuple[bytes, ...],
    limit: int,
    max_candidates: int,
    window_bytes: int,
) -> tuple[list[tuple[int, bytes]], bool]:
    overlap = max(len(signature) for signature in signatures) - 1
    cursor = 0
    carry = b""
    matches: list[tuple[int, bytes]] = []
    seen: set[tuple[int, bytes]] = set()
    limit_reached = False
    while cursor < limit:
        stream.seek(cursor)
        chunk = stream.read(min(window_bytes, limit - cursor))
        if not chunk:
            break
        data = carry + chunk
        base = cursor - len(carry)
        for signature in signatures:
            search_from = 0
            while True:
                index = data.find(signature, search_from)
                if index < 0:
                    break
                absolute = base + index
                key = (absolute, signature)
                if absolute < limit and key not in seen:
                    seen.add(key)
                    matches.append(key)
                    if len(matches) >= max_candidates:
                        limit_reached = True
                        return sorted(matches), limit_reached
                search_from = index + 1
        cursor += len(chunk)
        carry = data[-overlap:] if overlap else b""
    return sorted(matches), limit_reached


def _png_end(stream: BinaryIO, start: int, limit: int) -> Optional[int]:
    if _read_at(stream, start, 8, limit) != b"\x89PNG\r\n\x1a\n":
        return None
    cursor = start + 8
    chunks = 0
    while cursor + 12 <= limit and chunks < 100_000:
        header = _read_at(stream, cursor, 8, limit)
        if len(header) != 8:
            return None
        length = int.from_bytes(header[:4], "big")
        chunk_type = header[4:]
        end = cursor + 12 + length
        if end > limit:
            return None
        crc = binascii.crc32(chunk_type)
        remaining = length
        data_offset = cursor + 8
        while remaining:
            block = _read_at(stream, data_offset, min(remaining, 1024 * 1024), limit)
            if not block:
                return None
            crc = binascii.crc32(block, crc)
            data_offset += len(block)
            remaining -= len(block)
        expected_crc = int.from_bytes(_read_at(stream, cursor + 8 + length, 4, limit), "big")
        if crc & 0xFFFFFFFF != expected_crc:
            return None
        chunks += 1
        cursor = end
        if chunk_type == b"IEND":
            return cursor if length == 0 else None
    return None


def _find_jpeg_marker(stream: BinaryIO, cursor: int, limit: int) -> Optional[int]:
    while cursor < limit:
        stream.seek(cursor)
        chunk = stream.read(min(1024 * 1024, limit - cursor))
        if not chunk:
            return None
        index = chunk.find(b"\xff")
        if index < 0:
            cursor += len(chunk)
            continue
        marker = cursor + index
        pair = _read_at(stream, marker, 2, limit)
        if len(pair) != 2:
            return None
        code = pair[1]
        if code == 0x00 or 0xD0 <= code <= 0xD7:
            cursor = marker + 2
            continue
        if code == 0xFF:
            cursor = marker + 1
            continue
        return marker
    return None


def _jpeg_end(stream: BinaryIO, start: int, limit: int) -> Optional[int]:
    if _read_at(stream, start, 3, limit)[:2] != b"\xff\xd8":
        return None
    cursor = start + 2
    in_entropy_data = False
    markers = 0
    while cursor + 2 <= limit and markers < 100_000:
        marker = _find_jpeg_marker(stream, cursor, limit)
        if marker is None:
            return None
        code_bytes = _read_at(stream, marker, 2, limit)
        if len(code_bytes) != 2:
            return None
        code = code_bytes[1]
        markers += 1
        if code == 0xD9:
            return marker + 2
        if code == 0xD8 or code == 0x00:
            return None
        if code == 0x01 or 0xD0 <= code <= 0xD7:
            cursor = marker + 2
            continue
        length_bytes = _read_at(stream, marker + 2, 2, limit)
        if len(length_bytes) != 2:
            return None
        segment_length = int.from_bytes(length_bytes, "big")
        if segment_length < 2 or marker + 2 + segment_length > limit:
            return None
        cursor = marker + 2 + segment_length
        in_entropy_data = code == 0xDA
        if not in_entropy_data:
            continue
        next_marker = _find_jpeg_marker(stream, cursor, limit)
        if next_marker is None:
            return None
        cursor = next_marker
    return None


def _zip_end(stream: BinaryIO, start: int, limit: int) -> Optional[int]:
    if _read_at(stream, start, 4, limit) != b"PK\x03\x04":
        return None
    cursor = start + 4
    carry = b""
    while cursor < limit:
        stream.seek(cursor)
        chunk = stream.read(min(1024 * 1024, limit - cursor))
        if not chunk:
            return None
        data = carry + chunk
        base = cursor - len(carry)
        search_from = 0
        while True:
            index = data.find(b"PK\x05\x06", search_from)
            if index < 0:
                break
            eocd = base + index
            record = _read_at(stream, eocd + 4, 18, limit)
            if len(record) != 18:
                search_from = index + 1
                continue
            fields = struct.unpack("<4H2IH", record)
            disk_number, central_disk, entries_disk, entries_total = fields[:4]
            central_size, central_offset, comment_length = fields[4:]
            end = eocd + 22 + comment_length
            sentinel = 0xFFFF in (entries_disk, entries_total) or 0xFFFFFFFF in (
                central_size,
                central_offset,
            )
            central_start = start + central_offset
            central_end = central_start + central_size
            central_signature_ok = (
                entries_total == 0 or _read_at(stream, central_start, 4, limit) == b"PK\x01\x02"
            )
            if (
                not sentinel
                and disk_number == 0
                and central_disk == 0
                and entries_disk == entries_total
                and end <= limit
                and central_end == eocd
                and central_start >= start
                and central_signature_ok
            ):
                return end
            search_from = index + 1
        carry = data[-3:]
        cursor += len(chunk)
    return None


def _pdf_end(stream: BinaryIO, start: int, limit: int) -> Optional[int]:
    cursor = start + 5
    carry = b""
    last_marker: Optional[int] = None
    while cursor < limit:
        stream.seek(cursor)
        chunk = stream.read(min(1024 * 1024, limit - cursor))
        if not chunk:
            break
        data = carry + chunk
        base = cursor - len(carry)
        search_from = 0
        while True:
            index = data.find(b"%%EOF", search_from)
            if index < 0:
                break
            last_marker = base + index
            search_from = index + 1
        carry = data[-4:]
        cursor += len(chunk)
    if last_marker is None:
        return None
    end = last_marker + 5
    while end < limit and _read_at(stream, end, 1, limit) in (b" ", b"\t", b"\r", b"\n"):
        end += 1
    return end


def _pe_header_valid(stream: BinaryIO, start: int, limit: int) -> bool:
    dos = _read_at(stream, start, 64, limit)
    if len(dos) != 64 or dos[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(dos[60:64], "little")
    return pe_offset >= 64 and _read_at(stream, start + pe_offset, 4, limit) == b"PE\x00\x00"


def _candidate(
    *,
    format_name: str,
    media_type: str,
    extension: str,
    start: int,
    end: int,
    parent_length: int,
    status: str,
    detail: str,
) -> FileCandidate:
    validated = status == "validated"
    return FileCandidate(
        format=format_name,
        media_type=media_type,
        extension=extension,
        start_offset=start,
        byte_length=end - start,
        structural_status=status,
        validation_detail=detail,
        prefix_length=start,
        trailing_offset=end if validated and end < parent_length else None,
        trailing_length=parent_length - end if validated and end < parent_length else 0,
    )


def discover_file_candidates(
    path: Path,
    *,
    max_scan_bytes: int = 64 * 1024 * 1024,
    max_artifact_bytes: int = 64 * 1024 * 1024,
    max_candidates: int = 128,
    window_bytes: int = 1024 * 1024,
) -> DiscoveryResult:
    """Find supported signatures while respecting strict scan and artifact limits."""
    if min(max_scan_bytes, max_artifact_bytes, max_candidates, window_bytes) <= 0:
        raise ValueError("file scan limits must be positive")
    file_path = Path(path)
    file_length = file_path.stat().st_size
    scan_limit = min(file_length, max_scan_bytes)
    if file_length == 0:
        return DiscoveryResult((), 0, 0, False, False)
    signature_map = {
        signature: (name, media, extension) for signature, name, media, extension in _SIGNATURES
    }
    candidates: list[FileCandidate] = []
    with file_path.open("rb") as stream:
        matches, candidate_limit_reached = _find_offsets(
            stream,
            tuple(signature_map),
            scan_limit,
            max_candidates,
            window_bytes,
        )
        for start, signature in matches:
            format_name, media_type, extension = signature_map[signature]
            parser = {
                "png": _png_end,
                "jpeg": _jpeg_end,
                "zip": _zip_end,
                "pdf": _pdf_end,
            }.get(format_name)
            if parser is not None:
                structural_end = parser(stream, start, scan_limit)
                if structural_end is None:
                    if scan_limit < file_length:
                        end = min(scan_limit, start + max_artifact_bytes)
                        if end > start:
                            candidates.append(
                                _candidate(
                                    format_name=format_name,
                                    media_type=media_type,
                                    extension=extension,
                                    start=start,
                                    end=end,
                                    parent_length=file_length,
                                    status="scan-truncated",
                                    detail="structural end was not found within the scan budget",
                                )
                            )
                    continue
                status = "validated"
                detail = "structural end validated"
                end = structural_end
                if structural_end - start > max_artifact_bytes:
                    status = "artifact-truncated"
                    detail = "validated file exceeds the artifact byte budget"
                    end = start + max_artifact_bytes
                candidates.append(
                    _candidate(
                        format_name=format_name,
                        media_type=media_type,
                        extension=extension,
                        start=start,
                        end=end,
                        parent_length=file_length,
                        status=status,
                        detail=detail,
                    )
                )
                continue
            if format_name == "pe" and not _pe_header_valid(stream, start, scan_limit):
                continue
            if format_name == "gzip":
                header = _read_at(stream, start, 4, scan_limit)
                if len(header) != 4 or header[2] != 8 or header[3] & 0xE0:
                    continue
            end = min(file_length, scan_limit, start + max_artifact_bytes)
            if end <= start:
                continue
            detail = {
                "rar4": "RAR4 signature recognized; archive structure was not opened",
                "rar5": "RAR5 signature recognized; archive structure was not opened",
                "gzip": "GZIP header recognized; compressed data was not inflated",
                "pe": "DOS and PE signatures recognized; executable was not loaded",
            }[format_name]
            status = "signature-only"
            if end < min(file_length, scan_limit):
                status = "artifact-truncated"
                detail += "; artifact byte budget reached"
            elif scan_limit < file_length:
                status = "scan-truncated"
                detail += "; scan byte budget reached"
            candidates.append(
                _candidate(
                    format_name=format_name,
                    media_type=media_type,
                    extension=extension,
                    start=start,
                    end=end,
                    parent_length=file_length,
                    status=status,
                    detail=detail,
                )
            )
    unique = {
        (candidate.format, candidate.start_offset, candidate.byte_length): candidate
        for candidate in candidates
    }
    ordered = tuple(sorted(unique.values(), key=lambda item: (item.start_offset, item.format)))
    return DiscoveryResult(
        candidates=ordered[:max_candidates],
        file_length=file_length,
        scanned_bytes=scan_limit,
        scan_truncated=scan_limit < file_length,
        candidate_limit_reached=candidate_limit_reached or len(ordered) > max_candidates,
    )
