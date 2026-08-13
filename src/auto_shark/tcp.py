"""Bounded TCP segment indexing and per-direction reconstruction."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from bisect import bisect_left
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional
from uuid import uuid4

from .core.ids import EvidenceLocator, evidence_id, stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import TsharkCapabilities, probe_tshark
from .project import inspect_project
from .protocols.tcp import (
    TCP_REQUIRED_FIELDS,
    TcpPacket,
    parse_tcp_line,
    selected_tcp_fields,
    tshark_tcp_arguments,
)
from .storage import BlobStore, Database


@dataclass(frozen=True)
class TcpSourceRange:
    segment_id: int
    sequence_offset: int
    output_offset: int
    byte_length: int
    role: str


@dataclass(frozen=True)
class TcpConflict:
    first_segment_id: int
    conflicting_segment_id: int
    sequence_start: int
    byte_length: int
    first_sha256: str
    conflicting_sha256: str


@dataclass(frozen=True)
class TcpDirectionSummary:
    direction: str
    status: str
    segments: int
    sequence_start: Optional[int]
    sequence_end: Optional[int]
    unique_bytes: int
    output_bytes: int
    duplicate_bytes: int
    conflict_bytes: int
    gap_bytes: int
    gaps: int
    conflicts: int
    capture_midstream: bool
    evidence_id: Optional[str]
    blob_sha256: Optional[str]


@dataclass(frozen=True)
class TcpReconstructionSummary:
    project: str
    stream_index: int
    indexed_segments: int
    indexed_payload_bytes: int
    skipped_segments: int
    index_truncated: bool
    directions: tuple[TcpDirectionSummary, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class _AcceptedSpan:
    start: int
    end: int
    segment_id: int
    blob_path: Path
    blob_offset: int


@dataclass(frozen=True)
class _Piece:
    start: int
    end: int
    blob_offset: int


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_slice(path: Path, offset: int, length: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = length
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"short payload blob read from {path}")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _compare_ranges(
    first_path: Path,
    first_offset: int,
    second_path: Path,
    second_offset: int,
    length: int,
) -> list[tuple[bool, int, int]]:
    runs: list[tuple[bool, int, int]] = []
    processed = 0
    with first_path.open("rb") as first, second_path.open("rb") as second:
        first.seek(first_offset)
        second.seek(second_offset)
        remaining = length
        while remaining:
            block = min(remaining, 1024 * 1024)
            left = first.read(block)
            right = second.read(block)
            if len(left) != block or len(right) != block:
                raise ValueError("short payload blob read while comparing overlap")
            if left == right:
                runs.append((True, processed, block))
                processed += block
                remaining -= block
                continue
            run_equal = left[0] == right[0]
            run_start = 0
            for index in range(1, block):
                equal = left[index] == right[index]
                if equal == run_equal:
                    continue
                runs.append((run_equal, processed + run_start, index - run_start))
                run_equal = equal
                run_start = index
            runs.append((run_equal, processed + run_start, block - run_start))
            processed += block
            remaining -= block
    coalesced: list[tuple[bool, int, int]] = []
    for equal, offset, run_length in runs:
        if coalesced and coalesced[-1][0] == equal:
            previous_equal, previous_offset, previous_length = coalesced[-1]
            coalesced[-1] = (
                previous_equal,
                previous_offset,
                previous_length + run_length,
            )
        else:
            coalesced.append((equal, offset, run_length))
    return coalesced


def _coalesce_pieces(pieces: list[_Piece]) -> list[_Piece]:
    if not pieces:
        return []
    result = [pieces[0]]
    for piece in pieces[1:]:
        previous = result[-1]
        if (
            previous.end == piece.start
            and previous.blob_offset + (previous.end - previous.start) == piece.blob_offset
        ):
            result[-1] = _Piece(previous.start, piece.end, previous.blob_offset)
        else:
            result.append(piece)
    return result


def _plan_segment(
    accepted: list[_AcceptedSpan],
    *,
    segment_id: int,
    segment_start: int,
    segment_length: int,
    blob_path: Path,
) -> tuple[list[_AcceptedSpan], list[TcpSourceRange], list[TcpConflict], int]:
    pending = [_Piece(segment_start, segment_start + segment_length, 0)]
    sources: list[TcpSourceRange] = []
    conflicts: list[TcpConflict] = []
    duplicate_bytes = 0
    for span in accepted:
        next_pending: list[_Piece] = []
        for piece in pending:
            overlap_start = max(piece.start, span.start)
            overlap_end = min(piece.end, span.end)
            if overlap_start >= overlap_end:
                next_pending.append(piece)
                continue
            if piece.start < overlap_start:
                next_pending.append(_Piece(piece.start, overlap_start, piece.blob_offset))
            overlap_length = overlap_end - overlap_start
            segment_offset = piece.blob_offset + overlap_start - piece.start
            first_offset = span.blob_offset + overlap_start - span.start
            for equal, relative_offset, run_length in _compare_ranges(
                span.blob_path,
                first_offset,
                blob_path,
                segment_offset,
                overlap_length,
            ):
                run_start = overlap_start + relative_offset
                if equal:
                    duplicate_bytes += run_length
                    sources.append(
                        TcpSourceRange(
                            segment_id=segment_id,
                            sequence_offset=run_start,
                            output_offset=0,
                            byte_length=run_length,
                            role="duplicate",
                        )
                    )
                    continue
                first_run_offset = first_offset + relative_offset
                conflicting_run_offset = segment_offset + relative_offset
                conflicts.append(
                    TcpConflict(
                        first_segment_id=span.segment_id,
                        conflicting_segment_id=segment_id,
                        sequence_start=run_start,
                        byte_length=run_length,
                        first_sha256=_hash_slice(span.blob_path, first_run_offset, run_length),
                        conflicting_sha256=_hash_slice(
                            blob_path, conflicting_run_offset, run_length
                        ),
                    )
                )
            if overlap_end < piece.end:
                next_pending.append(
                    _Piece(
                        overlap_end,
                        piece.end,
                        piece.blob_offset + overlap_end - piece.start,
                    )
                )
        pending = _coalesce_pieces(sorted(next_pending, key=lambda item: item.start))
        if not pending:
            break
    additions = [
        _AcceptedSpan(piece.start, piece.end, segment_id, blob_path, piece.blob_offset)
        for piece in pending
    ]
    starts = [span.start for span in accepted]
    for addition in additions:
        accepted.insert(bisect_left(starts, addition.start), addition)
        starts = [span.start for span in accepted]
    return additions, sources, conflicts, duplicate_bytes


def _write_span(source: Path, offset: int, length: int, target: BinaryIO) -> None:
    with source.open("rb") as stream:
        stream.seek(offset)
        remaining = length
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"short payload blob read from {source}")
            target.write(chunk)
            remaining -= len(chunk)


def _blob_id(database: Database, project_root: Path, blob: object, complete: bool) -> int:
    relative_path = blob.path.relative_to(project_root).as_posix()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO blob (sha256,byte_length,relative_path,complete,created_at) "
            "VALUES (?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
            "complete=max(blob.complete,excluded.complete)",
            (blob.sha256, blob.byte_length, relative_path, int(complete), _utc_now()),
        )
        return int(
            connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
        )


def _record_packet(
    database: Database,
    project_root: Path,
    capture_db_id: int,
    capture_sha256: str,
    tool_run_id: int,
    packet: TcpPacket,
) -> tuple[int, int]:
    if not packet.payload:
        return 0, 0
    payload_blob = BlobStore(project_root / "blobs").put_bytes(packet.payload)
    payload_blob_id = _blob_id(database, project_root, payload_blob, True)
    conversation_public_id = stable_id(
        "conversation",
        {"capture_sha256": capture_sha256, "protocol": "tcp", "stream_index": packet.stream_index},
    )
    segment_public_id = stable_id(
        "tcp-segment",
        {"capture_sha256": capture_sha256, "frame_number": packet.frame_number},
    )
    with database.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO frame "
            "(capture_id,frame_number,time_epoch,captured_length,original_length) "
            "VALUES (?,?,?,?,?)",
            (
                capture_db_id,
                packet.frame_number,
                packet.time_epoch,
                packet.captured_length,
                packet.frame_length,
            ),
        )
        connection.execute(
            "INSERT OR IGNORE INTO conversation "
            "(conversation_id,capture_id,protocol,stream_index,endpoint_a,endpoint_b) "
            "VALUES (?,?,'tcp',?,?,?)",
            (
                conversation_public_id,
                capture_db_id,
                packet.stream_index,
                f"{packet.source}:{packet.source_port}",
                f"{packet.destination}:{packet.destination_port}",
            ),
        )
        conversation_id = int(
            connection.execute(
                "SELECT id FROM conversation WHERE conversation_id=?",
                (conversation_public_id,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO tcp_segment "
            "(segment_id,capture_id,conversation_id,tool_run_id,frame_number,stream_index,"
            "direction,sequence_relative,sequence_raw,payload_length,payload_blob_id,"
            "retransmission,spurious_retransmission,out_of_order,lost_segment) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(segment_id) DO UPDATE SET "
            "retransmission=max(tcp_segment.retransmission,excluded.retransmission),"
            "spurious_retransmission=max(tcp_segment.spurious_retransmission,"
            "excluded.spurious_retransmission),"
            "out_of_order=max(tcp_segment.out_of_order,excluded.out_of_order),"
            "lost_segment=max(tcp_segment.lost_segment,excluded.lost_segment)",
            (
                segment_public_id,
                capture_db_id,
                conversation_id,
                tool_run_id,
                packet.frame_number,
                packet.stream_index,
                packet.direction,
                packet.sequence_relative,
                packet.sequence_raw,
                len(packet.payload),
                payload_blob_id,
                int(packet.retransmission),
                int(packet.spurious_retransmission),
                int(packet.out_of_order),
                int(packet.lost_segment),
            ),
        )
        segment_id = int(
            connection.execute(
                "SELECT id FROM tcp_segment WHERE segment_id=?", (segment_public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO tcp_segment_run (segment_id,tool_run_id) VALUES (?,?)",
            (segment_id, tool_run_id),
        )
    return 1, len(packet.payload)


def _ensure_packet_context(
    database: Database,
    *,
    capture_db_id: int,
    capture_sha256: str,
    packet: TcpPacket,
) -> int:
    conversation_public_id = stable_id(
        "conversation",
        {
            "capture_sha256": capture_sha256,
            "protocol": "tcp",
            "stream_index": packet.stream_index,
        },
    )
    with database.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO frame "
            "(capture_id,frame_number,time_epoch,captured_length,original_length) "
            "VALUES (?,?,?,?,?)",
            (
                capture_db_id,
                packet.frame_number,
                packet.time_epoch,
                packet.captured_length,
                packet.frame_length,
            ),
        )
        connection.execute(
            "INSERT OR IGNORE INTO conversation "
            "(conversation_id,capture_id,protocol,stream_index,endpoint_a,endpoint_b) "
            "VALUES (?,?,'tcp',?,?,?)",
            (
                conversation_public_id,
                capture_db_id,
                packet.stream_index,
                f"{packet.source}:{packet.source_port}",
                f"{packet.destination}:{packet.destination_port}",
            ),
        )
        return int(
            connection.execute(
                "SELECT id FROM conversation WHERE conversation_id=?",
                (conversation_public_id,),
            ).fetchone()[0]
        )


def _sequence_output_offset(accepted: list[_AcceptedSpan], sequence: int) -> Optional[int]:
    output = 0
    for span in accepted:
        if span.start <= sequence < span.end:
            return output + sequence - span.start
        output += span.end - span.start
    return None


def _reconstruct_direction(
    database: Database,
    project_root: Path,
    capture_sha256: str,
    conversation_id: int,
    conversation_public_id: str,
    tool_run_id: int,
    direction: str,
    *,
    max_output_bytes: int,
    capture_midstream: bool,
    force_truncated: bool,
) -> TcpDirectionSummary:
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT ts.id,ts.frame_number,ts.sequence_relative,ts.payload_length,"
            "b.relative_path FROM tcp_segment ts JOIN blob b ON b.id=ts.payload_blob_id "
            "JOIN tcp_segment_run tsr ON tsr.segment_id=ts.id "
            "WHERE ts.conversation_id=? AND ts.direction=? AND tsr.tool_run_id=? "
            "ORDER BY ts.frame_number",
            (conversation_id, direction, tool_run_id),
        ).fetchall()
    accepted: list[_AcceptedSpan] = []
    duplicate_sources: list[TcpSourceRange] = []
    conflicts: list[TcpConflict] = []
    duplicate_bytes = 0
    for row in rows:
        additions, sources, new_conflicts, duplicates = _plan_segment(
            accepted,
            segment_id=int(row["id"]),
            segment_start=int(row["sequence_relative"]),
            segment_length=int(row["payload_length"]),
            blob_path=project_root / row["relative_path"],
        )
        del additions
        duplicate_sources.extend(sources)
        conflicts.extend(new_conflicts)
        duplicate_bytes += duplicates
    sequence_start = accepted[0].start if accepted else None
    sequence_end = max((span.end for span in accepted), default=None)
    frame_start = min((int(row["frame_number"]) for row in rows), default=None)
    frame_end = max((int(row["frame_number"]) for row in rows), default=None)
    gaps: list[tuple[int, int]] = []
    for left, right in zip(accepted, accepted[1:]):
        if right.start > left.end:
            gaps.append((left.end, right.start - left.end))
    unique_bytes = sum(span.end - span.start for span in accepted)
    gap_bytes = sum(length for _, length in gaps)
    output_limit_hit = unique_bytes > max_output_bytes
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="tcp-stream-", dir=str(project_root / "jobs")
    )
    temporary_path = Path(temporary_name)
    primary_sources: list[TcpSourceRange] = []
    output_bytes = 0
    blob = None
    try:
        with os.fdopen(descriptor, "wb") as target:
            for span in accepted:
                if output_bytes >= max_output_bytes:
                    break
                length = min(span.end - span.start, max_output_bytes - output_bytes)
                _write_span(span.blob_path, span.blob_offset, length, target)
                primary_sources.append(
                    TcpSourceRange(
                        segment_id=span.segment_id,
                        sequence_offset=span.start,
                        output_offset=output_bytes,
                        byte_length=length,
                        role="primary",
                    )
                )
                output_bytes += length
            target.flush()
            os.fsync(target.fileno())
        if output_bytes:
            with temporary_path.open("rb") as source:
                blob = BlobStore(project_root / "blobs").put_stream(source)
    finally:
        temporary_path.unlink(missing_ok=True)
    if force_truncated:
        status = "truncated"
    elif not accepted:
        status = "empty"
    elif output_limit_hit:
        status = "truncated"
    elif conflicts:
        status = "conflicting"
    elif gaps:
        status = "partial"
    else:
        status = "complete"
    reconstruction_public_id = stable_id(
        "tcp-reconstruction",
        {
            "conversation_id": conversation_public_id,
            "direction": direction,
            "version": 1,
        },
    )
    evidence_public_id: Optional[str] = None
    blob_sha256: Optional[str] = None
    with database.connect() as connection:
        evidence_db_id = None
        if blob is not None:
            blob_db_id = _blob_id(database, project_root, blob, status == "complete")
            locator = EvidenceLocator(
                capture_sha256=capture_sha256,
                source_kind="tcp-stream",
                frame_start=frame_start,
                frame_end=frame_end,
                protocol_message=f"{reconstruction_public_id}:{blob.sha256}",
                direction=direction,
                byte_offset=0,
                byte_length=blob.byte_length,
            )
            evidence_public_id = evidence_id(locator)
            blob_sha256 = blob.sha256
            connection.execute(
                "INSERT OR IGNORE INTO evidence "
                "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,"
                "byte_offset,byte_length,blob_id,locator_json) "
                "SELECT ?,capture_id,'tcp-stream',?,?,?,0,?,?,? "
                "FROM conversation WHERE id=?",
                (
                    evidence_public_id,
                    frame_start,
                    frame_end,
                    direction,
                    blob.byte_length,
                    blob_db_id,
                    json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
                    conversation_id,
                ),
            )
            evidence_db_id = int(
                connection.execute(
                    "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public_id,)
                ).fetchone()[0]
            )
        connection.execute(
            "INSERT INTO tcp_reconstruction "
            "(reconstruction_id,conversation_id,direction,evidence_id,tool_run_id,status,"
            "sequence_start,sequence_end,unique_bytes,output_bytes,duplicate_bytes,"
            "conflict_bytes,gap_bytes,capture_midstream,max_output_bytes,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(conversation_id,direction) "
            "DO UPDATE SET reconstruction_id=excluded.reconstruction_id,"
            "evidence_id=excluded.evidence_id,tool_run_id=excluded.tool_run_id,"
            "status=excluded.status,sequence_start=excluded.sequence_start,"
            "sequence_end=excluded.sequence_end,unique_bytes=excluded.unique_bytes,"
            "output_bytes=excluded.output_bytes,duplicate_bytes=excluded.duplicate_bytes,"
            "conflict_bytes=excluded.conflict_bytes,gap_bytes=excluded.gap_bytes,"
            "capture_midstream=excluded.capture_midstream,"
            "max_output_bytes=excluded.max_output_bytes,updated_at=excluded.updated_at",
            (
                reconstruction_public_id,
                conversation_id,
                direction,
                evidence_db_id,
                tool_run_id,
                status,
                sequence_start,
                sequence_end,
                unique_bytes,
                output_bytes,
                duplicate_bytes,
                sum(item.byte_length for item in conflicts),
                gap_bytes,
                int(capture_midstream),
                max_output_bytes,
                _utc_now(),
            ),
        )
        reconstruction_id = int(
            connection.execute(
                "SELECT id FROM tcp_reconstruction WHERE conversation_id=? AND direction=?",
                (conversation_id, direction),
            ).fetchone()[0]
        )
        connection.execute(
            "DELETE FROM tcp_reconstruction_source WHERE reconstruction_id=?",
            (reconstruction_id,),
        )
        connection.execute("DELETE FROM tcp_gap WHERE reconstruction_id=?", (reconstruction_id,))
        connection.execute(
            "DELETE FROM tcp_overlap_conflict WHERE reconstruction_id=?", (reconstruction_id,)
        )
        for source in primary_sources:
            connection.execute(
                "INSERT INTO tcp_reconstruction_source "
                "(reconstruction_id,segment_id,sequence_offset,output_offset,byte_length,role) "
                "VALUES (?,?,?,?,?,'primary')",
                (
                    reconstruction_id,
                    source.segment_id,
                    source.sequence_offset,
                    source.output_offset,
                    source.byte_length,
                ),
            )
        for source in duplicate_sources:
            output_offset = _sequence_output_offset(accepted, source.sequence_offset)
            if output_offset is None or output_offset >= output_bytes:
                continue
            length = min(source.byte_length, output_bytes - output_offset)
            connection.execute(
                "INSERT OR IGNORE INTO tcp_reconstruction_source "
                "(reconstruction_id,segment_id,sequence_offset,output_offset,byte_length,role) "
                "VALUES (?,?,?,?,?,'duplicate')",
                (
                    reconstruction_id,
                    source.segment_id,
                    source.sequence_offset,
                    output_offset,
                    length,
                ),
            )
        for gap_start, gap_length in gaps:
            connection.execute(
                "INSERT INTO tcp_gap (reconstruction_id,sequence_start,byte_length) VALUES (?,?,?)",
                (reconstruction_id, gap_start, gap_length),
            )
        for conflict in conflicts:
            conflict_public_id = stable_id(
                "tcp-overlap-conflict",
                {
                    "reconstruction_id": reconstruction_public_id,
                    "first_segment_id": conflict.first_segment_id,
                    "conflicting_segment_id": conflict.conflicting_segment_id,
                    "sequence_start": conflict.sequence_start,
                    "byte_length": conflict.byte_length,
                },
            )
            connection.execute(
                "INSERT INTO tcp_overlap_conflict "
                "(conflict_id,reconstruction_id,first_segment_id,conflicting_segment_id,"
                "sequence_start,byte_length,first_sha256,conflicting_sha256) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    conflict_public_id,
                    reconstruction_id,
                    conflict.first_segment_id,
                    conflict.conflicting_segment_id,
                    conflict.sequence_start,
                    conflict.byte_length,
                    conflict.first_sha256,
                    conflict.conflicting_sha256,
                ),
            )
    return TcpDirectionSummary(
        direction=direction,
        status=status,
        segments=len(rows),
        sequence_start=sequence_start,
        sequence_end=sequence_end,
        unique_bytes=unique_bytes,
        output_bytes=output_bytes,
        duplicate_bytes=duplicate_bytes,
        conflict_bytes=sum(item.byte_length for item in conflicts),
        gap_bytes=gap_bytes,
        gaps=len(gaps),
        conflicts=len(conflicts),
        capture_midstream=capture_midstream,
        evidence_id=evidence_public_id,
        blob_sha256=blob_sha256,
    )


def reconstruct_tcp_stream(
    project_path: Path,
    stream_index: int,
    tshark: Path,
    *,
    max_segments: int = 100_000,
    max_index_payload_bytes: int = 512 * 1024 * 1024,
    max_direction_bytes: int = 256 * 1024 * 1024,
    max_total_output_bytes: int = 512 * 1024 * 1024,
    capabilities: Optional[TsharkCapabilities] = None,
) -> TcpReconstructionSummary:
    if stream_index < 0:
        raise ValueError("TCP stream index cannot be negative")
    if (
        min(
            max_segments,
            max_index_payload_bytes,
            max_direction_bytes,
            max_total_output_bytes,
        )
        <= 0
    ):
        raise ValueError("TCP reconstruction limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = capabilities or probe_tshark(tshark)
    available_fields = set(capabilities.fields)
    missing = sorted(set(TCP_REQUIRED_FIELDS) - available_fields)
    has_ip_endpoints = {"ip.src", "ip.dst"}.issubset(available_fields)
    has_ipv6_endpoints = {"ipv6.src", "ipv6.dst"}.issubset(available_fields)
    if not capabilities.usable or missing or not (has_ip_endpoints or has_ipv6_endpoints):
        if not (has_ip_endpoints or has_ipv6_endpoints):
            missing.append("ip.src/ip.dst or ipv6.src/ipv6.dst")
        raise ValueError(f"TShark lacks required TCP fields: {', '.join(missing)}")
    argv = tshark_tcp_arguments(
        tshark,
        project.capture_path,
        stream_index,
        available_fields=available_fields,
    )
    parsed_fields = selected_tcp_fields(available_fields)
    run_public_id = uuid4().hex
    with database.connect() as connection:
        capture_db_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO tool_run "
            "(run_id,tool_name,tool_version,argv_json,capability_json,started_at,status) "
            "VALUES (?,'tshark',?,?,?,?,'running')",
            (
                run_public_id,
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_json(),
                _utc_now(),
            ),
        )
        tool_run_id = int(
            connection.execute(
                "SELECT id FROM tool_run WHERE run_id=?", (run_public_id,)
            ).fetchone()[0]
        )
    indexed_segments = 0
    indexed_payload_bytes = 0
    skipped_segments = 0
    index_truncated = False
    result = None
    run_status = "failed"
    exit_code = None
    stderr_text = "TCP indexing failed; see caller error"
    stderr_truncated = 0
    saw_syn_by_direction: dict[str, bool] = {}
    try:

        def consume(line: bytes) -> None:
            nonlocal indexed_segments, indexed_payload_bytes, skipped_segments, index_truncated
            packet = parse_tcp_line(line, parsed_fields)
            saw_syn_by_direction[packet.direction] = (
                saw_syn_by_direction.get(packet.direction, False) or packet.syn
            )
            if not packet.payload:
                return
            if (
                indexed_segments >= max_segments
                or indexed_payload_bytes + len(packet.payload) > max_index_payload_bytes
            ):
                reason = "segment-limit" if indexed_segments >= max_segments else "payload-budget"
                _ensure_packet_context(
                    database,
                    capture_db_id=capture_db_id,
                    capture_sha256=project.capture_sha256,
                    packet=packet,
                )
                with database.connect() as connection:
                    connection.execute(
                        "INSERT OR REPLACE INTO tcp_segment_skip "
                        "(tool_run_id,capture_id,frame_number,stream_index,direction,"
                        "payload_length,reason) VALUES (?,?,?,?,?,?,?)",
                        (
                            tool_run_id,
                            capture_db_id,
                            packet.frame_number,
                            packet.stream_index,
                            packet.direction,
                            len(packet.payload),
                            reason,
                        ),
                    )
                skipped_segments += 1
                index_truncated = True
                return
            added, added_bytes = _record_packet(
                database,
                project.root,
                capture_db_id,
                project.capture_sha256,
                tool_run_id,
                packet,
            )
            indexed_segments += added
            indexed_payload_bytes += added_bytes

        result = run_streaming_lines(
            argv,
            consume,
            timeout_seconds=300,
            max_line_bytes=16 * 1024 * 1024,
            stderr_limit=512 * 1024,
        )
        if result.timed_out:
            raise TimeoutError("TShark TCP segment extraction timed out")
        if result.output_limit_exceeded:
            raise ValueError("TShark emitted a TCP segment line above the configured limit")
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"TShark TCP extraction exited {result.returncode}: {detail[:500]}")
        run_status = "completed"
        exit_code = result.returncode
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        stderr_truncated = int(result.stderr_truncated)
    finally:
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
                "stderr_truncated=? WHERE id=?",
                (_utc_now(), run_status, exit_code, stderr_text, stderr_truncated, tool_run_id),
            )
    with database.connect() as connection:
        conversation = connection.execute(
            "SELECT id,conversation_id FROM conversation "
            "WHERE capture_id=? AND protocol='tcp' AND stream_index=?",
            (capture_db_id, stream_index),
        ).fetchone()
        if conversation is None:
            raise ValueError(f"TCP stream {stream_index} contains no indexed payload")
        indexed_directions = {
            str(row[0])
            for row in connection.execute(
                "SELECT DISTINCT ts.direction FROM tcp_segment ts "
                "JOIN tcp_segment_run tsr ON tsr.segment_id=ts.id "
                "WHERE ts.conversation_id=? AND tsr.tool_run_id=? "
                "ORDER BY direction",
                (conversation["id"], tool_run_id),
            )
        }
        skipped_directions = {
            str(row[0])
            for row in connection.execute(
                "SELECT DISTINCT direction FROM tcp_segment_skip WHERE tool_run_id=?",
                (tool_run_id,),
            )
        }
        directions = tuple(sorted(indexed_directions | skipped_directions))
    summaries: list[TcpDirectionSummary] = []
    remaining_total = max_total_output_bytes
    capture_has_stream_start = any(saw_syn_by_direction.values())
    for direction in directions:
        limit = min(max_direction_bytes, remaining_total)
        summary = _reconstruct_direction(
            database,
            project.root,
            project.capture_sha256,
            int(conversation["id"]),
            str(conversation["conversation_id"]),
            tool_run_id,
            direction,
            max_output_bytes=limit,
            capture_midstream=not capture_has_stream_start,
            force_truncated=direction in skipped_directions,
        )
        summaries.append(summary)
        remaining_total -= summary.output_bytes
    return TcpReconstructionSummary(
        project=str(project.root),
        stream_index=stream_index,
        indexed_segments=indexed_segments,
        indexed_payload_bytes=indexed_payload_bytes,
        skipped_segments=skipped_segments,
        index_truncated=index_truncated,
        directions=tuple(summaries),
    )
