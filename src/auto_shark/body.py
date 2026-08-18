"""On-demand HTTP body extraction with evidence and blob provenance."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import EvidenceLocator, evidence_id
from .engines.hexstream import run_hex_to_file
from .engines.stream import run_streaming_lines
from .engines.tshark import TlsRsaKey, TsharkCapabilities, probe_tshark
from .project import ProjectInfo, inspect_project
from .storage import BlobStore, Database

_BATCH_BODY_LINE = re.compile(rb'^"([0-9]+)"\t(?:"([0-9A-Fa-f:]*|<MISSING>)"|)$')


@dataclass(frozen=True)
class BodyExtractionSummary:
    project: str
    frame_number: int
    message_kind: str
    status: str
    declared_length: Optional[int]
    extracted_length: int
    truncated: bool
    sha256: Optional[str]
    blob_path: Optional[str]
    evidence_id: Optional[str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class BodyBatchExtractionSummary:
    statuses: tuple[BodyExtractionSummary, ...]
    skipped_frames: tuple[int, ...]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _body_arguments(
    tshark: Path,
    capture: Path,
    frame_number: int,
    *,
    preferences: Sequence[str] = (),
) -> list[str]:
    return [
        str(tshark),
        "-2",
        "-r",
        str(capture),
        *preferences,
        "-Y",
        f"frame.number == {frame_number}",
        "-T",
        "fields",
        "-E",
        "occurrence=f",
        "-e",
        "http.file_data",
    ]


def _batch_body_arguments(
    tshark: Path,
    capture: Path,
    frame_numbers: Sequence[int],
    *,
    preferences: Sequence[str] = (),
) -> list[str]:
    if not frame_numbers or any(frame <= 0 for frame in frame_numbers):
        raise ValueError("batch body frames must be positive")
    frame_set = ",".join(str(frame) for frame in frame_numbers)
    return [
        str(tshark),
        "-2",
        "-r",
        str(capture),
        *preferences,
        "-Y",
        f"frame.number in {{{frame_set}}}",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
        "-E",
        "occurrence=f",
        "-e",
        "frame.number",
        "-e",
        "http.file_data",
    ]


def _parse_batch_body_line(line: bytes) -> tuple[int, bytes]:
    match = _BATCH_BODY_LINE.fullmatch(line)
    if match is None:
        raise ValueError("malformed TShark HTTP body row")
    frame_number = int(match.group(1))
    body_value = match.group(2)
    if body_value in (None, b"<MISSING>"):
        return frame_number, b""
    compact = body_value.replace(b":", b"")
    if len(compact) % 2:
        raise ValueError(f"frame {frame_number} body has an incomplete hexadecimal byte")
    try:
        return frame_number, bytes.fromhex(compact.decode("ascii"))
    except ValueError as error:
        raise ValueError(f"frame {frame_number} body is not hexadecimal") from error


def _classify_body(
    declared_length: Optional[int], extracted_length: int, limit_truncated: bool
) -> str:
    if limit_truncated:
        return "limit-truncated"
    if extracted_length == 0:
        if declared_length == 0:
            return "empty"
        if declared_length is None:
            return "absent"
        return "missing"
    if declared_length is None or extracted_length == declared_length:
        return "complete"
    if extracted_length < declared_length:
        return "partial"
    return "length-mismatch"


def _persist_batch_body(
    project: ProjectInfo,
    database: Database,
    row: object,
    tool_run_id: int,
    data: bytes,
    *,
    limit_truncated: bool,
) -> BodyExtractionSummary:
    declared_value = row["content_length"]
    declared_length = int(declared_value) if declared_value is not None else None
    body_status = _classify_body(declared_length, len(data), limit_truncated)
    blob_sha256: Optional[str] = None
    blob_path: Optional[str] = None
    public_evidence_id: Optional[str] = None
    evidence_db_id: Optional[int] = None
    if data:
        blob = BlobStore(project.root / "blobs").put_bytes(data)
        relative_path = blob.path.relative_to(project.root).as_posix()
        locator = EvidenceLocator(
            capture_sha256=project.capture_sha256,
            source_kind="http-body",
            frame_start=int(row["representative_frame"]),
            frame_end=int(row["representative_frame"]),
            protocol_message=str(row["message_id"]),
            byte_offset=0,
            byte_length=blob.byte_length,
        )
        public_evidence_id = evidence_id(locator)
        with database.connect() as connection:
            capture_db_id = int(
                connection.execute(
                    "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT INTO blob (sha256,byte_length,relative_path,complete,created_at) "
                "VALUES (?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
                "complete=max(blob.complete,excluded.complete)",
                (
                    blob.sha256,
                    blob.byte_length,
                    relative_path,
                    int(body_status == "complete"),
                    _utc_now(),
                ),
            )
            blob_db_id = int(
                connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[
                    0
                ]
            )
            connection.execute(
                "INSERT OR IGNORE INTO evidence "
                "(evidence_id,capture_id,source_kind,frame_start,frame_end,"
                "protocol_message_id,byte_offset,byte_length,blob_id,locator_json) "
                "VALUES (?,?,'http-body',?,?,?,?,?,?,?)",
                (
                    public_evidence_id,
                    capture_db_id,
                    row["representative_frame"],
                    row["representative_frame"],
                    row["id"],
                    0,
                    blob.byte_length,
                    blob_db_id,
                    json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
                ),
            )
            evidence_db_id = int(
                connection.execute(
                    "SELECT id FROM evidence WHERE evidence_id=?", (public_evidence_id,)
                ).fetchone()[0]
            )
        blob_sha256 = blob.sha256
        blob_path = str(blob.path)
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO http_body "
            "(protocol_message_id,evidence_id,tool_run_id,declared_length,extracted_length,"
            "status,truncated,updated_at) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(protocol_message_id) DO UPDATE SET "
            "evidence_id=excluded.evidence_id,tool_run_id=excluded.tool_run_id,"
            "declared_length=excluded.declared_length,"
            "extracted_length=excluded.extracted_length,status=excluded.status,"
            "truncated=excluded.truncated,error=NULL,updated_at=excluded.updated_at",
            (
                row["id"],
                evidence_db_id,
                tool_run_id,
                declared_length,
                len(data),
                body_status,
                int(limit_truncated),
                _utc_now(),
            ),
        )
    return BodyExtractionSummary(
        project=str(project.root),
        frame_number=int(row["representative_frame"]),
        message_kind=str(row["message_kind"]),
        status=body_status,
        declared_length=declared_length,
        extracted_length=len(data),
        truncated=limit_truncated,
        sha256=blob_sha256,
        blob_path=blob_path,
        evidence_id=public_evidence_id,
    )


def extract_http_bodies_batch(
    project_path: Path,
    frame_numbers: Sequence[int],
    tshark: Path,
    *,
    max_body_bytes: int,
    max_total_bytes: int,
    capabilities: Optional[TsharkCapabilities] = None,
    tls_rsa_key: Optional[TlsRsaKey] = None,
) -> BodyBatchExtractionSummary:
    frames = tuple(dict.fromkeys(int(frame) for frame in frame_numbers))
    if not frames or any(frame <= 0 for frame in frames):
        raise ValueError("batch body frames must be positive")
    if max_body_bytes <= 0 or max_total_bytes <= 0:
        raise ValueError("batch body limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = capabilities or probe_tshark(tshark)
    if not capabilities.usable or not capabilities.features.get("http", False):
        raise ValueError("TShark lacks required HTTP body capability")
    placeholders = ",".join("?" for _ in frames)
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT pm.id,pm.message_id,pm.message_kind,pm.representative_frame,"
            "hm.content_length FROM protocol_message pm "
            "JOIN http_message hm ON hm.protocol_message_id=pm.id "
            f"WHERE pm.protocol='http' AND pm.representative_frame IN ({placeholders})",
            frames,
        ).fetchall()
    by_frame = {int(row["representative_frame"]): row for row in rows}
    missing_rows = [frame for frame in frames if frame not in by_frame]
    if missing_rows:
        raise ValueError(f"frames are not indexed HTTP messages: {missing_rows[:8]}")

    preferences = tls_rsa_key.arguments if tls_rsa_key is not None else ()
    argv = _batch_body_arguments(
        tshark, project.capture_path, frames, preferences=preferences
    )
    provenance_argv = tls_rsa_key.redact_argv(argv) if tls_rsa_key is not None else argv
    run_public_id = uuid4().hex
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run "
            "(run_id,tool_name,tool_version,argv_json,capability_json,started_at,status) "
            "VALUES (?,'tshark-http-body-batch',?,?,?,?,'running')",
            (
                run_public_id,
                capabilities.version_line,
                json.dumps(provenance_argv, ensure_ascii=False),
                capabilities.to_provenance_json(tls_rsa_key=tls_rsa_key),
                _utc_now(),
            ),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])

    remaining = max_total_bytes
    seen: set[int] = set()
    statuses: list[BodyExtractionSummary] = []
    skipped: list[int] = []
    result = None
    run_status = "failed"

    def consume(line: bytes) -> None:
        nonlocal remaining
        frame_number, data = _parse_batch_body_line(line)
        if frame_number not in by_frame:
            raise ValueError(f"unexpected HTTP body frame {frame_number}")
        if frame_number in seen:
            raise ValueError(f"duplicate HTTP body frame {frame_number}")
        seen.add(frame_number)
        if remaining <= 0:
            skipped.append(frame_number)
            return
        allocation = min(max_body_bytes, remaining)
        limited = len(data) > allocation
        selected = data[:allocation]
        status = _persist_batch_body(
            project,
            database,
            by_frame[frame_number],
            tool_run_id,
            selected,
            limit_truncated=limited,
        )
        statuses.append(status)
        remaining -= len(selected)

    try:
        result = run_streaming_lines(
            argv,
            consume,
            timeout_seconds=300,
            max_line_bytes=2 * max_body_bytes + 4096,
            stderr_limit=512 * 1024,
        )
        if result.timed_out:
            raise TimeoutError("TShark batch HTTP body extraction timed out")
        if result.output_limit_exceeded:
            raise ValueError("TShark batch HTTP body output exceeded the per-body limit")
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(
                f"TShark batch body extraction exited {result.returncode}: {detail[:500]}"
            )
        unseen = [frame for frame in frames if frame not in seen]
        if unseen:
            raise ValueError(f"TShark omitted requested HTTP body frames: {unseen[:8]}")
        run_status = "completed"
        order = {frame: index for index, frame in enumerate(frames)}
        return BodyBatchExtractionSummary(
            statuses=tuple(sorted(statuses, key=lambda item: order[item.frame_number])),
            skipped_frames=tuple(sorted(skipped, key=order.__getitem__)),
        )
    finally:
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
                "stderr_truncated=? WHERE run_id=?",
                (
                    _utc_now(),
                    run_status,
                    result.returncode if result is not None else None,
                    (
                        result.stderr.decode("utf-8", errors="replace")
                        if result is not None
                        else "batch body extraction failed; see caller error"
                    ),
                    int(result.stderr_truncated) if result is not None else 0,
                    run_public_id,
                ),
            )


def extract_http_body(
    project_path: Path,
    frame_number: int,
    tshark: Path,
    *,
    max_body_bytes: int,
    capabilities: Optional[TsharkCapabilities] = None,
    tls_rsa_key: Optional[TlsRsaKey] = None,
) -> BodyExtractionSummary:
    if frame_number <= 0:
        raise ValueError("frame number must be positive")
    if max_body_bytes <= 0:
        raise ValueError("max body bytes must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = capabilities or probe_tshark(tshark)
    if not capabilities.usable or not capabilities.features.get("http", False):
        raise ValueError("TShark lacks required HTTP body capability")
    with database.connect() as connection:
        row = connection.execute(
            "SELECT pm.id, pm.message_id, pm.message_kind, hm.content_length "
            "FROM protocol_message pm JOIN http_message hm ON hm.protocol_message_id = pm.id "
            "WHERE pm.representative_frame = ? AND pm.protocol = 'http'",
            (frame_number,),
        ).fetchone()
    if row is None:
        raise ValueError(f"frame {frame_number} is not an indexed HTTP message")

    preferences = tls_rsa_key.arguments if tls_rsa_key is not None else ()
    argv = _body_arguments(
        tshark, project.capture_path, frame_number, preferences=preferences
    )
    provenance_argv = tls_rsa_key.redact_argv(argv) if tls_rsa_key is not None else argv
    run_public_id = uuid4().hex
    started_at = _utc_now()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run "
            "(run_id, tool_name, tool_version, argv_json, capability_json, "
            "started_at, status) VALUES (?, 'tshark', ?, ?, ?, ?, 'running')",
            (
                run_public_id,
                capabilities.version_line,
                json.dumps(provenance_argv, ensure_ascii=False),
                capabilities.to_provenance_json(tls_rsa_key=tls_rsa_key),
                started_at,
            ),
        )
        tool_run_id = int(
            connection.execute(
                "SELECT id FROM tool_run WHERE run_id = ?", (run_public_id,)
            ).fetchone()[0]
        )

    jobs = project.root / "jobs"
    jobs.mkdir(exist_ok=True)
    temporary_path: Optional[Path] = None
    result = None
    status = "failed"
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix="http-body-", dir=str(jobs))
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as target:
            result = run_hex_to_file(
                argv,
                target,
                timeout_seconds=300,
                max_decoded_bytes=max_body_bytes,
                stderr_limit=512 * 1024,
                ignored_tokens=(b"<MISSING>",),
            )
        if result.timed_out:
            raise TimeoutError("TShark HTTP body extraction timed out")
        if result.returncode != 0 and not result.limit_truncated:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"TShark body extraction exited {result.returncode}: {detail[:500]}")
        declared_length = row["content_length"]
        body_status = _classify_body(
            int(declared_length) if declared_length is not None else None,
            result.decoded_bytes,
            result.limit_truncated,
        )
        blob_sha256: Optional[str] = None
        blob_path: Optional[str] = None
        public_evidence_id: Optional[str] = None
        evidence_db_id: Optional[int] = None
        if result.decoded_bytes > 0:
            with temporary_path.open("rb") as source:
                blob = BlobStore(project.root / "blobs").put_stream(source)
            relative_path = blob.path.relative_to(project.root).as_posix()
            locator = EvidenceLocator(
                capture_sha256=project.capture_sha256,
                source_kind="http-body",
                frame_start=frame_number,
                frame_end=frame_number,
                protocol_message=str(row["message_id"]),
                byte_offset=0,
                byte_length=blob.byte_length,
            )
            public_evidence_id = evidence_id(locator)
            with database.connect() as connection:
                capture_db_id = int(
                    connection.execute(
                        "SELECT id FROM capture WHERE sha256 = ?", (project.capture_sha256,)
                    ).fetchone()[0]
                )
                connection.execute(
                    "INSERT INTO blob "
                    "(sha256, byte_length, relative_path, complete, created_at) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(sha256) DO UPDATE SET "
                    "complete = max(blob.complete, excluded.complete)",
                    (
                        blob.sha256,
                        blob.byte_length,
                        relative_path,
                        int(body_status == "complete"),
                        _utc_now(),
                    ),
                )
                blob_db_id = int(
                    connection.execute(
                        "SELECT id FROM blob WHERE sha256 = ?", (blob.sha256,)
                    ).fetchone()[0]
                )
                connection.execute(
                    "INSERT OR IGNORE INTO evidence "
                    "(evidence_id, capture_id, source_kind, frame_start, frame_end, "
                    "protocol_message_id, byte_offset, byte_length, blob_id, locator_json) "
                    "VALUES (?, ?, 'http-body', ?, ?, ?, 0, ?, ?, ?)",
                    (
                        public_evidence_id,
                        capture_db_id,
                        frame_number,
                        frame_number,
                        row["id"],
                        blob.byte_length,
                        blob_db_id,
                        json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
                    ),
                )
                evidence_db_id = int(
                    connection.execute(
                        "SELECT id FROM evidence WHERE evidence_id = ?", (public_evidence_id,)
                    ).fetchone()[0]
                )
            blob_sha256 = blob.sha256
            blob_path = str(blob.path)
        with database.connect() as connection:
            connection.execute(
                "INSERT INTO http_body "
                "(protocol_message_id, evidence_id, tool_run_id, declared_length, "
                "extracted_length, status, truncated, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(protocol_message_id) DO UPDATE SET "
                "evidence_id=excluded.evidence_id, tool_run_id=excluded.tool_run_id, "
                "declared_length=excluded.declared_length, "
                "extracted_length=excluded.extracted_length, status=excluded.status, "
                "truncated=excluded.truncated, error=NULL, updated_at=excluded.updated_at",
                (
                    row["id"],
                    evidence_db_id,
                    tool_run_id,
                    declared_length,
                    result.decoded_bytes,
                    body_status,
                    int(result.limit_truncated),
                    _utc_now(),
                ),
            )
        status = "completed"
        return BodyExtractionSummary(
            project=str(project.root),
            frame_number=frame_number,
            message_kind=str(row["message_kind"]),
            status=body_status,
            declared_length=int(declared_length) if declared_length is not None else None,
            extracted_length=result.decoded_bytes,
            truncated=result.limit_truncated,
            sha256=blob_sha256,
            blob_path=blob_path,
            evidence_id=public_evidence_id,
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at = ?, status = ?, exit_code = ?, "
                "stderr_text = ?, stderr_truncated = ? WHERE run_id = ?",
                (
                    _utc_now(),
                    status,
                    result.returncode if result is not None else None,
                    (
                        result.stderr.decode("utf-8", errors="replace")
                        if result is not None
                        else "body extraction failed; see caller error"
                    ),
                    int(result.stderr_truncated) if result is not None else 0,
                    run_public_id,
                ),
            )
