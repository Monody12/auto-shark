"""On-demand HTTP body extraction with evidence and blob provenance."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import EvidenceLocator, evidence_id
from .engines.hexstream import run_hex_to_file
from .engines.tshark import TsharkCapabilities, probe_tshark
from .project import inspect_project
from .storage import BlobStore, Database


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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _body_arguments(tshark: Path, capture: Path, frame_number: int) -> list[str]:
    return [
        str(tshark),
        "-2",
        "-r",
        str(capture),
        "-Y",
        f"frame.number == {frame_number}",
        "-T",
        "fields",
        "-E",
        "occurrence=f",
        "-e",
        "http.file_data",
    ]


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


def extract_http_body(
    project_path: Path,
    frame_number: int,
    tshark: Path,
    *,
    max_body_bytes: int,
    capabilities: Optional[TsharkCapabilities] = None,
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

    argv = _body_arguments(tshark, project.capture_path, frame_number)
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
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_json(),
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
