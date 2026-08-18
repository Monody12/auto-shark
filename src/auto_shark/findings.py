"""Bounded multipart correlation and static protocol-result findings."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .core.ids import EvidenceLocator, evidence_id, stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import TsharkCapabilities, probe_tshark
from .project import inspect_project
from .protocols.multipart import (
    MultipartPartHeader,
    parse_multipart_line,
    tshark_multipart_arguments,
)
from .storage import Database

DETECTOR_VERSION = "1"
SUCCESS_PATTERN = re.compile(
    rb"\b(?:upload(?:ed)?[ \t_-]+success(?:ful(?:ly)?)?|success(?:ful(?:ly)?)?)\b",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class MultipartFindingSummary:
    multipart_parts: int
    multipart_resolved: int
    multipart_unresolved: int
    type_mismatch_findings: int
    contradiction_findings: int
    body_scans_skipped: int
    tool_run_id: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _record_tool_run(
    connection: sqlite3.Connection,
    capabilities: TsharkCapabilities,
    argv: list[str],
) -> tuple[int, str]:
    public_id = uuid4().hex
    connection.execute(
        "INSERT INTO tool_run "
        "(run_id,tool_name,tool_version,argv_json,capability_json,started_at,status) "
        "VALUES(?,?,?,?,?,?,'running')",
        (
            public_id,
            "tshark",
            capabilities.version_line,
            json.dumps(argv, ensure_ascii=False),
            capabilities.to_provenance_json(),
            _now(),
        ),
    )
    database_id = int(
        connection.execute(
            "SELECT id FROM tool_run WHERE run_id=?", (public_id,)
        ).fetchone()[0]
    )
    return database_id, public_id


def _persist_part(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    capture_sha256: str,
    tool_run_id: int,
    part: MultipartPartHeader,
) -> bool:
    message = connection.execute(
        "SELECT id,message_id FROM protocol_message "
        "WHERE capture_id=? AND protocol='http' AND representative_frame=?",
        (capture_id, part.frame_number),
    ).fetchone()
    if message is None:
        return False
    public_id = stable_id(
        "multipart-part",
        {
            "capture_sha256": capture_sha256,
            "message_id": str(message["message_id"]),
            "ordinal": part.ordinal,
        },
    )
    detail = {"disposition": part.disposition, "frame_number": part.frame_number}
    connection.execute(
        "INSERT INTO multipart_part "
        "(part_id,protocol_message_id,tool_run_id,ordinal,field_name,filename,"
        "declared_media_type,status,detail_json,updated_at) "
        "VALUES(?,?,?,?,?,?,?,'indexed',?,?) "
        "ON CONFLICT(protocol_message_id,ordinal) DO UPDATE SET "
        "tool_run_id=excluded.tool_run_id,field_name=excluded.field_name,"
        "filename=excluded.filename,declared_media_type=excluded.declared_media_type,"
        "status='indexed',detail_json=excluded.detail_json,updated_at=excluded.updated_at",
        (
            public_id,
            int(message["id"]),
            tool_run_id,
            part.ordinal,
            part.field_name,
            part.filename,
            part.declared_media_type,
            json.dumps(detail, sort_keys=True),
            _now(),
        ),
    )
    return True


def _create_finding(
    connection: sqlite3.Connection,
    *,
    detector: str,
    title: str,
    description: str,
    severity: str,
    confidence: float,
    evidence_ids: list[tuple[int, str]],
    tool_run_id: int,
) -> bool:
    evidence_public_ids = [
        str(
            connection.execute(
                "SELECT evidence_id FROM evidence WHERE id=?", (item[0],)
            ).fetchone()[0]
        )
        for item in evidence_ids
    ]
    public_id = stable_id(
        "finding",
        {
            "detector": detector,
            "detector_version": DETECTOR_VERSION,
            "evidence_ids": sorted(evidence_public_ids),
        },
    )
    existing = connection.execute(
        "SELECT id FROM finding WHERE finding_id=?", (public_id,)
    ).fetchone()
    connection.execute(
        "INSERT INTO finding "
        "(finding_id,detector,detector_version,title,description,severity,confidence,"
        "recommended_action,created_at) VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(finding_id) DO UPDATE SET title=excluded.title,"
        "description=excluded.description,severity=excluded.severity,"
        "confidence=excluded.confidence,recommended_action=excluded.recommended_action",
        (
            public_id,
            detector,
            DETECTOR_VERSION,
            title,
            description,
            severity,
            confidence,
            "Review the linked original evidence without executing extracted content.",
            _now(),
        ),
    )
    finding_id = int(
        connection.execute(
            "SELECT id FROM finding WHERE finding_id=?", (public_id,)
        ).fetchone()[0]
    )
    for evidence_db_id, role in evidence_ids:
        connection.execute(
            "INSERT OR IGNORE INTO finding_evidence(finding_id,evidence_id,role) "
            "VALUES(?,?,?)",
            (finding_id, evidence_db_id, role),
        )
    connection.execute(
        "INSERT OR IGNORE INTO finding_run(finding_id,tool_run_id) VALUES(?,?)",
        (finding_id, tool_run_id),
    )
    return existing is None


def _correlate_parts(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    tool_run_id: int,
) -> tuple[int, int, int]:
    resolved = unresolved = mismatch_findings = 0
    message_ids = [
        int(row[0])
        for row in connection.execute(
            "SELECT DISTINCT mp.protocol_message_id FROM multipart_part mp "
            "JOIN protocol_message pm ON pm.id=mp.protocol_message_id "
            "WHERE pm.capture_id=?",
            (capture_id,),
        )
    ]
    for message_id in message_ids:
        parts = connection.execute(
            "SELECT * FROM multipart_part WHERE protocol_message_id=? ORDER BY ordinal",
            (message_id,),
        ).fetchall()
        carves = connection.execute(
            "SELECT fc.id carve_db_id,fc.artifact_id,a.detected_media_type,"
            "a.source_evidence_id FROM file_carve fc "
            "JOIN evidence parent ON parent.id=fc.parent_evidence_id "
            "JOIN artifact a ON a.id=fc.artifact_id "
            "WHERE parent.protocol_message_id=?",
            (message_id,),
        ).fetchall()
        for part in parts:
            connection.execute(
                "DELETE FROM multipart_part_artifact WHERE part_id=?", (part["id"],)
            )
        if len(parts) != 1 or len(carves) != 1:
            for part in parts:
                detail = {"part_count": len(parts), "carve_count": len(carves)}
                connection.execute(
                    "UPDATE multipart_part SET status='unresolved',detail_json=?,"
                    "updated_at=? WHERE id=?",
                    (json.dumps(detail, sort_keys=True), _now(), part["id"]),
                )
                connection.execute(
                    "INSERT INTO multipart_part_artifact "
                    "(part_id,artifact_id,carve_id,role,detail_json) "
                    "VALUES(?,NULL,NULL,'unresolved',?)",
                    (part["id"], json.dumps(detail, sort_keys=True)),
                )
                unresolved += 1
            continue
        part, carve = parts[0], carves[0]
        declared = str(part["declared_media_type"] or "").lower()
        detected = str(carve["detected_media_type"] or "").lower()
        role = "type-mismatch" if declared and detected and declared != detected else "matched"
        detail = {"declared_media_type": declared or None, "detected_media_type": detected or None}
        connection.execute(
            "INSERT INTO multipart_part_artifact "
            "(part_id,artifact_id,carve_id,role,detail_json) VALUES(?,?,?,?,?)",
            (
                part["id"],
                carve["artifact_id"],
                carve["carve_db_id"],
                role,
                json.dumps(detail, sort_keys=True),
            ),
        )
        connection.execute(
            "UPDATE multipart_part SET status='resolved',detail_json=?,updated_at=? "
            "WHERE id=?",
            (json.dumps(detail, sort_keys=True), _now(), part["id"]),
        )
        connection.execute(
            "UPDATE artifact SET declared_media_type=coalesce(declared_media_type,?) "
            "WHERE id=?",
            (declared or None, carve["artifact_id"]),
        )
        resolved += 1
        if role == "type-mismatch":
            mismatch_findings += int(
                _create_finding(
                    connection,
                    detector="declared-actual-type-mismatch",
                    title="Declared and detected file types differ",
                    description=f"Multipart declares {declared}; static carve detects {detected}.",
                    severity="medium",
                    confidence=0.95,
                    evidence_ids=[(int(carve["source_evidence_id"]), "artifact")],
                    tool_run_id=tool_run_id,
                )
            )
    return resolved, unresolved, mismatch_findings


def _scan_contradictions(
    connection: sqlite3.Connection,
    *,
    project_root: Path,
    capture_id: int,
    capture_sha256: str,
    tool_run_id: int,
    max_body_scan_bytes: int,
) -> tuple[int, int]:
    findings = skipped = 0
    rows = connection.execute(
        "SELECT pm.id message_db_id,pm.message_id,pm.representative_frame,"
        "hm.response_code,hb.status,hb.truncated,hb.extracted_length,"
        "e.id evidence_db_id,e.byte_offset,b.id blob_db_id,b.relative_path "
        "FROM protocol_message pm JOIN http_message hm ON hm.protocol_message_id=pm.id "
        "JOIN http_body hb ON hb.protocol_message_id=pm.id "
        "LEFT JOIN evidence e ON e.id=hb.evidence_id "
        "LEFT JOIN blob b ON b.id=e.blob_id "
        "WHERE pm.capture_id=? AND pm.message_kind='response' "
        "AND hm.response_code BETWEEN 500 AND 599",
        (capture_id,),
    ).fetchall()
    for row in rows:
        if (
            row["status"] != "complete"
            or int(row["truncated"]) != 0
            or row["relative_path"] is None
            or int(row["extracted_length"]) > max_body_scan_bytes
        ):
            skipped += 1
            continue
        path = project_root / str(row["relative_path"])
        with path.open("rb") as stream:
            body = stream.read(int(row["extracted_length"]) + 1)
        if len(body) != int(row["extracted_length"]):
            skipped += 1
            continue
        match = SUCCESS_PATTERN.search(body)
        if match is None:
            continue
        locator = EvidenceLocator(
            capture_sha256=capture_sha256,
            source_kind="http-result-semantic",
            frame_start=int(row["representative_frame"]),
            frame_end=int(row["representative_frame"]),
            protocol_message=str(row["message_id"]),
            byte_offset=match.start(),
            byte_length=match.end() - match.start(),
        )
        public_evidence_id = evidence_id(locator)
        connection.execute(
            "INSERT OR IGNORE INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "protocol_message_id,byte_offset,byte_length,text_value,blob_id,locator_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                public_evidence_id,
                capture_id,
                "http-result-semantic",
                row["representative_frame"],
                row["representative_frame"],
                row["message_db_id"],
                match.start(),
                match.end() - match.start(),
                match.group(0).decode("ascii", errors="replace"),
                row["blob_db_id"],
                json.dumps(locator.payload(), sort_keys=True),
            ),
        )
        evidence_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?", (public_evidence_id,)
            ).fetchone()[0]
        )
        findings += int(
            _create_finding(
                connection,
                detector="http-status-body-contradiction",
                title="HTTP error status contradicts response body",
                description=(
                    f"HTTP {int(row['response_code'])} response contains a success semantic."
                ),
                severity="high",
                confidence=0.95,
                evidence_ids=[(evidence_db_id, "success-semantic")],
                tool_run_id=tool_run_id,
            )
        )
    return findings, skipped


def index_multipart_findings(
    project_path: Path,
    tshark: Path,
    *,
    max_parts: int = 10_000,
    max_body_scan_bytes: int = 4 * 1024 * 1024,
) -> MultipartFindingSummary:
    if min(max_parts, max_body_scan_bytes) <= 0:
        raise ValueError("multipart finding limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = probe_tshark(tshark)
    if not capabilities.usable or not capabilities.features.get("multipart", False):
        raise ValueError("TShark lacks required multipart fields")
    argv = tshark_multipart_arguments(tshark, project.capture_path)
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        tool_run_id, tool_run_public_id = _record_tool_run(connection, capabilities, argv)
    parts_seen = 0
    result = None
    status = "failed"
    try:
        with database.connect() as connection:

            def consume(line: bytes) -> None:
                nonlocal parts_seen
                for part in parse_multipart_line(line):
                    if parts_seen >= max_parts:
                        raise ValueError("multipart part limit reached")
                    parts_seen += int(
                        _persist_part(
                            connection,
                            capture_id=capture_id,
                            capture_sha256=project.capture_sha256,
                            tool_run_id=tool_run_id,
                            part=part,
                        )
                    )

            result = run_streaming_lines(
                argv,
                consume,
                timeout_seconds=300,
                max_line_bytes=1024 * 1024,
                stderr_limit=512 * 1024,
            )
            if result.timed_out:
                raise TimeoutError("TShark multipart metadata timed out")
            if result.output_limit_exceeded:
                raise ValueError("TShark multipart metadata line limit exceeded")
            if result.returncode != 0:
                raise ValueError(f"TShark multipart metadata exited {result.returncode}")
            resolved, unresolved, mismatches = _correlate_parts(
                connection, capture_id=capture_id, tool_run_id=tool_run_id
            )
            contradictions, skipped = _scan_contradictions(
                connection,
                project_root=project.root,
                capture_id=capture_id,
                capture_sha256=project.capture_sha256,
                tool_run_id=tool_run_id,
                max_body_scan_bytes=max_body_scan_bytes,
            )
        status = "completed"
    finally:
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
                "stderr_truncated=? WHERE id=?",
                (
                    _now(),
                    status,
                    result.returncode if result else None,
                    result.stderr.decode("utf-8", errors="replace")
                    if result
                    else "multipart finding indexing failed",
                    int(result.stderr_truncated) if result else 0,
                    tool_run_id,
                ),
            )
    return MultipartFindingSummary(
        multipart_parts=parts_seen,
        multipart_resolved=resolved,
        multipart_unresolved=unresolved,
        type_mismatch_findings=mismatches,
        contradiction_findings=contradictions,
        body_scans_skipped=skipped,
        tool_run_id=tool_run_public_id,
    )
