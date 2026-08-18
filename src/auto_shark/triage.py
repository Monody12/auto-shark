"""Bounded triage over current project evidence with explainable ranking."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .core.ids import EvidenceLocator, candidate_id, evidence_id, stable_id
from .project import inspect_project
from .search import ByteMatch, scan_flag_matches
from .storage import Database

DETECTOR = "bounded-triage"
DETECTOR_VERSION = "1"
SENSITIVE_FIELDS = {
    "api_key",
    "key",
    "passphrase",
    "passwd",
    "password",
    "secret",
    "token",
}
PASSWORD_FIELDS = {"passphrase", "passwd", "password"}
PLACEHOLDERS = {
    "********",
    "changeme",
    "none",
    "null",
    "password",
    "secret",
    "test",
    "undefined",
    "your_password",
}
HEX_VALUE = re.compile(r"[0-9a-fA-F]+")
BASE64_VALUE = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
KNOWN_PREFIX = re.compile(r"^\{?(flag|ctf|key|answer)(?:\{|[:=])", re.IGNORECASE)


@dataclass(frozen=True)
class RankedCandidate:
    candidate_id: str
    kind: str
    value: str
    confidence: float
    rank_score: float


@dataclass(frozen=True)
class TriageSummary:
    schema_version: str
    project: str
    evidence_selected: int
    evidence_scanned: int
    scanned_bytes: int
    complete: int
    input_truncated: int
    candidate_limited: int
    skipped_budget: int
    skipped_limit: int
    failed: int
    known_matches: int
    field_candidates: int
    candidates: tuple[RankedCandidate, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class _TriageInput:
    evidence_db_id: int
    evidence_public_id: str
    capture_id: int
    protocol_message_id: Optional[int]
    transaction_id: Optional[int]
    source_kind: str
    input_kind: str
    frame_start: Optional[int]
    frame_end: Optional[int]
    direction: Optional[str]
    blob_id: int
    blob_sha256: str
    blob_length: int
    relative_path: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _policy_json(
    *,
    max_evidence: int,
    max_evidence_bytes: int,
    max_total_bytes: int,
    max_matches_per_evidence: int,
    max_candidates: int,
    max_field_bytes: int,
    window_bytes: int,
) -> str:
    return json.dumps(
        {
            "max_candidates": max_candidates,
            "max_evidence": max_evidence,
            "max_evidence_bytes": max_evidence_bytes,
            "max_field_bytes": max_field_bytes,
            "max_matches_per_evidence": max_matches_per_evidence,
            "max_total_bytes": max_total_bytes,
            "window_bytes": window_bytes,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _current_inputs(database: Database) -> tuple[_TriageInput, ...]:
    query = """
        SELECT e.id evidence_db_id,e.evidence_id evidence_public_id,e.capture_id,
               e.protocol_message_id,e.transaction_id,e.source_kind,'evidence' input_kind,
               e.frame_start,e.frame_end,e.direction,b.id blob_id,b.sha256 blob_sha256,
               b.byte_length blob_length,b.relative_path
        FROM http_body hb JOIN evidence e ON e.id=hb.evidence_id
        JOIN blob b ON b.id=e.blob_id
        WHERE hb.extracted_length>0
        UNION
        SELECT e.id,e.evidence_id,e.capture_id,e.protocol_message_id,e.transaction_id,
               e.source_kind,'evidence',e.frame_start,e.frame_end,e.direction,
               b.id,b.sha256,b.byte_length,b.relative_path
        FROM transform t JOIN evidence e ON e.id=t.output_evidence_id
        JOIN blob b ON b.id=e.blob_id
        WHERE t.status='complete' AND t.truncated=0 AND e.byte_length=b.byte_length
        UNION
        SELECT e.id,e.evidence_id,e.capture_id,e.protocol_message_id,e.transaction_id,
               e.source_kind,'artifact',e.frame_start,e.frame_end,e.direction,
               b.id,b.sha256,b.byte_length,b.relative_path
        FROM file_carve fc JOIN evidence e ON e.id=fc.carved_evidence_id
        JOIN artifact a ON a.id=fc.artifact_id JOIN blob b ON b.id=a.blob_id
        WHERE fc.structural_status IN ('validated','signature-only') AND b.complete=1
        UNION
        SELECT e.id,e.evidence_id,e.capture_id,e.protocol_message_id,e.transaction_id,
               e.source_kind,'evidence',e.frame_start,e.frame_end,e.direction,
               b.id,b.sha256,b.byte_length,b.relative_path
        FROM tcp_reconstruction tr JOIN evidence e ON e.id=tr.evidence_id
        JOIN blob b ON b.id=e.blob_id
        UNION
        SELECT e.id,e.evidence_id,e.capture_id,e.protocol_message_id,e.transaction_id,
               e.source_kind,'evidence',e.frame_start,e.frame_end,e.direction,
               b.id,b.sha256,b.byte_length,b.relative_path
        FROM evidence e JOIN blob b ON b.id=e.blob_id
        WHERE e.source_kind='tftp-data' AND b.complete=1
        UNION
        SELECT e.id,e.evidence_id,e.capture_id,e.protocol_message_id,e.transaction_id,
               e.source_kind,'artifact',e.frame_start,e.frame_end,e.direction,
               b.id,b.sha256,b.byte_length,b.relative_path
        FROM evidence e JOIN blob b ON b.id=e.blob_id
        WHERE e.source_kind='smtp-attachment' AND b.complete=1
        ORDER BY evidence_public_id,input_kind,blob_sha256
    """
    with database.connect() as connection:
        rows = connection.execute(query).fetchall()
    return tuple(
        _TriageInput(
            evidence_db_id=int(row["evidence_db_id"]),
            evidence_public_id=str(row["evidence_public_id"]),
            capture_id=int(row["capture_id"]),
            protocol_message_id=(
                int(row["protocol_message_id"]) if row["protocol_message_id"] is not None else None
            ),
            transaction_id=(
                int(row["transaction_id"]) if row["transaction_id"] is not None else None
            ),
            source_kind=str(row["source_kind"]),
            input_kind=str(row["input_kind"]),
            frame_start=(int(row["frame_start"]) if row["frame_start"] is not None else None),
            frame_end=(int(row["frame_end"]) if row["frame_end"] is not None else None),
            direction=str(row["direction"]) if row["direction"] is not None else None,
            blob_id=int(row["blob_id"]),
            blob_sha256=str(row["blob_sha256"]),
            blob_length=int(row["blob_length"]),
            relative_path=str(row["relative_path"]),
        )
        for row in rows
    )


def _project_blob_path(project_root: Path, relative_path: str) -> Path:
    path = (project_root / relative_path).resolve()
    try:
        path.relative_to(project_root.resolve())
    except ValueError as error:
        raise ValueError("blob path escapes the analysis project") from error
    if not path.is_file():
        raise FileNotFoundError(str(path))
    return path


def _persist_scan(
    database: Database,
    item: _TriageInput,
    *,
    policy_json: str,
    max_bytes: int,
    scanned_bytes: int,
    matches: int,
    status: str,
    error: Optional[str] = None,
) -> None:
    public_id = stable_id(
        "triage-scan",
        {
            "detector": DETECTOR,
            "detector_version": DETECTOR_VERSION,
            "evidence_id": item.evidence_public_id,
            "input_blob_sha256": item.blob_sha256,
            "policy": json.loads(policy_json),
        },
    )
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO triage_scan "
            "(scan_id,evidence_id,detector,detector_version,policy_json,max_bytes,"
            "scanned_bytes,matches,status,error,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(evidence_id,detector,detector_version,policy_json) DO UPDATE SET "
            "scan_id=excluded.scan_id,max_bytes=excluded.max_bytes,"
            "scanned_bytes=excluded.scanned_bytes,matches=excluded.matches,"
            "status=excluded.status,error=excluded.error,updated_at=excluded.updated_at",
            (
                public_id,
                item.evidence_db_id,
                DETECTOR,
                DETECTOR_VERSION,
                policy_json,
                max_bytes,
                scanned_bytes,
                matches,
                status,
                error,
                _utc_now(),
            ),
        )


def _tcp_frames(database: Database, evidence_db_id: int, start: int, length: int) -> list[int]:
    end = start + length
    with database.connect() as connection:
        return [
            int(row[0])
            for row in connection.execute(
                "SELECT DISTINCT ts.frame_number FROM tcp_reconstruction tr "
                "JOIN tcp_reconstruction_source trs ON trs.reconstruction_id=tr.id "
                "JOIN tcp_segment ts ON ts.id=trs.segment_id "
                "WHERE tr.evidence_id=? AND trs.role='primary' "
                "AND trs.output_offset<? AND trs.output_offset+trs.byte_length>? "
                "ORDER BY ts.frame_number",
                (evidence_db_id, end, start),
            )
        ]


def _persist_signal(
    connection: object,
    *,
    candidate_db_id: int,
    candidate_public_id: str,
    evidence_db_id: int,
    evidence_public_id: str,
    name: str,
    contribution: float,
    detail: dict[str, object],
) -> None:
    public_id = stable_id(
        "candidate-signal",
        {
            "candidate_id": candidate_public_id,
            "detector": DETECTOR,
            "detector_version": DETECTOR_VERSION,
            "evidence_id": evidence_public_id,
            "signal_name": name,
        },
    )
    connection.execute(
        "INSERT INTO candidate_signal "
        "(signal_id,candidate_id,evidence_id,detector,detector_version,signal_name,"
        "contribution,detail_json) VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(candidate_id,evidence_id,detector,detector_version,signal_name) "
        "DO UPDATE SET signal_id=excluded.signal_id,contribution=excluded.contribution,"
        "detail_json=excluded.detail_json",
        (
            public_id,
            candidate_db_id,
            evidence_db_id,
            DETECTOR,
            DETECTOR_VERSION,
            name,
            contribution,
            json.dumps(detail, ensure_ascii=False, sort_keys=True),
        ),
    )


def _upsert_candidate(
    connection: object,
    *,
    kind: str,
    value: str,
    score: float,
    evidence_db_id: int,
    evidence_public_id: str,
    evidence_role: str,
    signals: tuple[tuple[str, float, dict[str, object]], ...],
) -> str:
    normalized = value.strip()
    public_id = candidate_id(kind, normalized)
    confidence = min(0.99, max(0.0, score / 100.0))
    connection.execute(
        "INSERT INTO candidate "
        "(candidate_id,kind,raw_value,normalized_value,confidence,rank_score,created_at) "
        "VALUES (?,?,?,?,?,?,?) ON CONFLICT(candidate_id) DO UPDATE SET "
        "confidence=max(candidate.confidence,excluded.confidence),"
        "rank_score=max(candidate.rank_score,excluded.rank_score)",
        (public_id, kind, value, normalized, confidence, score, _utc_now()),
    )
    candidate_db_id = int(
        connection.execute(
            "SELECT id FROM candidate WHERE candidate_id=?", (public_id,)
        ).fetchone()[0]
    )
    connection.execute(
        "INSERT OR IGNORE INTO candidate_evidence (candidate_id,evidence_id,role) VALUES (?,?,?)",
        (candidate_db_id, evidence_db_id, evidence_role),
    )
    for name, contribution, detail in signals:
        _persist_signal(
            connection,
            candidate_db_id=candidate_db_id,
            candidate_public_id=public_id,
            evidence_db_id=evidence_db_id,
            evidence_public_id=evidence_public_id,
            name=name,
            contribution=contribution,
            detail=detail,
        )
    return public_id


def _persist_known_match(
    database: Database,
    capture_sha256: str,
    item: _TriageInput,
    match: ByteMatch,
) -> str:
    frames = (
        _tcp_frames(database, item.evidence_db_id, match.offset, len(match.value))
        if item.source_kind == "tcp-stream"
        else []
    )
    frame_start = min(frames) if frames else item.frame_start
    frame_end = max(frames) if frames else item.frame_end
    value = match.value.decode("utf-8", errors="replace")
    locator = EvidenceLocator(
        capture_sha256=capture_sha256,
        source_kind="flag-match",
        frame_start=frame_start,
        frame_end=frame_end,
        protocol_message=item.evidence_public_id,
        direction=item.direction,
        byte_offset=match.offset,
        byte_length=len(match.value),
    )
    match_public_id = evidence_id(locator)
    with database.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
            "transaction_id,direction,byte_offset,byte_length,text_value,blob_id,locator_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                match_public_id,
                item.capture_id,
                "flag-match",
                frame_start,
                frame_end,
                item.protocol_message_id,
                item.transaction_id,
                item.direction,
                match.offset,
                len(match.value),
                value,
                item.blob_id,
                json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
            ),
        )
        match_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?", (match_public_id,)
            ).fetchone()[0]
        )
        prefix_match = KNOWN_PREFIX.match(value)
        prefix = prefix_match.group(1).lower() if prefix_match else ""
        score = 100.0 if prefix == "flag" else 95.0
        return _upsert_candidate(
            connection,
            kind="flag",
            value=value,
            score=score,
            evidence_db_id=match_db_id,
            evidence_public_id=match_public_id,
            evidence_role="direct-match",
            signals=(
                (
                    "known-format",
                    score,
                    {
                        "contributing_frames": frames,
                        "input_evidence_id": item.evidence_public_id,
                        "length": len(match.value),
                        "offset": match.offset,
                        "prefix": prefix,
                    },
                ),
            ),
        )


def _field_shape(value: str) -> tuple[str, float]:
    if len(value) >= 16 and len(value) % 2 == 0 and HEX_VALUE.fullmatch(value):
        return "hex", 8.0
    if len(value) >= 8 and len(value) % 4 == 0 and BASE64_VALUE.fullmatch(value):
        return "base64-like", 6.0
    return "plain", 0.0


def _field_candidates(
    database: Database,
    project_root: Path,
    fully_scanned: set[int],
    remaining_candidates: int,
    max_field_bytes: int,
) -> tuple[int, set[str]]:
    if remaining_candidates <= 0:
        return 0, set()
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT ff.ordinal,ff.name,e.id evidence_db_id,e.evidence_id,e.frame_start,"
            "e.frame_end,b.relative_path,b.byte_length FROM form_field ff "
            "JOIN evidence e ON e.id=ff.decoded_value_evidence_id "
            "JOIN blob b ON b.id=e.blob_id JOIN http_body hb "
            "ON hb.protocol_message_id=ff.protocol_message_id "
            "WHERE hb.status='complete' AND EXISTS ("
            "SELECT 1 FROM form_field sensitive WHERE "
            "sensitive.protocol_message_id=ff.protocol_message_id "
            "AND lower(sensitive.name) IN (" + ",".join("?" for _ in SENSITIVE_FIELDS) + ")) "
            "ORDER BY e.frame_start,ff.protocol_message_id,ff.ordinal",
            tuple(sorted(SENSITIVE_FIELDS)),
        ).fetchall()
    count = 0
    public_ids: set[str] = set()
    for row in rows:
        evidence_db_id = int(row["evidence_db_id"])
        if evidence_db_id not in fully_scanned or int(row["byte_length"]) > max_field_bytes:
            continue
        path = _project_blob_path(project_root, str(row["relative_path"]))
        with path.open("rb") as stream:
            data = stream.read(max_field_bytes + 1)
        if len(data) > max_field_bytes or any(byte < 0x20 or byte > 0x7E for byte in data):
            continue
        value = data.decode("ascii").strip()
        if not value or value.lower() in PLACEHOLDERS:
            continue
        field_name = str(row["name"]).strip().lower()
        sensitive = field_name in SENSITIVE_FIELDS
        kind = "sensitive-field" if sensitive else "context-field"
        role_score = 60.0 if field_name in PASSWORD_FIELDS else (50.0 if sensitive else 10.0)
        length_score = 10.0 if len(value) >= 32 else (5.0 if len(value) >= 8 else 1.0)
        shape, shape_score = _field_shape(value)
        score = role_score + length_score + shape_score + 2.0
        signals = (
            ("field-role", role_score, {"field_name": field_name, "ordinal": int(row["ordinal"])}),
            ("printable", 2.0, {"encoding": "ascii"}),
            ("length", length_score, {"length": len(value)}),
            ("value-shape", shape_score, {"shape": shape}),
        )
        with database.connect() as connection:
            public_id = _upsert_candidate(
                connection,
                kind=kind,
                value=value,
                score=score,
                evidence_db_id=evidence_db_id,
                evidence_public_id=str(row["evidence_id"]),
                evidence_role="structured-field",
                signals=signals,
            )
        public_ids.add(public_id)
        count += 1
        if len(public_ids) >= remaining_candidates:
            break
    return count, public_ids


def triage_project(
    project_path: Path,
    *,
    max_evidence: int = 10_000,
    max_evidence_bytes: int = 64 * 1024 * 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
    max_matches_per_evidence: int = 128,
    max_candidates: int = 1024,
    max_field_bytes: int = 4096,
    window_bytes: int = 1024 * 1024,
) -> TriageSummary:
    limits = (
        max_evidence,
        max_evidence_bytes,
        max_total_bytes,
        max_matches_per_evidence,
        max_candidates,
        max_field_bytes,
        window_bytes,
    )
    if min(limits) <= 0:
        raise ValueError("triage limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    inputs = _current_inputs(database)
    policy = _policy_json(
        max_evidence=max_evidence,
        max_evidence_bytes=max_evidence_bytes,
        max_total_bytes=max_total_bytes,
        max_matches_per_evidence=max_matches_per_evidence,
        max_candidates=max_candidates,
        max_field_bytes=max_field_bytes,
        window_bytes=window_bytes,
    )
    scanned_bytes = 0
    evidence_scanned = 0
    statuses = {
        "complete": 0,
        "input-truncated": 0,
        "candidate-limit": 0,
        "skipped-budget": 0,
        "skipped-limit": 0,
        "failed": 0,
    }
    known_matches = 0
    candidate_public_ids: set[str] = set()
    fully_scanned: set[int] = set()
    for index, item in enumerate(inputs):
        if index >= max_evidence or len(candidate_public_ids) >= max_candidates:
            status = "skipped-limit"
            _persist_scan(
                database,
                item,
                policy_json=policy,
                max_bytes=max_evidence_bytes,
                scanned_bytes=0,
                matches=0,
                status=status,
            )
            statuses[status] += 1
            continue
        remaining_total = max_total_bytes - scanned_bytes
        if remaining_total <= 0:
            status = "skipped-budget"
            _persist_scan(
                database,
                item,
                policy_json=policy,
                max_bytes=max_evidence_bytes,
                scanned_bytes=0,
                matches=0,
                status=status,
            )
            statuses[status] += 1
            continue
        scan_bytes = min(max_evidence_bytes, remaining_total)
        try:
            path = _project_blob_path(project.root, item.relative_path)
            result = scan_flag_matches(
                path,
                max_bytes=scan_bytes,
                max_matches=min(
                    max_matches_per_evidence,
                    max_candidates - len(candidate_public_ids),
                ),
                chunk_size=window_bytes,
            )
            scanned_bytes += result.scanned_bytes
            evidence_scanned += 1
            for match in result.matches:
                candidate_public_ids.add(
                    _persist_known_match(database, project.capture_sha256, item, match)
                )
            known_matches += len(result.matches)
            if result.candidate_limited:
                status = "candidate-limit"
            elif result.input_truncated:
                status = "input-truncated"
            else:
                status = "complete"
            if not result.input_truncated and not result.candidate_limited:
                fully_scanned.add(item.evidence_db_id)
            _persist_scan(
                database,
                item,
                policy_json=policy,
                max_bytes=scan_bytes,
                scanned_bytes=result.scanned_bytes,
                matches=len(result.matches),
                status=status,
            )
            statuses[status] += 1
        except (OSError, ValueError) as error:
            status = "failed"
            _persist_scan(
                database,
                item,
                policy_json=policy,
                max_bytes=scan_bytes,
                scanned_bytes=0,
                matches=0,
                status=status,
                error=str(error)[:4096],
            )
            statuses[status] += 1
    field_count, field_public_ids = _field_candidates(
        database,
        project.root,
        fully_scanned,
        max_candidates - len(candidate_public_ids),
        max_field_bytes,
    )
    candidate_public_ids.update(field_public_ids)
    ranked: tuple[RankedCandidate, ...] = ()
    if candidate_public_ids:
        ordered_ids = tuple(sorted(candidate_public_ids))
        placeholders = ",".join("?" for _ in ordered_ids)
        with database.connect() as connection:
            ranked = tuple(
                RankedCandidate(
                    candidate_id=str(row["candidate_id"]),
                    kind=str(row["kind"]),
                    value=str(row["normalized_value"]),
                    confidence=float(row["confidence"]),
                    rank_score=float(row["rank_score"]),
                )
                for row in connection.execute(
                    "SELECT candidate_id,kind,normalized_value,confidence,rank_score "
                    f"FROM candidate WHERE candidate_id IN ({placeholders}) "
                    "ORDER BY rank_score DESC,confidence DESC,candidate_id LIMIT ?",
                    (*ordered_ids, max_candidates),
                )
            )
    return TriageSummary(
        schema_version="auto-shark.triage/v1",
        project=str(project.root),
        evidence_selected=len(inputs),
        evidence_scanned=evidence_scanned,
        scanned_bytes=scanned_bytes,
        complete=statuses["complete"],
        input_truncated=statuses["input-truncated"],
        candidate_limited=statuses["candidate-limit"],
        skipped_budget=statuses["skipped-budget"],
        skipped_limit=statuses["skipped-limit"],
        failed=statuses["failed"],
        known_matches=known_matches,
        field_candidates=field_count,
        candidates=ranked,
    )
