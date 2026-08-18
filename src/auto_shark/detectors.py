"""Bounded M4 detector entry point, starting with unknown flag-like tokens."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import EvidenceLocator, candidate_id, evidence_id, stable_id
from .manual_queue import rebuild_manual_queue
from .project import inspect_project
from .storage import Database
from .triage import _current_inputs, _project_blob_path, _tcp_frames, _TriageInput

UNKNOWN_DETECTOR = "m4-unknown-candidate"
UNKNOWN_DETECTOR_VERSION = "1"
BRACE_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_-]{1,32})\{([\x21-\x7a\x7c\x7e]{4,256})\}(?![A-Za-z0-9_])"
)
TOKEN_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_.+/=:-])([A-Za-z0-9][A-Za-z0-9_.+/=:-]{23,127})(?![A-Za-z0-9_.+/=:-])"
)
KNOWN_PREFIXES = {"flag", "ctf", "key", "answer"}
TOKEN_MARKERS = set("_./+-=")
MAX_OVERLAP = 256


@dataclass(frozen=True)
class UnknownMatch:
    kind: str
    value: bytes
    offset: int


@dataclass(frozen=True)
class DetectionSummary:
    schema_version: str
    project: str
    run_id: str
    detector_set: str
    status: str
    inputs_processed: int
    inputs_skipped: int
    candidates: int
    matches: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class ProjectDetectionSummary:
    schema_version: str
    project: str
    status: str
    detector_runs: tuple[str, ...]
    inputs_processed: int
    inputs_skipped: int
    candidates: int
    findings: int
    events: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _classes(value: bytes) -> set[str]:
    text = value.decode("ascii", errors="ignore")
    result: set[str] = set()
    if any(char.islower() for char in text):
        result.add("lower")
    if any(char.isupper() for char in text):
        result.add("upper")
    if any(char.isdigit() for char in text):
        result.add("digit")
    if any(char in TOKEN_MARKERS for char in text):
        result.add("marker")
    return result


def _valid_long_token(value: bytes) -> bool:
    if not (24 <= len(value) <= 128):
        return False
    if value.lower().startswith((b"http://", b"https://", b"www.")):
        return False
    if value.count(b"/") > 3 or value.count(b".") > 3:
        return False
    if b"=" in value[:-2]:
        return False
    classes = _classes(value)
    if len(classes) < 4:
        return False
    if set(value) <= set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="):
        return False
    lowered = value.lower()
    return not all(byte in b"0123456789abcdef" for byte in lowered)


def _deduplicate(matches: list[UnknownMatch]) -> list[UnknownMatch]:
    return sorted(
        {(item.kind, item.offset, item.value): item for item in matches}.values(),
        key=lambda item: (item.offset, item.kind, item.value),
    )


def scan_unknown_matches(
    path: Path,
    *,
    max_bytes: int = 64 * 1024 * 1024,
    max_matches: int = 128,
    chunk_size: int = 1024 * 1024,
) -> tuple[tuple[UnknownMatch, ...], int, bool, bool]:
    """Scan bounded bytes and return matches, bytes read, truncation, and match limit."""
    if min(max_bytes, max_matches, chunk_size) <= 0:
        raise ValueError("unknown-token scan limits must be positive")
    matches: list[UnknownMatch] = []
    overlap = b""
    scanned = 0
    input_length = path.stat().st_size
    input_truncated = input_length > max_bytes
    scan_length = min(input_length, max_bytes)
    candidate_limited = False
    with path.open("rb") as stream:
        while scanned < scan_length:
            block = stream.read(min(chunk_size, scan_length - scanned))
            if not block:
                break
            scanned += len(block)
            data = overlap + block
            base = scanned - len(data)
            at_end = scanned >= scan_length
            for match in BRACE_PATTERN.finditer(data):
                if not at_end and match.end() == len(data):
                    continue
                prefix = match.group(1).decode("ascii", errors="ignore").lower()
                if prefix in KNOWN_PREFIXES:
                    continue
                value = match.group(0)
                matches.append(UnknownMatch("unknown-brace", value, base + match.start()))
            for match in TOKEN_PATTERN.finditer(data):
                if not at_end and match.end(1) == len(data):
                    continue
                value = match.group(1)
                if _valid_long_token(value):
                    matches.append(UnknownMatch("unknown-token", value, base + match.start(1)))
            unique = _deduplicate(matches)
            if len(unique) >= max_matches:
                matches = unique[:max_matches]
                candidate_limited = True
                break
            matches = unique
            overlap = data[-MAX_OVERLAP:]
    return tuple(matches), scanned, input_truncated, candidate_limited


def _policy_json(
    max_evidence: int,
    max_evidence_bytes: int,
    max_total_bytes: int,
    max_matches: int,
    max_candidates: int,
    chunk_size: int,
) -> str:
    return json.dumps(
        {
            "max_candidates": max_candidates,
            "max_evidence": max_evidence,
            "max_evidence_bytes": max_evidence_bytes,
            "max_total_bytes": max_total_bytes,
            "max_matches": max_matches,
            "chunk_size": chunk_size,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _insert_skip(
    database: Database,
    run_db_id: int,
    scope_kind: str,
    scope_id: Optional[str],
    reason: str,
    detail: dict[str, object],
) -> None:
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO detector_skip "
            "(detector_run_id, scope_kind, scope_id, reason, count, detail_json) "
            "VALUES(?,?,?,?,1,?) ON CONFLICT(detector_run_id,scope_kind,scope_id,reason) "
            "DO UPDATE SET count=detector_skip.count+1,detail_json=excluded.detail_json",
            (
                run_db_id,
                scope_kind,
                scope_id,
                reason,
                json.dumps(detail, ensure_ascii=False, sort_keys=True),
            ),
        )


def _persist_unknown(
    database: Database, project: object, item: _TriageInput, match: UnknownMatch
) -> bool:
    capture_sha256 = str(project.capture_sha256)
    frames = (
        _tcp_frames(database, item.evidence_db_id, match.offset, len(match.value))
        if item.source_kind == "tcp-stream"
        else []
    )
    frame_start = min(frames) if frames else item.frame_start
    frame_end = max(frames) if frames else item.frame_end
    value = match.value.decode("utf-8", errors="replace")
    with database.connect() as connection:
        if connection.execute(
            "SELECT 1 FROM candidate c JOIN candidate_evidence ce ON ce.candidate_id=c.id "
            "WHERE c.kind='flag' AND c.normalized_value=? AND ce.evidence_id IN "
            "(SELECT id FROM evidence WHERE blob_id=?) LIMIT 1",
            (value.strip(), item.blob_id),
        ).fetchone():
            return False
    locator = EvidenceLocator(
        capture_sha256=capture_sha256,
        source_kind="unknown-candidate",
        frame_start=frame_start,
        frame_end=frame_end,
        protocol_message=item.evidence_public_id,
        direction=item.direction,
        byte_offset=match.offset,
        byte_length=len(match.value),
    )
    public_evidence_id = evidence_id(locator)
    public_candidate_id = candidate_id("unknown-flag", value.strip())
    score = 78.0 if match.kind == "unknown-brace" else 45.0
    confidence = min(0.9, score / 100.0)
    with database.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO evidence "
            "(evidence_id, capture_id, source_kind, frame_start, frame_end, "
            "protocol_message_id, transaction_id, direction, byte_offset, byte_length, "
            "text_value, blob_id, locator_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                public_evidence_id,
                item.capture_id,
                "unknown-candidate",
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
        evidence_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?", (public_evidence_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO candidate "
            "(candidate_id, kind, raw_value, normalized_value, confidence, rank_score, created_at) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(candidate_id) DO UPDATE SET "
            "confidence=max(candidate.confidence,excluded.confidence),"
            "rank_score=max(candidate.rank_score,excluded.rank_score)",
            (public_candidate_id, "unknown-flag", value, value.strip(), confidence, score, _now()),
        )
        candidate_db_id = int(
            connection.execute(
                "SELECT id FROM candidate WHERE candidate_id=?", (public_candidate_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO candidate_evidence(candidate_id,evidence_id,role) VALUES(?,?,?)",
            (candidate_db_id, evidence_db_id, "unknown-format"),
        )
        signal_id = stable_id(
            "candidate-signal",
            {
                "candidate_id": public_candidate_id,
                "evidence_id": public_evidence_id,
                "detector": UNKNOWN_DETECTOR,
                "version": UNKNOWN_DETECTOR_VERSION,
                "name": match.kind,
            },
        )
        connection.execute(
            "INSERT INTO candidate_signal "
            "(signal_id, candidate_id, evidence_id, detector, detector_version, signal_name, "
            "contribution, detail_json) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(candidate_id,evidence_id,detector,detector_version,signal_name) "
            "DO UPDATE SET contribution=excluded.contribution,detail_json=excluded.detail_json",
            (
                signal_id,
                candidate_db_id,
                evidence_db_id,
                UNKNOWN_DETECTOR,
                UNKNOWN_DETECTOR_VERSION,
                match.kind,
                score,
                json.dumps(
                    {
                        "offset": match.offset,
                        "length": len(match.value),
                        "input_evidence_id": item.evidence_public_id,
                        "frames": frames,
                    },
                    sort_keys=True,
                ),
            ),
        )
    return True


def detect_unknown_candidates(
    project_path: Path,
    *,
    max_evidence: int = 10_000,
    max_evidence_bytes: int = 64 * 1024 * 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
    max_matches: int = 128,
    max_candidates: int = 1024,
    chunk_size: int = 1024 * 1024,
) -> DetectionSummary:
    limits = (
        max_evidence,
        max_evidence_bytes,
        max_total_bytes,
        max_matches,
        max_candidates,
        chunk_size,
    )
    if min(limits) <= 0:
        raise ValueError("unknown-candidate limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    policy = _policy_json(
        max_evidence, max_evidence_bytes, max_total_bytes, max_matches, max_candidates, chunk_size
    )
    run_id = str(uuid4())
    started = _now()
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO detector_run"
            "(run_id,capture_id,detector_set,detector_version,policy_json,status,"
            "inputs_processed,inputs_skipped,candidates,findings,events,started_at) "
            "VALUES(?,?,?,?,?,'partial',0,0,0,0,0,?)",
            (run_id, capture_id, UNKNOWN_DETECTOR, UNKNOWN_DETECTOR_VERSION, policy, started),
        )
        run_db_id = int(
            connection.execute("SELECT id FROM detector_run WHERE run_id=?", (run_id,)).fetchone()[
                0
            ]
        )
    inputs = _current_inputs(database)
    processed = skipped = candidates = matches_count = 0
    total_bytes = 0
    status = "completed"
    for index, item in enumerate(inputs):
        if candidates >= max_candidates:
            _insert_skip(
                database,
                run_db_id,
                "evidence",
                item.evidence_public_id,
                "candidate-limit",
                {"max_candidates": max_candidates},
            )
            skipped += 1
            status = "budget-limited"
            continue
        if index >= max_evidence:
            _insert_skip(
                database,
                run_db_id,
                "evidence",
                item.evidence_public_id,
                "evidence-limit",
                {"max_evidence": max_evidence},
            )
            skipped += 1
            status = "budget-limited"
            continue
        if total_bytes >= max_total_bytes:
            _insert_skip(
                database,
                run_db_id,
                "evidence",
                item.evidence_public_id,
                "total-byte-limit",
                {"max_total_bytes": max_total_bytes},
            )
            skipped += 1
            status = "budget-limited"
            continue
        try:
            path = _project_blob_path(project.root, item.relative_path)
            allowance = min(max_evidence_bytes, max_total_bytes - total_bytes)
            found, scanned, truncated, limited = scan_unknown_matches(
                path,
                max_bytes=allowance,
                max_matches=min(max_matches, max_candidates - candidates),
                chunk_size=chunk_size,
            )
        except (OSError, ValueError) as error:
            _insert_skip(
                database,
                run_db_id,
                "evidence",
                item.evidence_public_id,
                "failed",
                {"error": str(error)},
            )
            skipped += 1
            status = "partial"
            continue
        processed += 1
        total_bytes += scanned
        if truncated:
            _insert_skip(
                database,
                run_db_id,
                "evidence",
                item.evidence_public_id,
                "input-truncated",
                {"scanned_bytes": scanned, "blob_length": item.blob_length},
            )
            status = "partial"
        if limited:
            _insert_skip(
                database,
                run_db_id,
                "evidence",
                item.evidence_public_id,
                "match-limit",
                {"max_matches": max_matches},
            )
            status = "budget-limited"
        for match in found:
            if candidates >= max_candidates:
                status = "budget-limited"
                break
            if _persist_unknown(database, project, item, match):
                candidates += 1
            matches_count += 1
    ended = _now()
    with database.connect() as connection:
        connection.execute(
            "UPDATE detector_run SET status=?,inputs_processed=?,inputs_skipped=?,"
            "candidates=?,ended_at=? WHERE id=?",
            (status, processed, skipped, candidates, ended, run_db_id),
        )
    return DetectionSummary(
        "auto-shark.detect/v1",
        str(project.root),
        run_id,
        UNKNOWN_DETECTOR,
        status,
        processed,
        skipped,
        candidates,
        matches_count,
    )


def detect_project(
    project_path: Path,
    *,
    max_evidence: int = 10_000,
    max_evidence_bytes: int = 64 * 1024 * 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
    max_matches: int = 128,
    max_candidates: int = 1024,
    chunk_size: int = 1024 * 1024,
    max_transactions: int = 10_000,
    max_parameters: int = 1024,
    max_parameter_bytes: int = 4096,
    max_events: int = 10_000,
    max_findings: int = 1000,
    max_preview_bytes: int = 256,
    max_webshell_fields: int = 100_000,
    max_webshell_value_bytes: int = 64 * 1024,
    max_ognl_fields: int = 100_000,
    max_ognl_body_bytes: int = 1024 * 1024,
) -> ProjectDetectionSummary:
    """Run the currently enabled bounded M4 detector set."""
    from .ognl_detection import detect_ognl_command_injection
    from .sql_detection import detect_sql_injection
    from .webshell_detection import detect_webshell_activity

    unknown = detect_unknown_candidates(
        project_path,
        max_evidence=max_evidence,
        max_evidence_bytes=max_evidence_bytes,
        max_total_bytes=max_total_bytes,
        max_matches=max_matches,
        max_candidates=max_candidates,
        chunk_size=chunk_size,
    )
    sql = detect_sql_injection(
        project_path,
        max_transactions=max_transactions,
        max_parameters=max_parameters,
        max_parameter_bytes=max_parameter_bytes,
        max_events=max_events,
        max_findings=max_findings,
        max_preview_bytes=max_preview_bytes,
    )
    webshell = detect_webshell_activity(
        project_path,
        max_transactions=max_transactions,
        max_fields=max_webshell_fields,
        max_value_bytes=max_webshell_value_bytes,
        max_events=max_events,
        max_findings=max_findings,
        max_preview_bytes=max_preview_bytes,
    )
    ognl = detect_ognl_command_injection(
        project_path,
        max_transactions=max_transactions,
        max_fields=max_ognl_fields,
        max_body_bytes=max_ognl_body_bytes,
        max_events=max_events,
        max_findings=max_findings,
        max_preview_bytes=max_preview_bytes,
    )
    rebuild_manual_queue(project_path)
    statuses = {unknown.status, sql.status, webshell.status, ognl.status}
    if "failed" in statuses:
        status = "failed"
    elif "partial" in statuses:
        status = "partial"
    elif "budget-limited" in statuses:
        status = "budget-limited"
    else:
        status = "completed"
    return ProjectDetectionSummary(
        "auto-shark.detect/v1",
        str(project_path.resolve()),
        status,
        (unknown.run_id, sql.run_id, webshell.run_id, ognl.run_id),
        unknown.inputs_processed
        + sql.parameters_processed
        + webshell.transactions_processed
        + ognl.transactions_processed,
        unknown.inputs_skipped
        + sql.inputs_skipped
        + webshell.inputs_skipped
        + ognl.inputs_skipped,
        unknown.candidates,
        sql.findings + webshell.findings + ognl.findings,
        sql.events + webshell.events + ognl.events,
    )
