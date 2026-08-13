"""Budgeted HTTP body scheduling and end-to-end analysis workflow."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .analysis import AnalysisSummary, analyze_http
from .body import BodyExtractionSummary, extract_http_body
from .core.ids import stable_id
from .engines.tshark import probe_tshark
from .pipeline import ScanSummary, scan_project
from .storage import Database


@dataclass(frozen=True)
class BodyTarget:
    protocol_message_id: int
    message_public_id: str
    frame_number: int
    message_kind: str
    content_length: Optional[int]
    priority: int
    selection_reason: str


@dataclass(frozen=True)
class BodyRunSummary:
    selected: int
    completed: int
    failed: int
    skipped_budget: int
    extracted_bytes: int
    statuses: tuple[BodyExtractionSummary, ...]


@dataclass(frozen=True)
class WorkflowSummary:
    analysis: AnalysisSummary
    bodies: BodyRunSummary
    scan: Optional[ScanSummary]

    def to_json(self, *, verbose_bodies: bool = False) -> str:
        payload = asdict(self)
        if not verbose_bodies:
            payload["bodies"]["statuses"] = []
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def select_http_body_targets(database: Database, uri: Optional[str]) -> list[BodyTarget]:
    parameters: tuple[object, ...] = ()
    uri_clause = ""
    reason = "all-http-transactions"
    if uri is not None:
        uri_clause = "AND request_http.uri = ?"
        parameters = (uri,)
        reason = f"request-uri:{uri}"
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT DISTINCT member.id AS protocol_message_id, member.message_id, "
            "member.representative_frame, member.message_kind, member_http.content_length "
            "FROM transaction_record tr "
            "JOIN protocol_message request_message ON request_message.id=tr.request_message_id "
            "JOIN http_message request_http ON request_http.protocol_message_id=request_message.id "
            "JOIN transaction_message tm ON tm.transaction_id=tr.id "
            "JOIN protocol_message member ON member.id=tm.protocol_message_id "
            "JOIN http_message member_http ON member_http.protocol_message_id=member.id "
            "WHERE tr.protocol='http' "
            f"{uri_clause} "
            "ORDER BY member.representative_frame",
            parameters,
        ).fetchall()
    return [
        BodyTarget(
            protocol_message_id=int(row["protocol_message_id"]),
            message_public_id=str(row["message_id"]),
            frame_number=int(row["representative_frame"]),
            message_kind=str(row["message_kind"]),
            content_length=(
                int(row["content_length"]) if row["content_length"] is not None else None
            ),
            priority=100,
            selection_reason=reason,
        )
        for row in rows
    ]


def _task_id(capture_sha256: str, target: BodyTarget) -> str:
    return stable_id(
        "body-task",
        {
            "capture_sha256": capture_sha256,
            "protocol_message_id": target.message_public_id,
            "selection_reason": target.selection_reason,
        },
    )


def _upsert_task(
    database: Database,
    capture_sha256: str,
    target: BodyTarget,
    *,
    max_bytes: int,
    status: str,
    extracted_bytes: Optional[int] = None,
    error: Optional[str] = None,
) -> None:
    now = _utc_now()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO body_task "
            "(task_id,protocol_message_id,selection_reason,priority,max_bytes,status,"
            "extracted_bytes,error,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(task_id) DO UPDATE SET max_bytes=excluded.max_bytes, "
            "status=excluded.status, extracted_bytes=excluded.extracted_bytes, "
            "error=excluded.error, updated_at=excluded.updated_at",
            (
                _task_id(capture_sha256, target),
                target.protocol_message_id,
                target.selection_reason,
                target.priority,
                max_bytes,
                status,
                extracted_bytes,
                error,
                now,
                now,
            ),
        )


def extract_selected_http_bodies(
    project: Path,
    tshark: Path,
    *,
    uri: Optional[str],
    max_body_bytes: int,
    max_total_bytes: int,
) -> BodyRunSummary:
    if max_body_bytes <= 0 or max_total_bytes <= 0:
        raise ValueError("body extraction budgets must be positive")
    database = Database(Path(project) / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        capture_sha256 = str(connection.execute("SELECT sha256 FROM capture").fetchone()[0])
    targets = select_http_body_targets(database, uri)
    capabilities = probe_tshark(tshark)
    if not capabilities.usable or not capabilities.features.get("http", False):
        raise ValueError("TShark lacks required HTTP body capability")
    remaining = max_total_bytes
    summaries: list[BodyExtractionSummary] = []
    completed = 0
    failed = 0
    skipped = 0
    extracted = 0
    for target in targets:
        if remaining <= 0:
            _upsert_task(
                database,
                capture_sha256,
                target,
                max_bytes=max_body_bytes,
                status="skipped-budget",
                error="total body extraction budget exhausted",
            )
            skipped += 1
            continue
        allocation = min(max_body_bytes, remaining)
        _upsert_task(
            database,
            capture_sha256,
            target,
            max_bytes=allocation,
            status="running",
        )
        try:
            summary = extract_http_body(
                project,
                target.frame_number,
                tshark,
                max_body_bytes=allocation,
                capabilities=capabilities,
            )
        except (OSError, TimeoutError, ValueError) as error:
            _upsert_task(
                database,
                capture_sha256,
                target,
                max_bytes=allocation,
                status="failed",
                error=str(error)[:2000],
            )
            failed += 1
            continue
        summaries.append(summary)
        completed += 1
        extracted += summary.extracted_length
        remaining -= summary.extracted_length
        _upsert_task(
            database,
            capture_sha256,
            target,
            max_bytes=allocation,
            status="completed",
            extracted_bytes=summary.extracted_length,
        )
    return BodyRunSummary(
        selected=len(targets),
        completed=completed,
        failed=failed,
        skipped_budget=skipped,
        extracted_bytes=extracted,
        statuses=tuple(summaries),
    )


def analyze_with_bodies(
    capture: Path,
    project: Path,
    tshark: Path,
    *,
    uri: Optional[str],
    max_body_bytes: int,
    max_total_bytes: int,
    run_scan: bool,
) -> WorkflowSummary:
    analysis = analyze_http(capture, project, tshark, matching_uri=uri)
    bodies = extract_selected_http_bodies(
        project,
        tshark,
        uri=uri,
        max_body_bytes=max_body_bytes,
        max_total_bytes=max_total_bytes,
    )
    scan = scan_project(project) if run_scan else None
    return WorkflowSummary(analysis=analysis, bodies=bodies, scan=scan)
