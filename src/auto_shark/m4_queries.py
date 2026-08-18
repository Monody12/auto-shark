"""Bounded M4 finding and static WebShell timeline read models."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .project import inspect_project
from .storage import Database
from .webshell_detection import WEBSHELL_DETECTOR

MAX_PAGE_LIMIT = 1000


@dataclass(frozen=True)
class FindingsPage:
    schema_version: str
    project: str
    candidate_offset: int
    candidate_limit: int
    candidate_total: int
    finding_offset: int
    finding_limit: int
    finding_total: int
    max_signals: int
    max_evidence_links: int
    max_detail_bytes: int
    signals_returned: int
    evidence_links_returned: int
    candidates: tuple[dict[str, object], ...]
    findings: tuple[dict[str, object], ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class TimelinePage:
    schema_version: str
    project: str
    offset: int
    limit: int
    total: int
    count: int
    include_duplicates: bool
    max_evidence_links: int
    max_detail_bytes: int
    evidence_links_returned: int
    items: tuple[dict[str, object], ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _validate_page(offset: int, limit: int, name: str) -> None:
    if offset < 0:
        raise ValueError(f"{name} offset cannot be negative")
    if not 0 < limit <= MAX_PAGE_LIMIT:
        raise ValueError(f"{name} limit must be between 1 and {MAX_PAGE_LIMIT}")


def _bounded_json(value: str, max_bytes: int) -> tuple[object, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return json.loads(value), False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def _evidence_links(connection, query: str, parameters: tuple[object, ...], limit: int):
    return [
        {
            "role": str(row["role"]),
            "evidence_id": str(row["evidence_id"]),
            "source_kind": str(row["source_kind"]),
            "frame_start": row["frame_start"],
            "frame_end": row["frame_end"],
            "byte_offset": row["byte_offset"],
            "byte_length": row["byte_length"],
            "field_name": row["field_name"],
        }
        for row in connection.execute(query, (*parameters, limit))
    ]


def query_findings(
    project_path: Path,
    *,
    candidate_offset: int = 0,
    candidate_limit: int = 100,
    finding_offset: int = 0,
    finding_limit: int = 100,
    max_signals: int = 1000,
    max_evidence_links: int = 10_000,
    max_detail_bytes: int = 4096,
) -> FindingsPage:
    _validate_page(candidate_offset, candidate_limit, "candidate")
    _validate_page(finding_offset, finding_limit, "finding")
    if min(max_signals, max_evidence_links, max_detail_bytes) <= 0:
        raise ValueError("finding auxiliary limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        candidate_total = int(
            connection.execute(
                "SELECT count(DISTINCT c.id) FROM candidate c "
                "JOIN candidate_evidence ce ON ce.candidate_id=c.id "
                "JOIN evidence e ON e.id=ce.evidence_id WHERE e.capture_id=?",
                (capture_id,),
            ).fetchone()[0]
        )
        candidate_rows = connection.execute(
            "SELECT DISTINCT c.id,c.candidate_id,c.kind,c.raw_value,c.normalized_value,"
            "c.confidence,c.rank_score FROM candidate c "
            "JOIN candidate_evidence ce ON ce.candidate_id=c.id "
            "JOIN evidence e ON e.id=ce.evidence_id WHERE e.capture_id=? "
            "ORDER BY c.rank_score DESC,c.candidate_id LIMIT ? OFFSET ?",
            (capture_id, candidate_limit, candidate_offset),
        ).fetchall()
        finding_total = int(
            connection.execute(
                "SELECT count(DISTINCT f.id) FROM finding f "
                "JOIN finding_evidence fe ON fe.finding_id=f.id "
                "JOIN evidence e ON e.id=fe.evidence_id WHERE e.capture_id=?",
                (capture_id,),
            ).fetchone()[0]
        )
        finding_rows = connection.execute(
            "SELECT DISTINCT f.id,f.finding_id,f.detector,f.detector_version,f.title,"
            "f.description,f.severity,f.confidence,f.recommended_action,f.created_at "
            "FROM finding f JOIN finding_evidence fe ON fe.finding_id=f.id "
            "JOIN evidence e ON e.id=fe.evidence_id WHERE e.capture_id=? "
            "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END,f.confidence DESC,f.finding_id LIMIT ? OFFSET ?",
            (capture_id, finding_limit, finding_offset),
        ).fetchall()
        signal_remaining = max_signals
        evidence_remaining = max_evidence_links
        signals_returned = evidence_returned = 0
        candidates = []
        for row in candidate_rows:
            signal_total = int(
                connection.execute(
                    "SELECT count(*) FROM candidate_signal WHERE candidate_id=?", (row["id"],)
                ).fetchone()[0]
            )
            signals = []
            if signal_remaining:
                for signal in connection.execute(
                    "SELECT detector,detector_version,signal_name,contribution,detail_json "
                    "FROM candidate_signal WHERE candidate_id=? "
                    "ORDER BY contribution DESC,signal_name LIMIT ?",
                    (row["id"], signal_remaining),
                ):
                    detail, detail_truncated = _bounded_json(
                        str(signal["detail_json"]), max_detail_bytes
                    )
                    signals.append(
                        {
                            "detector": str(signal["detector"]),
                            "detector_version": str(signal["detector_version"]),
                            "signal_name": str(signal["signal_name"]),
                            "contribution": float(signal["contribution"]),
                            "detail": detail,
                            "detail_truncated": detail_truncated,
                        }
                    )
                signal_remaining -= len(signals)
                signals_returned += len(signals)
            evidence_total = int(
                connection.execute(
                    "SELECT count(*) FROM candidate_evidence WHERE candidate_id=?",
                    (row["id"],),
                ).fetchone()[0]
            )
            links = _evidence_links(
                connection,
                "SELECT ce.role,e.evidence_id,e.source_kind,e.frame_start,e.frame_end,"
                "e.byte_offset,e.byte_length,e.field_name FROM candidate_evidence ce "
                "JOIN evidence e ON e.id=ce.evidence_id WHERE ce.candidate_id=? "
                "ORDER BY ce.role,e.evidence_id LIMIT ?",
                (row["id"],),
                evidence_remaining,
            )
            evidence_remaining -= len(links)
            evidence_returned += len(links)
            item = dict(row)
            item.pop("id")
            item.update(
                {
                    "signals": signals,
                    "signal_total": signal_total,
                    "signals_truncated": len(signals) < signal_total,
                    "evidence": links,
                    "evidence_total": evidence_total,
                    "evidence_truncated": len(links) < evidence_total,
                }
            )
            candidates.append(item)
        findings = []
        for row in finding_rows:
            evidence_total = int(
                connection.execute(
                    "SELECT count(*) FROM finding_evidence WHERE finding_id=?", (row["id"],)
                ).fetchone()[0]
            )
            links = _evidence_links(
                connection,
                "SELECT fe.role,e.evidence_id,e.source_kind,e.frame_start,e.frame_end,"
                "e.byte_offset,e.byte_length,e.field_name FROM finding_evidence fe "
                "JOIN evidence e ON e.id=fe.evidence_id WHERE fe.finding_id=? "
                "ORDER BY fe.role,e.evidence_id LIMIT ?",
                (row["id"],),
                evidence_remaining,
            )
            evidence_remaining -= len(links)
            evidence_returned += len(links)
            item = dict(row)
            item.pop("id")
            item.update(
                {
                    "evidence": links,
                    "evidence_total": evidence_total,
                    "evidence_truncated": len(links) < evidence_total,
                }
            )
            findings.append(item)
    return FindingsPage(
        "auto-shark.findings/v1",
        str(project.root),
        candidate_offset,
        candidate_limit,
        candidate_total,
        finding_offset,
        finding_limit,
        finding_total,
        max_signals,
        max_evidence_links,
        max_detail_bytes,
        signals_returned,
        evidence_returned,
        tuple(candidates),
        tuple(findings),
    )


def query_timeline(
    project_path: Path,
    *,
    detector: str = WEBSHELL_DETECTOR,
    event_kind: Optional[str] = None,
    status: Optional[str] = None,
    frame_start: Optional[int] = None,
    frame_end: Optional[int] = None,
    include_duplicates: bool = False,
    offset: int = 0,
    limit: int = 100,
    max_evidence_links: int = 10_000,
    max_detail_bytes: int = 4096,
) -> TimelinePage:
    _validate_page(offset, limit, "timeline")
    if min(max_evidence_links, max_detail_bytes) <= 0:
        raise ValueError("timeline auxiliary limits must be positive")
    if not detector.strip():
        raise ValueError("timeline detector cannot be empty")
    if frame_start is not None and frame_start < 0:
        raise ValueError("timeline frame start cannot be negative")
    if frame_end is not None and frame_end < 0:
        raise ValueError("timeline frame end cannot be negative")
    if frame_start is not None and frame_end is not None and frame_end < frame_start:
        raise ValueError("timeline frame end cannot precede frame start")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    where = ["be.capture_id=?", "be.detector=?"]
    parameters: list[object] = [None, detector]
    if not include_duplicates:
        where.append("be.duplicate_of IS NULL")
    if event_kind is not None:
        where.append("be.event_kind=?")
        parameters.append(event_kind)
    if status is not None:
        where.append("be.status=?")
        parameters.append(status)
    if frame_start is not None:
        where.append("be.request_frame>=?")
        parameters.append(frame_start)
    if frame_end is not None:
        where.append("be.request_frame<=?")
        parameters.append(frame_end)
    clause = " AND ".join(where)
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        parameters[0] = capture_id
        total = int(
            connection.execute(
                f"SELECT count(*) FROM behavior_event be WHERE {clause}", parameters
            ).fetchone()[0]
        )
        rows = connection.execute(
            "SELECT be.id,be.event_id,be.event_kind,be.status,be.request_frame,"
            "be.response_frame,be.target,be.semantic_key,be.confidence,be.detail_json,"
            "duplicate.event_id duplicate_of,"
            "(SELECT count(*) FROM behavior_event repeated WHERE repeated.capture_id=be.capture_id "
            "AND repeated.detector=be.detector "
            "AND repeated.semantic_key=be.semantic_key) repeat_count "
            "FROM behavior_event be LEFT JOIN behavior_event duplicate "
            "ON duplicate.id=be.duplicate_of "
            f"WHERE {clause} ORDER BY be.request_frame,be.id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
        evidence_remaining = max_evidence_links
        evidence_returned = 0
        items = []
        for row in rows:
            evidence_total = int(
                connection.execute(
                    "SELECT count(*) FROM behavior_event_evidence WHERE event_id=?",
                    (row["id"],),
                ).fetchone()[0]
            )
            links = _evidence_links(
                connection,
                "SELECT bee.role,e.evidence_id,e.source_kind,e.frame_start,e.frame_end,"
                "e.byte_offset,e.byte_length,e.field_name FROM behavior_event_evidence bee "
                "JOIN evidence e ON e.id=bee.evidence_id WHERE bee.event_id=? "
                "ORDER BY bee.role,e.evidence_id LIMIT ?",
                (row["id"],),
                evidence_remaining,
            )
            evidence_remaining -= len(links)
            evidence_returned += len(links)
            detail, detail_truncated = _bounded_json(str(row["detail_json"]), max_detail_bytes)
            item = dict(row)
            item.pop("id")
            item.pop("detail_json")
            item.update(
                {
                    "detail": detail,
                    "detail_truncated": detail_truncated,
                    "evidence": links,
                    "evidence_total": evidence_total,
                    "evidence_truncated": len(links) < evidence_total,
                }
            )
            items.append(item)
    return TimelinePage(
        "auto-shark.timeline/v1",
        str(project.root),
        offset,
        limit,
        total,
        len(items),
        include_duplicates,
        max_evidence_links,
        max_detail_bytes,
        evidence_returned,
        tuple(items),
    )
