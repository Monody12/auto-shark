"""Deterministic bounded investigation report read model."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .investigation import query_notes
from .m4_queries import query_findings, query_timeline
from .project import ProjectInfo, inspect_project
from .queries import query_manual_queue, query_summary
from .storage import Database

MAX_ITEM_LIMIT = 1000
MAX_AUXILIARY_LIMIT = 100_000
MAX_TEXT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ReportLimits:
    protocols: int = 256
    conversations: int = 1000
    candidates: int = 1000
    findings: int = 1000
    events: int = 1000
    artifacts: int = 1000
    manual_tasks: int = 1000
    review_marks: int = 1000
    notes: int = 1000
    evidence: int = 10_000
    tool_runs: int = 1000
    detector_runs: int = 1000
    signals: int = 10_000
    evidence_links: int = 50_000
    detail_bytes: int = 4096
    note_bytes: int = 64 * 1024

    def validate(self) -> None:
        values = asdict(self)
        if min(values.values()) <= 0:
            raise ValueError("report limits must be positive")
        for name in (
            "protocols",
            "conversations",
            "candidates",
            "findings",
            "events",
            "artifacts",
            "manual_tasks",
            "review_marks",
            "notes",
            "tool_runs",
            "detector_runs",
        ):
            if values[name] > MAX_ITEM_LIMIT:
                raise ValueError(f"report {name} limit cannot exceed {MAX_ITEM_LIMIT}")
        for name in ("evidence", "signals", "evidence_links"):
            if values[name] > MAX_AUXILIARY_LIMIT:
                raise ValueError(
                    f"report {name} limit cannot exceed {MAX_AUXILIARY_LIMIT}"
                )
        for name in ("detail_bytes", "note_bytes"):
            if values[name] > MAX_TEXT_BYTES:
                raise ValueError(f"report {name} limit cannot exceed {MAX_TEXT_BYTES}")


@dataclass(frozen=True)
class ReportDocument:
    payload: dict[str, object]

    def to_json(self) -> str:
        return json.dumps(
            self.payload, ensure_ascii=False, sort_keys=True, indent=2
        ) + "\n"


def _collection(total: int, limit: int, items: list[dict[str, object]]) -> dict[str, object]:
    return {
        "total": total,
        "limit": limit,
        "count": len(items),
        "truncated": len(items) < total,
        "items": items,
    }


def _capture_id(connection: sqlite3.Connection, capture_sha256: str) -> int:
    row = connection.execute(
        "SELECT id FROM capture WHERE sha256=?", (capture_sha256,)
    ).fetchone()
    if row is None:
        raise ValueError("project capture is missing from the database")
    return int(row[0])


def _artifact_collection(
    connection: sqlite3.Connection, capture_id: int, limit: int
) -> dict[str, object]:
    scope = (
        "EXISTS(SELECT 1 FROM evidence source WHERE source.id=a.source_evidence_id "
        "AND source.capture_id=?) OR EXISTS(SELECT 1 FROM artifact_evidence ae "
        "JOIN evidence linked ON linked.id=ae.evidence_id WHERE ae.artifact_id=a.id "
        "AND linked.capture_id=?)"
    )
    total = int(
        connection.execute(
            f"SELECT count(*) FROM artifact a WHERE {scope}", (capture_id, capture_id)
        ).fetchone()[0]
    )
    rows = connection.execute(
        "SELECT a.artifact_id,a.suggested_name,a.declared_media_type,"
        "a.detected_media_type,a.review_state,a.created_at,b.sha256,b.byte_length,"
        "b.complete,b.media_type,b.magic_description,e.evidence_id source_evidence_id "
        "FROM artifact a JOIN blob b ON b.id=a.blob_id "
        "LEFT JOIN evidence e ON e.id=a.source_evidence_id "
        f"WHERE {scope} ORDER BY a.artifact_id LIMIT ?",
        (capture_id, capture_id, limit),
    ).fetchall()
    return _collection(total, limit, [dict(row) for row in rows])


def _review_mark_collection(
    connection: sqlite3.Connection, capture_id: int, limit: int
) -> dict[str, object]:
    subject_sql = (
        "SELECT 'candidate' subject_kind,c.candidate_id subject_id FROM candidate c "
        "JOIN candidate_evidence ce ON ce.candidate_id=c.id "
        "JOIN evidence e ON e.id=ce.evidence_id WHERE e.capture_id=? UNION "
        "SELECT 'finding',f.finding_id FROM finding f "
        "JOIN finding_evidence fe ON fe.finding_id=f.id "
        "JOIN evidence e ON e.id=fe.evidence_id WHERE e.capture_id=? UNION "
        "SELECT 'artifact',a.artifact_id FROM artifact a WHERE "
        "EXISTS(SELECT 1 FROM evidence source WHERE source.id=a.source_evidence_id "
        "AND source.capture_id=?) OR EXISTS(SELECT 1 FROM artifact_evidence ae "
        "JOIN evidence linked ON linked.id=ae.evidence_id WHERE ae.artifact_id=a.id "
        "AND linked.capture_id=?) UNION "
        "SELECT 'behavior-event',event_id FROM behavior_event WHERE capture_id=? UNION "
        "SELECT 'manual-task',task_id FROM manual_task WHERE capture_id=? UNION "
        "SELECT 'evidence',evidence_id FROM evidence WHERE capture_id=?"
    )
    parameters = (capture_id,) * 7
    total = int(
        connection.execute(
            f"WITH subjects AS ({subject_sql}) SELECT count(*) FROM review_mark rm "
            "JOIN subjects s ON s.subject_kind=rm.subject_kind AND s.subject_id=rm.subject_id",
            parameters,
        ).fetchone()[0]
    )
    rows = connection.execute(
        f"WITH subjects AS ({subject_sql}) "
        "SELECT rm.subject_kind,rm.subject_id,rm.state,rm.updated_at FROM review_mark rm "
        "JOIN subjects s ON s.subject_kind=rm.subject_kind AND s.subject_id=rm.subject_id "
        "ORDER BY rm.subject_kind,rm.subject_id LIMIT ?",
        (*parameters, limit),
    ).fetchall()
    return _collection(total, limit, [dict(row) for row in rows])


def _evidence_collection(
    connection: sqlite3.Connection, capture_id: int, limit: int
) -> dict[str, object]:
    total = int(
        connection.execute(
            "SELECT count(*) FROM evidence WHERE capture_id=?", (capture_id,)
        ).fetchone()[0]
    )
    rows = connection.execute(
        "SELECT e.evidence_id,e.source_kind,e.frame_start,e.frame_end,e.direction,"
        "e.byte_offset,e.byte_length,e.field_name,b.sha256 blob_sha256,"
        "b.byte_length blob_bytes,b.complete blob_complete,b.media_type blob_media_type,"
        "b.magic_description blob_magic FROM evidence e "
        "LEFT JOIN blob b ON b.id=e.blob_id WHERE e.capture_id=? "
        "ORDER BY e.evidence_id LIMIT ?",
        (capture_id, limit),
    ).fetchall()
    return _collection(total, limit, [dict(row) for row in rows])


def _tool_run_collection(connection: sqlite3.Connection, limit: int) -> dict[str, object]:
    total = int(connection.execute("SELECT count(*) FROM tool_run").fetchone()[0])
    rows = connection.execute(
        "SELECT run_id,tool_name,tool_version,started_at,ended_at,status,exit_code,"
        "stderr_truncated FROM tool_run ORDER BY started_at,run_id LIMIT ?",
        (limit,),
    ).fetchall()
    return _collection(total, limit, [dict(row) for row in rows])


def _detector_run_collection(
    connection: sqlite3.Connection, capture_id: int, limit: int
) -> dict[str, object]:
    total = int(
        connection.execute(
            "SELECT count(*) FROM detector_run WHERE capture_id=?", (capture_id,)
        ).fetchone()[0]
    )
    rows = connection.execute(
        "SELECT run_id,detector_set,detector_version,status,inputs_processed,"
        "inputs_skipped,candidates,findings,events,started_at,ended_at "
        "FROM detector_run WHERE capture_id=? ORDER BY started_at,run_id LIMIT ?",
        (capture_id, limit),
    ).fetchall()
    return _collection(total, limit, [dict(row) for row in rows])


def _redact_local_paths(value: object, project: ProjectInfo) -> object:
    if isinstance(value, dict):
        return {key: _redact_local_paths(item, project) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_local_paths(item, project) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_local_paths(item, project) for item in value)
    if isinstance(value, str):
        result = value
        for local_path in (str(project.root), str(project.capture_path)):
            if local_path:
                result = result.replace(local_path, "[local-path]")
        return result
    return value


def collect_report(
    project_path: Path, *, limits: Optional[ReportLimits] = None
) -> ReportDocument:
    if limits is None:
        limits = ReportLimits()
    limits.validate()
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()

    summary = query_summary(
        project.root,
        protocol_limit=limits.protocols,
        conversation_limit=limits.conversations,
    )
    findings = query_findings(
        project.root,
        candidate_limit=limits.candidates,
        finding_limit=limits.findings,
        max_signals=limits.signals,
        max_evidence_links=limits.evidence_links,
        max_detail_bytes=limits.detail_bytes,
    )
    timeline = query_timeline(
        project.root,
        limit=limits.events,
        max_evidence_links=limits.evidence_links,
        max_detail_bytes=limits.detail_bytes,
    )
    queue = query_manual_queue(
        project.root,
        limit=limits.manual_tasks,
        max_signals=limits.signals,
        max_evidence_links=limits.evidence_links,
        max_detail_bytes=limits.detail_bytes,
    )
    notes = query_notes(
        project.root,
        limit=limits.notes,
        max_body_bytes=limits.note_bytes,
    )

    with database.connect() as connection:
        capture_id = _capture_id(connection, project.capture_sha256)
        capture = dict(
            connection.execute(
                "SELECT capture_id,source_name,byte_length,sha256,format,created_at "
                "FROM capture WHERE id=?",
                (capture_id,),
            ).fetchone()
        )
        capture["database_schema"] = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        artifacts = _artifact_collection(connection, capture_id, limits.artifacts)
        review_marks = _review_mark_collection(connection, capture_id, limits.review_marks)
        evidence = _evidence_collection(connection, capture_id, limits.evidence)
        tool_runs = _tool_run_collection(connection, limits.tool_runs)
        detector_runs = _detector_run_collection(connection, capture_id, limits.detector_runs)

    protocols = _collection(summary.protocol_total, limits.protocols, list(summary.protocols))
    conversations = _collection(
        summary.conversation_total, limits.conversations, list(summary.conversations)
    )
    candidates = _collection(
        findings.candidate_total, limits.candidates, list(findings.candidates)
    )
    finding_items = _collection(
        findings.finding_total, limits.findings, list(findings.findings)
    )
    events = _collection(timeline.total, limits.events, list(timeline.items))
    manual_tasks = _collection(queue.total, limits.manual_tasks, list(queue.items))
    note_items = _collection(notes.total, limits.notes, list(notes.items))
    collections = {
        "protocols": protocols,
        "conversations": conversations,
        "candidates": candidates,
        "findings": finding_items,
        "events": events,
        "artifacts": artifacts,
        "manual_tasks": manual_tasks,
        "review_marks": review_marks,
        "notes": note_items,
        "evidence": evidence,
        "tool_runs": tool_runs,
        "detector_runs": detector_runs,
    }
    payload: dict[str, object] = {
        "schema_version": "auto-shark.report/v1",
        "capture": capture,
        "coverage": summary.coverage,
        "limits": asdict(limits),
        "overview": {
            name: int(collection["total"]) for name, collection in collections.items()
        },
        "assessment": _assessment(collections),
        **collections,
    }
    return ReportDocument(_redact_local_paths(payload, project))


def _assessment(collections: dict) -> dict:
    """Derive a coarse challenge-type verdict and next-step focus lines."""

    def items(name: str) -> list:
        collection = collections.get(name) or {}
        return list(collection.get("items") or [])

    behaviors = []
    protocol_counts = {
        str(item.get("protocol_label")): int(item.get("frame_count") or 0)
        for item in items("protocols")
    }
    if protocol_counts.get("rtp"):
        behaviors.append(
            {
                "kind": "voip-traffic",
                "source": "protocol-inventory",
                "count": protocol_counts["rtp"],
                "hint": (
                    "Inspect SIP/SDP setup and both RTP directions. Run voip-extract "
                    "to reconstruct supported G.711 streams as WAV; if playback sounds "
                    "like modem tones, try an FSK decoder such as minimodem."
                ),
            }
        )
    if protocol_counts.get("snmp"):
        behaviors.append(
            {
                "kind": "snmp-traffic",
                "source": "protocol-inventory",
                "count": protocol_counts["snmp"],
                "hint": (
                    "Review SNMP community strings, OIDs, and response OctetString "
                    "values for sensitive host information or embedded flags."
                ),
            }
        )
    dns_evidence = [
        item for item in items("evidence") if item.get("source_kind") == "dns-label-stream"
    ]
    if dns_evidence:
        behaviors.append(
            {
                "kind": "dns-encoded-labels",
                "source": "dns-label-triage",
                "count": len(dns_evidence),
                "hint": (
                    "Review the encoded-label groups, duplicate rate, decoded preview, "
                    "and any structurally validated recovered artifacts."
                ),
            }
        )
    tftp_evidence = [
        item for item in items("evidence") if item.get("source_kind") == "tftp-data"
    ]
    if tftp_evidence:
        behaviors.append(
            {
                "kind": "tftp-file-transfer",
                "source": "tftp-reassembly",
                "count": len(tftp_evidence),
                "hint": (
                    "Review both RRQ downloads and WRQ uploads. Inspect recovered text and "
                    "file metadata before using bounded image or archive analyzers."
                ),
            }
        )
    smtp_evidence = [
        item for item in items("evidence") if item.get("source_kind") == "smtp-attachment"
    ]
    if smtp_evidence:
        behaviors.append(
            {
                "kind": "smtp-mime-attachment",
                "source": "smtp-mime-recovery",
                "count": len(smtp_evidence),
                "hint": "Review recovered mail attachments and their exact TCP/MIME provenance.",
            }
        )
    detector_counts: dict[str, int] = {}
    for finding in items("findings"):
        detector = str(finding.get("detector", "unknown"))
        detector_counts[detector] = detector_counts.get(detector, 0) + 1
    for detector, count in sorted(detector_counts.items()):
        if "sql-injection" in detector:
            kind, hint = "sql-injection", (
                "Inspect the flagged parameters and response differences; compare "
                "against the clean baseline requests when present."
            )
        elif "webshell" in detector:
            kind, hint = "webshell-activity", (
                "Follow the operation timeline: uploads, directory listings, "
                "file writes/reads, and encoded command traffic."
            )
        elif "ognl" in detector:
            kind, hint = "web-command-execution", (
                "Inspect the exact URL form field name, extracted command, and "
                "the correlated HTTP response evidence."
            )
        elif detector == "icmp-ttl-oracle":
            kind, hint = "icmp-ttl-oracle", (
                "Read candidate ASCII from request TTL values and use explicit echo reply "
                "references as the acceptance oracle. Do not infer uncaptured steps."
            )
        elif detector.startswith("image-analyzer"):
            kind, hint = "image-analysis", (
                "Review the preserved analyzer reports for the image artifacts."
            )
        else:
            kind, hint = detector, "Review the finding evidence links."
        behaviors.append(
            {"kind": kind, "source": detector, "count": count, "hint": hint}
        )

    candidates = items("candidates")
    top = candidates[0] if candidates else None
    candidate_summary = {
        "total": int((collections.get("candidates") or {}).get("total", len(candidates))),
        "top": None
        or (top and {
            "kind": top.get("kind"),
            "rank_score": top.get("rank_score"),
            "value": top.get("normalized_value"),
        }),
    }
    artifact_summary = {
        "image": 0,
        "audio": 0,
        "archive": 0,
        "executable": 0,
        "other": 0,
    }
    for artifact in items("artifacts"):
        media = str(artifact.get("detected_media_type") or "")
        if media.startswith("image/"):
            artifact_summary["image"] += 1
        elif media.startswith("audio/"):
            artifact_summary["audio"] += 1
        elif any(token in media for token in ("zip", "rar", "gzip", "compressed")):
            artifact_summary["archive"] += 1
        elif "executable" in media or media == "application/x-dosexec":
            artifact_summary["executable"] += 1
        else:
            artifact_summary["other"] += 1

    focus: list[str] = []
    if top is not None:
        focus.append(
            f"Top candidate ({top.get('kind')}, rank {top.get('rank_score')}): "
            f"{top.get('normalized_value')}"
        )
    if artifact_summary["archive"]:
        focus.append(
            f"{artifact_summary['archive']} archive artifact(s) need manual review; "
            "password recovery stays out of scope by design."
        )
    if artifact_summary["image"]:
        focus.append(
            f"{artifact_summary['image']} image artifact(s) available for declared "
            "image analyzers."
        )
    if artifact_summary["audio"]:
        focus.append(
            f"{artifact_summary['audio']} audio artifact(s) are ready for playback or "
            "bounded audio analyzers."
        )
    if protocol_counts.get("rtp"):
        focus.append(
            "VoIP/RTP traffic detected: correlate SIP/SDP, reconstruct both audio "
            "directions, and treat telephone-event packets as possible DTMF."
        )
    if protocol_counts.get("rtpevent"):
        focus.append(
            f"{protocol_counts['rtpevent']} RTP telephone-event packet(s) need DTMF review."
        )
    if protocol_counts.get("snmp"):
        focus.append(
            "SNMP traffic detected: inspect community/OID request-response pairs and "
            "search bounded variable-binding text."
        )
    if dns_evidence:
        focus.append(
            f"{len(dns_evidence)} suspicious DNS encoded-label group(s) need framing "
            "and ordering review; validated recovered files are listed as artifacts."
        )
    if tftp_evidence:
        focus.append(
            f"{len(tftp_evidence)} TFTP transfer(s) reconstructed; review incomplete "
            "block states and never execute transferred packages."
        )
    open_tasks = sum(
        1 for task in items("manual_tasks") if task.get("state") == "open"
    )
    if open_tasks:
        focus.append(f"{open_tasks} open manual-review task(s) in the queue.")
    events = items("events")
    if events:
        focus.append(f"{len(events)} behavior event(s) on the WebShell timeline.")
    return {
        "behaviors": behaviors,
        "candidate_summary": candidate_summary,
        "artifact_summary": artifact_summary,
        "suggested_focus": focus,
    }
