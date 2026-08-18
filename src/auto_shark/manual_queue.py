"""Persistent, idempotent manual-analysis task generation and state updates."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .core.ids import stable_id
from .project import inspect_project
from .storage import Database

RULE_VERSION = "corpus-v3"
TASK_STATES = frozenset({"open", "in-progress", "resolved", "dismissed"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ManualQueueSummary:
    schema_version: str
    project: str
    queue_run_id: str
    status: str
    created: int
    updated: int
    skipped: int
    tasks: int
    signals: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class _Signal:
    subject_kind: str
    subject_id: str
    task_kind: str
    rule_name: str
    score: int
    detail: dict[str, object]
    evidence: tuple[tuple[int, str], ...] = ()


def _candidate_signals(
    connection: sqlite3.Connection, capture_id: int
) -> list[_Signal]:
    result = []
    rows = connection.execute(
        "SELECT DISTINCT c.id,c.candidate_id,c.kind,c.rank_score FROM candidate c "
        "JOIN candidate_evidence ce ON ce.candidate_id=c.id "
        "JOIN evidence e ON e.id=ce.evidence_id WHERE e.capture_id=?",
        (capture_id,),
    ).fetchall()
    for row in rows:
        kind = str(row["kind"])
        score = float(row["rank_score"])
        if score >= 100:
            rule, priority = "rank-100-known-format", 100
        elif kind == "sensitive-field":
            rule, priority = "sensitive-field", 80
        elif kind == "unknown-flag" and score >= 70:
            rule, priority = "unknown-flag-like", 70
        else:
            continue
        evidence = tuple(
            (int(item["evidence_id"]), str(item["role"]))
            for item in connection.execute(
                "SELECT evidence_id,role FROM candidate_evidence WHERE candidate_id=?",
                (row["id"],),
            )
        )
        result.append(
            _Signal(
                "candidate",
                str(row["candidate_id"]),
                "candidate-review",
                rule,
                priority,
                {"candidate_kind": kind, "rank_score": score},
                evidence,
            )
        )
    return result


def _finding_signals(connection: sqlite3.Connection, capture_id: int) -> list[_Signal]:
    result = []
    for row in connection.execute(
        "SELECT DISTINCT f.id,f.finding_id,f.detector,f.severity FROM finding f "
        "JOIN finding_evidence fe ON fe.finding_id=f.id "
        "JOIN evidence e ON e.id=fe.evidence_id WHERE e.capture_id=?",
        (capture_id,),
    ):
        detector = str(row["detector"])
        priority = 90 if detector == "http-status-body-contradiction" else 85
        evidence = tuple(
            (int(item["evidence_id"]), str(item["role"]))
            for item in connection.execute(
                "SELECT evidence_id,role FROM finding_evidence WHERE finding_id=?",
                (row["id"],),
            )
        )
        result.append(
            _Signal(
                "finding",
                str(row["finding_id"]),
                "finding-review",
                detector,
                priority,
                {"detector": detector, "severity": str(row["severity"])},
                evidence,
            )
        )
    return result


def _artifact_signals(connection: sqlite3.Connection, capture_id: int) -> list[_Signal]:
    result = []
    rows = connection.execute(
        "SELECT a.id,a.artifact_id,a.source_evidence_id,a.detected_media_type,"
        "a.suggested_name "
        "FROM artifact a JOIN evidence e ON e.id=a.source_evidence_id "
        "WHERE a.review_state='unreviewed' AND e.capture_id=?",
        (capture_id,),
    ).fetchall()
    for row in rows:
        media_type = str(row["detected_media_type"] or "").lower()
        name = str(row["suggested_name"] or "").lower()
        risky = (
            media_type
            in {
                "application/zip",
                "application/vnd.rar",
                "application/x-rar",
                "application/x-dosexec",
            }
            or name.endswith((".zip", ".rar", ".exe", ".dll"))
        )
        if not risky:
            continue
        evidence = (
            ((int(row["source_evidence_id"]), "artifact"),)
            if row["source_evidence_id"] is not None
            else ()
        )
        result.append(
            _Signal(
                "artifact",
                str(row["artifact_id"]),
                "artifact-review",
                "unreviewed-archive-or-executable",
                80,
                {"detected_media_type": media_type or None, "suggested_name": name or None},
                evidence,
            )
        )
    return result


def _tcp_signals(connection: sqlite3.Connection, capture_id: int) -> list[_Signal]:
    result = []
    rows = connection.execute(
        "SELECT tr.reconstruction_id,tr.evidence_id,tr.status,tr.conflict_bytes,tr.gap_bytes,"
        "c.conversation_id FROM tcp_reconstruction tr "
        "JOIN conversation c ON c.id=tr.conversation_id WHERE c.capture_id=? "
        "AND (tr.status IN ('partial','conflicting','truncated') "
        "OR tr.conflict_bytes>0 OR tr.gap_bytes>0)",
        (capture_id,),
    ).fetchall()
    for row in rows:
        evidence = (
            ((int(row["evidence_id"]), "reconstruction"),)
            if row["evidence_id"] is not None
            else ()
        )
        result.append(
            _Signal(
                "conversation",
                str(row["conversation_id"]),
                "protocol-review",
                "tcp-conflict-gap-or-partial",
                85,
                {
                    "conflict_bytes": int(row["conflict_bytes"]),
                    "gap_bytes": int(row["gap_bytes"]),
                    "reconstruction_id": str(row["reconstruction_id"]),
                    "status": str(row["status"]),
                },
                evidence,
            )
        )
    return result


def _http_signals(connection: sqlite3.Connection, capture_id: int) -> list[_Signal]:
    result = []
    rows = connection.execute(
        "SELECT transaction_id,status FROM transaction_record "
        "WHERE capture_id=? AND status IN ('unmatched-request','orphan-response')",
        (capture_id,),
    ).fetchall()
    for row in rows:
        status = str(row["status"])
        result.append(
            _Signal(
                "transaction",
                str(row["transaction_id"]),
                "protocol-review",
                status,
                75 if status == "orphan-response" else 70,
                {"transaction_status": status},
            )
        )
    trailing = connection.execute(
        "SELECT id,evidence_id FROM evidence "
        "WHERE capture_id=? AND source_kind='trailing-data'",
        (capture_id,),
    ).fetchall()
    for row in trailing:
        evidence_db_id = int(row["id"])
        public_id = str(row["evidence_id"])
        result.append(
            _Signal(
                "evidence",
                public_id,
                "artifact-review",
                "trailing-data",
                65,
                {},
                ((evidence_db_id, "trailing-data"),),
            )
        )
    return result


def _dns_signals(connection: sqlite3.Connection, capture_id: int) -> list[_Signal]:
    result = []
    rows = connection.execute(
        "SELECT id,evidence_id,frame_start,frame_end,locator_json FROM evidence "
        "WHERE capture_id=? AND source_kind='dns-label-stream' ORDER BY frame_start",
        (capture_id,),
    ).fetchall()
    for row in rows:
        detail = json.loads(str(row["locator_json"]))
        score = max(60, min(100, int(detail.get("score", 60))))
        detail["next_step"] = (
            "Review the bounded decoded preview and retransmissions. Export only "
            "structurally validated artifacts; otherwise confirm framing and ordering manually."
        )
        result.append(
            _Signal(
                "evidence",
                str(row["evidence_id"]),
                "protocol-review",
                "suspicious-dns-encoded-labels",
                score,
                detail,
                ((int(row["id"]), "dns-label-stream"),),
            )
        )
    return result


def _tftp_signals(connection: sqlite3.Connection, capture_id: int) -> list[_Signal]:
    result = []
    rows = connection.execute(
        "SELECT id,evidence_id,locator_json FROM evidence "
        "WHERE capture_id=? AND source_kind='tftp-data' ORDER BY frame_start,evidence_id",
        (capture_id,),
    ).fetchall()
    for row in rows:
        detail = json.loads(str(row["locator_json"]))
        status = str(detail.get("status") or "unknown")
        complete = status in {"complete", "empty"}
        detail["next_step"] = (
            "Inspect the recovered file bytes and metadata; do not execute transferred "
            "packages. Continue with declared image/archive analyzers when appropriate."
            if complete
            else "Review missing, conflicting, or budget-limited TFTP blocks before "
            "treating the reconstructed bytes as a complete file."
        )
        result.append(
            _Signal(
                "evidence",
                str(row["evidence_id"]),
                "artifact-review" if complete else "protocol-review",
                "tftp-file-transfer" if complete else "tftp-incomplete-transfer",
                70 if complete else 85,
                detail,
                ((int(row["id"]), "tftp-transfer"),),
            )
        )
    return result


def _smtp_signals(connection: sqlite3.Connection, capture_id: int) -> list[_Signal]:
    result = []
    rows = connection.execute(
        "SELECT sa.attachment_id,sa.status,sa.filename,sa.declared_media_type,"
        "sa.evidence_id,sm.data_frame FROM smtp_attachment sa "
        "JOIN smtp_message sm ON sm.id=sa.smtp_message_id WHERE sm.capture_id=? "
        "ORDER BY sm.data_frame,sa.ordinal",
        (capture_id,),
    ).fetchall()
    for row in rows:
        complete = str(row["status"]) == "complete"
        evidence = (
            ((int(row["evidence_id"]), "smtp-attachment"),)
            if row["evidence_id"] is not None
            else ()
        )
        result.append(
            _Signal(
                "evidence" if evidence else "smtp-attachment",
                (
                    str(
                        connection.execute(
                            "SELECT evidence_id FROM evidence WHERE id=?",
                            (row["evidence_id"],),
                        ).fetchone()[0]
                    )
                    if evidence
                    else str(row["attachment_id"])
                ),
                "artifact-review" if complete else "protocol-review",
                "smtp-mime-attachment" if complete else "smtp-incomplete-attachment",
                70 if complete else 85,
                {
                    "data_frame": int(row["data_frame"]),
                    "filename": str(row["filename"] or ""),
                    "media_type": str(row["declared_media_type"] or ""),
                    "status": str(row["status"]),
                    "next_step": (
                        "Inspect the recovered MIME attachment without executing it."
                        if complete
                        else (
                            "Review the MIME decode or budget failure before treating "
                            "the attachment as complete."
                        )
                    ),
                },
                evidence,
            )
        )
    return result


def _unsupported_signals(
    connection: sqlite3.Connection,
    capture_id: int,
    max_unsupported_tasks: int,
) -> tuple[list[_Signal], int]:
    rows = connection.execute(
        "SELECT ac.subject_id,po.protocol_label,po.frame_count FROM analysis_coverage ac "
        "JOIN protocol_observation po ON po.observation_id=ac.subject_id "
        "WHERE ac.capture_id=? AND ac.subject_kind='protocol' "
        "AND ac.status='unavailable' AND po.protocol_label NOT IN ('dns','ssdp') "
        "ORDER BY po.frame_count DESC,po.protocol_label",
        (capture_id,),
    ).fetchall()
    selected = rows[:max_unsupported_tasks]
    result = []
    for row in selected:
        label = str(row["protocol_label"])
        frame_count = int(row["frame_count"])
        detail: dict[str, object] = {
            "frame_count": frame_count,
            "protocol_label": label,
        }
        if label == "rtp":
            rule, priority = "voip-rtp-audio", 75
            detail["next_step"] = (
                "Run voip-extract for G.711, review both call directions, and listen "
                "for speech, DTMF, or modem tones."
            )
        elif label == "rtpevent":
            rule, priority = "rtp-telephone-event", 70
            detail["next_step"] = (
                "Review RTP telephone-event values separately as possible DTMF digits."
            )
        elif label in {"sip", "sdp"}:
            rule, priority = "voip-signaling", 60
            detail["next_step"] = (
                "Inspect SIP/SDP call setup, negotiated codecs, media ports, and call IDs."
            )
        elif label == "snmp":
            rule, priority = "snmp-sensitive-values", 65
            detail["next_step"] = (
                "Review SNMP community strings, request/response OIDs, and bounded "
                "OctetString/variable-binding text for credentials, host details, or flags."
            )
        elif label == "icmp":
            rule, priority = "icmp-side-channel-review", 55
            detail["next_step"] = (
                "Run icmp-triage. Compare echo requests with explicit response frames, inspect "
                "printable or varying TTL values, and review nonstandard payload bytes."
            )
        elif label == "tftp":
            rule, priority = "tftp-traffic", 65
            detail["next_step"] = (
                "Run tftp-extract to reconstruct both RRQ downloads and WRQ uploads, "
                "then inspect transferred files without executing them."
            )
        elif label == "tls":
            rule, priority = "tls-encrypted-traffic", 55
            detail["next_step"] = (
                "Look for a challenge-provided TLS key log or RSA private key. Import it into "
                "Wireshark/TShark; RSA keys only decrypt compatible legacy RSA key exchanges, "
                "not ECDHE or TLS 1.3 sessions."
            )
        else:
            rule = "unsupported-protocol"
            priority = min(60, 30 + int(frame_count > 10) * 10)
        result.append(
            _Signal(
                "protocol",
                str(row["subject_id"]),
                "protocol-review",
                rule,
                priority,
                detail,
            )
        )
    return result, max(0, len(rows) - len(selected))


def _coverage_signals(connection: sqlite3.Connection, capture_id: int) -> list[_Signal]:
    result = []
    rows = connection.execute(
        "SELECT subject_kind,subject_id,status,detail_json FROM analysis_coverage "
        "WHERE capture_id=? AND status IN ('failed','partial','budget-limited')",
        (capture_id,),
    ).fetchall()
    for row in rows:
        status = str(row["status"])
        priority = 90 if status == "failed" else 85
        result.append(
            _Signal(
                str(row["subject_kind"]),
                str(row["subject_id"]),
                "protocol-review",
                f"analysis-{status}",
                priority,
                json.loads(str(row["detail_json"])),
            )
        )
    return result


def rebuild_manual_queue(
    project_path: Path,
    *,
    max_tasks: int = 10_000,
    max_signals: int = 50_000,
    max_evidence_links: int = 100_000,
    max_unsupported_tasks: int = 25,
) -> ManualQueueSummary:
    if min(max_tasks, max_signals, max_evidence_links, max_unsupported_tasks) <= 0:
        raise ValueError("manual queue limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    queue_run_public_id = uuid4().hex
    started_at = _now()
    policy = {
        "max_evidence_links": max_evidence_links,
        "max_signals": max_signals,
        "max_tasks": max_tasks,
        "max_unsupported_tasks": max_unsupported_tasks,
    }
    created = skipped = evidence_links = 0
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        latest_inventory = connection.execute(
            "SELECT id FROM capture_inventory_run WHERE capture_id=? ORDER BY id DESC LIMIT 1",
            (capture_id,),
        ).fetchone()
        connection.execute(
            "INSERT INTO manual_queue_run "
            "(queue_run_id,capture_id,inventory_run_id,rule_version,policy_json,status,"
            "created_count,updated_count,skipped_count,started_at) "
            "VALUES(?,?,?,?,?,'partial',0,0,0,?)",
            (
                queue_run_public_id,
                capture_id,
                int(latest_inventory["id"]) if latest_inventory else None,
                RULE_VERSION,
                json.dumps(policy, sort_keys=True),
                started_at,
            ),
        )
        queue_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        unsupported, unsupported_skipped = _unsupported_signals(
            connection, capture_id, max_unsupported_tasks
        )
        skipped += unsupported_skipped
        signals = (
            _candidate_signals(connection, capture_id)
            + _finding_signals(connection, capture_id)
            + _artifact_signals(connection, capture_id)
            + _tcp_signals(connection, capture_id)
            + _http_signals(connection, capture_id)
            + _dns_signals(connection, capture_id)
            + _tftp_signals(connection, capture_id)
            + _smtp_signals(connection, capture_id)
            + _coverage_signals(connection, capture_id)
            + unsupported
        )
        connection.execute(
            "DELETE FROM manual_task_signal WHERE task_id IN "
            "(SELECT id FROM manual_task WHERE capture_id=?)",
            (capture_id,),
        )
        connection.execute(
            "DELETE FROM manual_task_evidence WHERE task_id IN "
            "(SELECT id FROM manual_task WHERE capture_id=?)",
            (capture_id,),
        )
        seen_tasks: set[tuple[str, str, str]] = set()
        updated_tasks: set[int] = set()
        persisted_signals = 0
        for signal in signals:
            key = (signal.subject_kind, signal.subject_id, signal.task_kind)
            if key not in seen_tasks and len(seen_tasks) >= max_tasks:
                skipped += 1
                continue
            if persisted_signals >= max_signals:
                skipped += 1
                continue
            seen_tasks.add(key)
            task_public_id = stable_id(
                "manual-task",
                {
                    "capture_sha256": project.capture_sha256,
                    "subject_kind": signal.subject_kind,
                    "subject_id": signal.subject_id,
                    "task_kind": signal.task_kind,
                },
            )
            existing = connection.execute(
                "SELECT id FROM manual_task WHERE task_id=?", (task_public_id,)
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO manual_task "
                    "(task_id,capture_id,subject_kind,subject_id,task_kind,"
                    "suggested_priority,state,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,'open',?,?)",
                    (
                        task_public_id,
                        capture_id,
                        signal.subject_kind,
                        signal.subject_id,
                        signal.task_kind,
                        signal.score,
                        started_at,
                        started_at,
                    ),
                )
                task_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
                created += 1
            else:
                task_id = int(existing["id"])
                updated_tasks.add(task_id)
            connection.execute(
                "INSERT INTO manual_task_signal "
                "(task_id,queue_run_id,rule_name,rule_version,score,detail_json) "
                "VALUES(?,?,?,?,?,?)",
                (
                    task_id,
                    queue_run_id,
                    signal.rule_name,
                    RULE_VERSION,
                    signal.score,
                    json.dumps(signal.detail, sort_keys=True),
                ),
            )
            persisted_signals += 1
            for evidence_id, role in signal.evidence:
                if evidence_links >= max_evidence_links:
                    skipped += 1
                    continue
                connection.execute(
                    "INSERT OR IGNORE INTO manual_task_evidence(task_id,evidence_id,role) "
                    "VALUES(?,?,?)",
                    (task_id, evidence_id, role),
                )
                evidence_links += 1
        connection.execute(
            "UPDATE manual_task SET suggested_priority=coalesce(("
            "SELECT max(score) FROM manual_task_signal WHERE task_id=manual_task.id),0),"
            "updated_at=? WHERE capture_id=?",
            (_now(), capture_id),
        )
        status = "budget-limited" if skipped else "completed"
        updated = len(updated_tasks)
        connection.execute(
            "UPDATE manual_queue_run SET status=?,created_count=?,updated_count=?,"
            "skipped_count=?,ended_at=? WHERE id=?",
            (status, created, updated, skipped, _now(), queue_run_id),
        )
        task_count = int(
            connection.execute(
                "SELECT count(*) FROM manual_task WHERE capture_id=?", (capture_id,)
            ).fetchone()[0]
        )
    return ManualQueueSummary(
        schema_version="auto-shark.manual-queue-index/v1",
        project=str(project.root),
        queue_run_id=queue_run_public_id,
        status=status,
        created=created,
        updated=updated,
        skipped=skipped,
        tasks=task_count,
        signals=persisted_signals,
    )


def update_manual_task_state(project_path: Path, task_id: str, state: str) -> dict[str, object]:
    if state not in TASK_STATES:
        raise ValueError(f"invalid manual task state: {state}")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        cursor = connection.execute(
            "UPDATE manual_task SET state=?,updated_at=? WHERE task_id=?",
            (state, _now(), task_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"manual task not found: {task_id}")
        row = connection.execute(
            "SELECT task_id,subject_kind,subject_id,task_kind,suggested_priority,state,"
            "updated_at FROM manual_task WHERE task_id=?",
            (task_id,),
        ).fetchone()
    return {
        "schema_version": "auto-shark.manual-task/v1",
        **dict(row),
    }
