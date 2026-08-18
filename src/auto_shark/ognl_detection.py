"""Bounded Struts/OGNL command-injection detection in URL form field names."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import EvidenceLocator, evidence_id, stable_id
from .project import inspect_project
from .storage import Database
from .transforms.form import FormFieldValue, parse_urlencoded_form

DETECTOR = "struts-ognl-command-injection"
DETECTOR_VERSION = "1"
COMMAND_PATTERN = re.compile(
    r"(?is)(?:ProcessBuilder|(?:Runtime|getRuntime)\s*\(\s*\)\s*\.exec)"
    r"[^'\"]{0,96}['\"]([^'\"]{1,512})['\"]"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class OgnlClassification:
    markers: tuple[str, ...]
    command: Optional[str]


@dataclass(frozen=True)
class OgnlDetectionSummary:
    schema_version: str
    project: str
    run_id: str
    status: str
    transactions_processed: int
    fields_processed: int
    inputs_skipped: int
    events: int
    findings: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def classify_ognl_field_name(name: str) -> Optional[OgnlClassification]:
    lowered = name.lower()
    if "${" not in name and "%{" not in name:
        return None
    context_markers = tuple(
        marker
        for marker in ("#context", "#request", "#req", "com.opensymphony", "ognl", "struts")
        if marker in lowered
    )
    execution_markers = tuple(
        marker
        for marker in ("processbuilder", "java.lang.runtime", "getruntime(", ".exec(")
        if marker in lowered
    )
    if not context_markers or not execution_markers:
        return None
    command_match = COMMAND_PATTERN.search(name)
    command = command_match.group(1).strip() if command_match is not None else None
    return OgnlClassification(
        markers=("ognl-expression", *context_markers, *execution_markers),
        command=command,
    )


def _transaction_rows(connection: sqlite3.Connection, capture_id: int) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT tr.id transaction_db_id,tr.transaction_id,req.id request_message_db_id,"
        "req.message_id request_message_public_id,req.representative_frame request_frame,"
        "hm.method,hm.uri,qev.id request_body_evidence_db_id,"
        "qev.evidence_id request_body_evidence_public_id,qev.blob_id request_body_blob_id,"
        "qb.sha256 request_body_sha256,qb.byte_length request_body_bytes,"
        "qb.relative_path request_body_relative_path,"
        "resp.representative_frame response_frame,rev.id response_evidence_db_id,"
        "rev.evidence_id response_evidence_public_id "
        "FROM transaction_record tr JOIN protocol_message req ON req.id=tr.request_message_id "
        "JOIN http_message hm ON hm.protocol_message_id=req.id "
        "JOIN http_body qbody ON qbody.protocol_message_id=req.id "
        "JOIN evidence qev ON qev.id=qbody.evidence_id JOIN blob qb ON qb.id=qev.blob_id "
        "LEFT JOIN protocol_message resp ON resp.id=tr.response_message_id "
        "LEFT JOIN http_body rbody ON rbody.protocol_message_id=resp.id "
        "LEFT JOIN evidence rev ON rev.id=rbody.evidence_id "
        "WHERE tr.capture_id=? AND upper(coalesce(hm.method,''))='POST' "
        "AND lower(coalesce(hm.content_type,'')) LIKE 'application/x-www-form-urlencoded%' "
        "AND qbody.status='complete' ORDER BY req.representative_frame,tr.id",
        (capture_id,),
    ).fetchall()


def _safe_blob_path(root: Path, relative_path: str) -> Path:
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("blob path escapes the analysis project") from error
    return path


def _read_verified_body(project_root: Path, transaction: sqlite3.Row, limit: int) -> bytes:
    path = _safe_blob_path(project_root, str(transaction["request_body_relative_path"]))
    with path.open("rb") as stream:
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise ValueError("request body exceeds the configured byte limit")
    expected_bytes = int(transaction["request_body_bytes"])
    expected_sha256 = str(transaction["request_body_sha256"])
    if len(body) != expected_bytes or hashlib.sha256(body).hexdigest() != expected_sha256:
        raise ValueError("request body blob verification failed")
    return body


def _insert_skip(
    connection: sqlite3.Connection,
    detector_run_id: int,
    scope_kind: str,
    scope_id: str,
    reason: str,
    detail: dict[str, object],
) -> None:
    connection.execute(
        "INSERT INTO detector_skip(detector_run_id,scope_kind,scope_id,reason,count,"
        "detail_json) VALUES(?,?,?,?,1,?) ON CONFLICT(detector_run_id,scope_kind,"
        "scope_id,reason) DO UPDATE SET count=detector_skip.count+1,"
        "detail_json=excluded.detail_json",
        (
            detector_run_id,
            scope_kind,
            scope_id,
            reason,
            json.dumps(detail, ensure_ascii=False, sort_keys=True),
        ),
    )


def _persist_name_evidence(
    connection: sqlite3.Connection,
    capture_id: int,
    capture_sha256: str,
    transaction: sqlite3.Row,
    field: FormFieldValue,
) -> tuple[int, str]:
    locator = EvidenceLocator(
        capture_sha256=capture_sha256,
        source_kind="form-field-name-injection",
        frame_start=int(transaction["request_frame"]),
        frame_end=int(transaction["request_frame"]),
        protocol_message=str(transaction["request_message_public_id"]),
        byte_offset=field.raw_name_offset,
        byte_length=field.raw_name_length,
        field_name="url-form-name",
    )
    public_id = evidence_id(locator)
    text_value = field.name if len(field.name.encode("utf-8")) <= 4096 else None
    connection.execute(
        "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
        "protocol_message_id,transaction_id,byte_offset,byte_length,field_name,text_value,"
        "blob_id,locator_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(evidence_id) DO UPDATE SET text_value=excluded.text_value,"
        "locator_json=excluded.locator_json",
        (
            public_id,
            capture_id,
            "form-field-name-injection",
            int(transaction["request_frame"]),
            int(transaction["request_frame"]),
            int(transaction["request_message_db_id"]),
            int(transaction["transaction_db_id"]),
            field.raw_name_offset,
            field.raw_name_length,
            "url-form-name",
            text_value,
            int(transaction["request_body_blob_id"]),
            json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
        ),
    )
    internal_id = int(
        connection.execute("SELECT id FROM evidence WHERE evidence_id=?", (public_id,)).fetchone()[
            0
        ]
    )
    return internal_id, public_id


def _persist_event(
    connection: sqlite3.Connection,
    capture_id: int,
    capture_sha256: str,
    detector_run_id: int,
    transaction: sqlite3.Row,
    field: FormFieldValue,
    classification: OgnlClassification,
    evidence_db_id: int,
    evidence_public_id: str,
    max_preview_bytes: int,
) -> tuple[int, str]:
    command = classification.command or "(command requires payload review)"
    endpoint = f"{str(transaction['method']).upper()} {transaction['uri']}"
    semantic_key = stable_id(
        "ognl-command-semantic",
        {"endpoint": endpoint, "command": command.casefold()},
    )
    event_public_id = stable_id(
        "behavior-event",
        {
            "detector": DETECTOR,
            "version": DETECTOR_VERSION,
            "transaction_id": str(transaction["transaction_id"]),
            "ordinal": field.ordinal,
        },
    )
    duplicate = connection.execute(
        "SELECT id FROM behavior_event WHERE capture_id=? AND detector=? AND semantic_key=? "
        "AND request_frame<? ORDER BY request_frame,id LIMIT 1",
        (capture_id, DETECTOR, semantic_key, int(transaction["request_frame"])),
    ).fetchone()
    preview_bytes = field.name.encode("utf-8")
    preview_truncated = len(preview_bytes) > max_preview_bytes
    preview = preview_bytes[:max_preview_bytes].decode("utf-8", errors="ignore")
    response_evidence_db_id = transaction["response_evidence_db_id"]
    status = "complete" if response_evidence_db_id is not None else "partial"
    detail = {
        "command": classification.command,
        "field_name_evidence_id": evidence_public_id,
        "markers": classification.markers,
        "preview": preview,
        "preview_truncated": preview_truncated,
        "raw_name_length": field.raw_name_length,
        "raw_name_offset": field.raw_name_offset,
        "response_evidence_id": transaction["response_evidence_public_id"],
    }
    connection.execute(
        "INSERT INTO behavior_event(event_id,capture_id,transaction_id,protocol_message_id,"
        "detector,detector_version,event_kind,status,request_frame,response_frame,target,"
        "semantic_key,confidence,detail_json,duplicate_of,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET "
        "status=excluded.status,response_frame=excluded.response_frame,target=excluded.target,"
        "confidence=excluded.confidence,detail_json=excluded.detail_json,"
        "duplicate_of=excluded.duplicate_of",
        (
            event_public_id,
            capture_id,
            int(transaction["transaction_db_id"]),
            int(transaction["request_message_db_id"]),
            DETECTOR,
            DETECTOR_VERSION,
            "web-command-execution",
            status,
            int(transaction["request_frame"]),
            (
                int(transaction["response_frame"])
                if transaction["response_frame"] is not None
                else None
            ),
            command,
            semantic_key,
            0.99 if status == "complete" else 0.80,
            json.dumps(detail, ensure_ascii=False, sort_keys=True),
            int(duplicate[0]) if duplicate is not None else None,
            _now(),
        ),
    )
    event_db_id = int(
        connection.execute("SELECT id FROM behavior_event WHERE event_id=?", (event_public_id,))
        .fetchone()[0]
    )
    connection.execute("DELETE FROM behavior_event_evidence WHERE event_id=?", (event_db_id,))
    connection.execute(
        "INSERT INTO behavior_event_evidence(event_id,evidence_id,role) "
        "VALUES(?,?,'field-name')",
        (event_db_id, evidence_db_id),
    )
    if response_evidence_db_id is not None:
        connection.execute(
            "INSERT INTO behavior_event_evidence(event_id,evidence_id,role) "
            "VALUES(?,?,'response')",
            (event_db_id, int(response_evidence_db_id)),
        )
    connection.execute(
        "INSERT OR IGNORE INTO behavior_event_run(event_id,detector_run_id) VALUES(?,?)",
        (event_db_id, detector_run_id),
    )
    return evidence_db_id, endpoint


def _persist_finding(
    connection: sqlite3.Connection,
    capture_sha256: str,
    tool_run_id: int,
    endpoint: str,
    evidence_ids: set[int],
) -> None:
    public_id = stable_id(
        "finding",
        {"capture_sha256": capture_sha256, "detector": DETECTOR, "endpoint": endpoint},
    )
    connection.execute(
        "INSERT INTO finding(finding_id,detector,detector_version,title,description,severity,"
        "confidence,recommended_action,created_at) VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(finding_id) DO UPDATE SET description=excluded.description,"
        "severity=excluded.severity,confidence=excluded.confidence",
        (
            public_id,
            DETECTOR,
            DETECTOR_VERSION,
            "Struts/OGNL command injection",
            f"An OGNL expression with a command-execution API was observed at {endpoint}.",
            "critical",
            0.99,
            "Review the exact form field name, command target, and correlated HTTP response.",
            _now(),
        ),
    )
    finding_db_id = int(
        connection.execute("SELECT id FROM finding WHERE finding_id=?", (public_id,)).fetchone()[0]
    )
    connection.execute("DELETE FROM finding_evidence WHERE finding_id=?", (finding_db_id,))
    for evidence_db_id in sorted(evidence_ids):
        connection.execute(
            "INSERT INTO finding_evidence(finding_id,evidence_id,role) "
            "VALUES(?,?,'command-expression')",
            (finding_db_id, evidence_db_id),
        )
    connection.execute(
        "INSERT OR IGNORE INTO finding_run(finding_id,tool_run_id) VALUES(?,?)",
        (finding_db_id, tool_run_id),
    )


def detect_ognl_command_injection(
    project_path: Path,
    *,
    max_transactions: int = 10_000,
    max_fields: int = 100_000,
    max_body_bytes: int = 1024 * 1024,
    max_events: int = 10_000,
    max_findings: int = 1000,
    max_preview_bytes: int = 256,
) -> OgnlDetectionSummary:
    if min(
        max_transactions,
        max_fields,
        max_body_bytes,
        max_events,
        max_findings,
        max_preview_bytes,
    ) <= 0:
        raise ValueError("OGNL detector limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    run_id = str(uuid4())
    policy = {
        "max_body_bytes": max_body_bytes,
        "max_events": max_events,
        "max_fields": max_fields,
        "max_findings": max_findings,
        "max_preview_bytes": max_preview_bytes,
        "max_transactions": max_transactions,
    }
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO detector_run(run_id,capture_id,detector_set,detector_version,"
            "policy_json,status,inputs_processed,inputs_skipped,candidates,findings,events,"
            "started_at) VALUES(?,?,?,?,?,'partial',0,0,0,0,0,?)",
            (
                run_id,
                capture_id,
                DETECTOR,
                DETECTOR_VERSION,
                json.dumps(policy, sort_keys=True),
                _now(),
            ),
        )
        detector_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        tool_run_public_id = uuid4().hex
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,tool_version,argv_json,started_at,status) "
            "VALUES(?,?,?,?,?,'running')",
            (
                tool_run_public_id,
                "auto-shark-ognl-detector",
                DETECTOR_VERSION,
                json.dumps(policy, sort_keys=True),
                _now(),
            ),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])

    status = "completed"
    processed = fields_processed = skipped = events = 0
    finding_evidence: dict[str, set[int]] = {}
    try:
        with database.connect() as connection:
            transactions = _transaction_rows(connection, capture_id)
            for index, transaction in enumerate(transactions):
                transaction_public_id = str(transaction["transaction_id"])
                if index >= max_transactions:
                    _insert_skip(
                        connection,
                        detector_run_id,
                        "transaction",
                        transaction_public_id,
                        "transaction-limit",
                        {"max_transactions": max_transactions},
                    )
                    skipped += 1
                    status = "budget-limited"
                    continue
                processed += 1
                body_bytes = int(transaction["request_body_bytes"])
                if body_bytes > max_body_bytes:
                    _insert_skip(
                        connection,
                        detector_run_id,
                        "transaction",
                        transaction_public_id,
                        "body-byte-limit",
                        {"body_bytes": body_bytes, "max_body_bytes": max_body_bytes},
                    )
                    skipped += 1
                    status = "budget-limited"
                    continue
                try:
                    body = _read_verified_body(project.root, transaction, max_body_bytes)
                except (OSError, ValueError) as error:
                    _insert_skip(
                        connection,
                        detector_run_id,
                        "transaction",
                        transaction_public_id,
                        "body-unavailable",
                        {"error": str(error)[:500]},
                    )
                    skipped += 1
                    status = "partial"
                    continue
                try:
                    fields = parse_urlencoded_form(body, max_fields=max_fields)
                except ValueError as error:
                    _insert_skip(
                        connection,
                        detector_run_id,
                        "transaction",
                        transaction_public_id,
                        "form-parse-failed",
                        {"error": str(error)},
                    )
                    skipped += 1
                    status = "partial"
                    continue
                for field in fields:
                    if fields_processed >= max_fields:
                        _insert_skip(
                            connection,
                            detector_run_id,
                            "field",
                            f"{transaction_public_id}:{field.ordinal}",
                            "field-limit",
                            {"max_fields": max_fields},
                        )
                        skipped += 1
                        status = "budget-limited"
                        continue
                    fields_processed += 1
                    classification = classify_ognl_field_name(field.name)
                    if classification is None:
                        continue
                    if events >= max_events:
                        _insert_skip(
                            connection,
                            detector_run_id,
                            "field",
                            f"{transaction_public_id}:{field.ordinal}",
                            "event-limit",
                            {"max_events": max_events},
                        )
                        skipped += 1
                        status = "budget-limited"
                        continue
                    evidence_db_id, evidence_public_id = _persist_name_evidence(
                        connection,
                        capture_id,
                        project.capture_sha256,
                        transaction,
                        field,
                    )
                    evidence_db_id, endpoint = _persist_event(
                        connection,
                        capture_id,
                        project.capture_sha256,
                        detector_run_id,
                        transaction,
                        field,
                        classification,
                        evidence_db_id,
                        evidence_public_id,
                        max_preview_bytes,
                    )
                    finding_evidence.setdefault(endpoint, set()).add(evidence_db_id)
                    events += 1
            finding_count = 0
            for endpoint, evidence_ids in sorted(finding_evidence.items()):
                if finding_count >= max_findings:
                    _insert_skip(
                        connection,
                        detector_run_id,
                        "finding",
                        endpoint,
                        "finding-limit",
                        {"max_findings": max_findings},
                    )
                    skipped += 1
                    status = "budget-limited"
                    continue
                _persist_finding(
                    connection,
                    project.capture_sha256,
                    tool_run_id,
                    endpoint,
                    evidence_ids,
                )
                finding_count += 1
            connection.execute(
                "UPDATE detector_run SET status=?,inputs_processed=?,inputs_skipped=?,"
                "findings=?,events=?,ended_at=? WHERE id=?",
                (status, processed, skipped, finding_count, events, _now(), detector_run_id),
            )
            connection.execute(
                "UPDATE tool_run SET status='completed',exit_code=0,ended_at=? WHERE id=?",
                (_now(), tool_run_id),
            )
    except Exception as error:
        with database.connect() as connection:
            connection.execute(
                "UPDATE detector_run SET status='failed',inputs_skipped=inputs_skipped+1,"
                "ended_at=? WHERE id=?",
                (_now(), detector_run_id),
            )
            connection.execute(
                "UPDATE tool_run SET status='failed',exit_code=1,stderr_text=?,ended_at=? "
                "WHERE id=?",
                (f"{type(error).__name__}: {error}"[:4096], _now(), tool_run_id),
            )
        raise
    return OgnlDetectionSummary(
        "auto-shark.ognl-detection/v1",
        str(project.root),
        run_id,
        status,
        processed,
        fields_processed,
        skipped,
        events,
        finding_count,
    )
