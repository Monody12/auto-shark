"""Bounded static WebShell wrapper and operation reconstruction."""

from __future__ import annotations

import hashlib
import json
import ntpath
import posixpath
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import stable_id
from .project import ProjectInfo, inspect_project
from .storage import Database

WEBSHELL_DETECTOR = "static-webshell-activity"
WEBSHELL_DETECTOR_VERSION = "1"
WRAPPER_PATTERN = re.compile(
    r"(?is)\beval\b.{0,24}?base64_decode\s*\(\s*\$_POST\s*"
    r"\[\s*['\"]?([A-Za-z_][A-Za-z0-9_-]*)"
)
BASE64_POST_PATTERN = re.compile(
    r"(?is)base64_decode\s*\(\s*\$_POST\s*\[\s*['\"]?"
    r"([A-Za-z_][A-Za-z0-9_-]*)"
)
POST_FIELD_PATTERN = re.compile(
    r"(?is)\$_POST\s*\[\s*['\"]?([A-Za-z_][A-Za-z0-9_-]*)"
)
COMMAND_PATTERN = re.compile(
    r"(?is)(?:^|[^A-Za-z0-9_])(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\("
)
DATABASE_PATTERN = re.compile(
    r"(?is)(?:mysqli?_(?:query|connect)|pg_query|sqlite_query|new\s+PDO\b)"
)


@dataclass(frozen=True)
class WebShellClassification:
    event_kind: str
    confidence: float
    markers: tuple[str, ...]
    target_required: bool


@dataclass(frozen=True)
class WebShellDetectionSummary:
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
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class _EvidenceValue:
    db_id: int
    public_id: str
    byte_length: int
    text_value: Optional[str]
    relative_path: Optional[str]
    transform_name: Optional[str] = None
    transform_status: Optional[str] = None
    transform_truncated: bool = False


@dataclass(frozen=True)
class _Field:
    ordinal: int
    name: str
    decoded: _EvidenceValue
    outputs: tuple[_EvidenceValue, ...]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def wrapper_action_parameter(value: str) -> Optional[str]:
    match = WRAPPER_PATTERN.search(value)
    return match.group(1) if match is not None else None


def classify_webshell_action(value: str) -> WebShellClassification:
    lowered = value.lower()
    if "php_uname" in lowered and (
        "get_current_user" in lowered or "posix_geteuid" in lowered
    ):
        return WebShellClassification(
            "system-information", 0.96, ("php_uname", "user-context"), False
        )
    if "opendir(" in lowered and "readdir(" in lowered:
        return WebShellClassification(
            "directory-listing", 0.97, ("opendir", "readdir"), True
        )
    if "fwrite(" in lowered and re.search(r"(?is)fopen\s*\([^,]+,\s*['\"]w", value):
        return WebShellClassification("file-write", 0.98, ("fopen-w", "fwrite"), True)
    if "fread(" in lowered and "filesize(" in lowered:
        return WebShellClassification("file-read", 0.98, ("fread", "filesize"), True)
    if re.search(r"(?is)(?:^|[^A-Za-z0-9_])unlink\s*\(", value):
        return WebShellClassification("file-delete", 0.96, ("unlink",), True)
    if re.search(r"(?is)(?:^|[^A-Za-z0-9_])rename\s*\(", value):
        return WebShellClassification("file-rename", 0.96, ("rename",), True)
    if re.search(r"(?is)(?:^|[^A-Za-z0-9_])mkdir\s*\(", value):
        return WebShellClassification("directory-create", 0.95, ("mkdir",), True)
    if DATABASE_PATTERN.search(value):
        return WebShellClassification("database-action", 0.92, ("database-api",), False)
    if COMMAND_PATTERN.search(value):
        return WebShellClassification("command-execution", 0.94, ("command-api",), True)
    return WebShellClassification("unknown-operation", 0.55, (), False)


def normalize_webshell_target(value: str) -> str:
    target = value.replace("\x00", "").strip()
    if not target:
        return "(unresolved)"
    if re.match(r"^[A-Za-z]:[\\/]", target):
        normalized = ntpath.normpath(target.replace("/", "\\"))
        return normalized[0].upper() + normalized[1:]
    if target.startswith("/"):
        return posixpath.normpath(target)
    return " ".join(target.split())


def _bounded_preview(data: bytes, max_bytes: int) -> tuple[str, bool]:
    truncated = len(data) > max_bytes
    return data[:max_bytes].decode("utf-8", errors="replace"), truncated


def _safe_blob_path(root: Path, relative_path: str) -> Path:
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("blob path escapes the analysis project") from error
    return path


def _read_evidence(root: Path, value: _EvidenceValue, max_bytes: int) -> bytes:
    if value.byte_length > max_bytes:
        raise OverflowError(f"evidence exceeds {max_bytes} bytes")
    if value.text_value is not None:
        data = value.text_value.encode("utf-8")
        if len(data) > max_bytes:
            raise OverflowError(f"evidence text exceeds {max_bytes} bytes")
        return data
    if value.relative_path is None:
        raise FileNotFoundError("evidence has neither text nor Blob storage")
    path = _safe_blob_path(root, value.relative_path)
    with path.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise OverflowError(f"evidence Blob exceeds {max_bytes} bytes")
    return data


def _transaction_rows(connection: sqlite3.Connection, capture_id: int) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT tr.id transaction_db_id,tr.transaction_id,req.id request_message_db_id,"
        "req.message_id request_message_public_id,req.representative_frame request_frame,"
        "hm.method,hm.uri,resp.representative_frame response_frame,"
        "rb.evidence_id response_evidence_db_id "
        "FROM transaction_record tr JOIN protocol_message req ON req.id=tr.request_message_id "
        "JOIN http_message hm ON hm.protocol_message_id=req.id "
        "LEFT JOIN protocol_message resp ON resp.id=tr.response_message_id "
        "LEFT JOIN http_body rb ON rb.protocol_message_id=resp.id "
        "WHERE tr.capture_id=? AND upper(coalesce(hm.method,''))='POST' "
        "ORDER BY req.representative_frame,tr.id",
        (capture_id,),
    ).fetchall()


def _evidence_value(row: sqlite3.Row, prefix: str) -> Optional[_EvidenceValue]:
    if row[f"{prefix}_db_id"] is None:
        return None
    return _EvidenceValue(
        db_id=int(row[f"{prefix}_db_id"]),
        public_id=str(row[f"{prefix}_public_id"]),
        byte_length=int(row[f"{prefix}_byte_length"] or 0),
        text_value=(
            str(row[f"{prefix}_text_value"])
            if row[f"{prefix}_text_value"] is not None
            else None
        ),
        relative_path=(
            str(row[f"{prefix}_relative_path"])
            if row[f"{prefix}_relative_path"] is not None
            else None
        ),
        transform_name=(
            str(row["transform_name"])
            if prefix == "output" and row["transform_name"] is not None
            else None
        ),
        transform_status=(
            str(row["transform_status"])
            if prefix == "output" and row["transform_status"] is not None
            else None
        ),
        transform_truncated=bool(row["transform_truncated"] or 0) if prefix == "output" else False,
    )


def _field_rows(connection: sqlite3.Connection, message_id: int) -> tuple[_Field, ...]:
    rows = connection.execute(
        "SELECT ff.ordinal,ff.name,de.id decoded_db_id,de.evidence_id decoded_public_id,"
        "de.byte_length decoded_byte_length,de.text_value decoded_text_value,"
        "db.relative_path decoded_relative_path,t.name transform_name,"
        "t.status transform_status,t.truncated transform_truncated,"
        "oe.id output_db_id,oe.evidence_id output_public_id,"
        "oe.byte_length output_byte_length,oe.text_value output_text_value,"
        "ob.relative_path output_relative_path "
        "FROM form_field ff JOIN evidence de ON de.id=ff.decoded_value_evidence_id "
        "LEFT JOIN blob db ON db.id=de.blob_id "
        "LEFT JOIN transform t ON t.parent_evidence_id=de.id AND t.output_evidence_id IS NOT NULL "
        "LEFT JOIN evidence oe ON oe.id=t.output_evidence_id "
        "LEFT JOIN blob ob ON ob.id=oe.blob_id WHERE ff.protocol_message_id=? "
        "ORDER BY ff.ordinal,t.depth,t.id",
        (message_id,),
    ).fetchall()
    grouped: dict[tuple[int, str], tuple[_EvidenceValue, list[_EvidenceValue]]] = {}
    for row in rows:
        key = (int(row["ordinal"]), str(row["name"]))
        decoded = _evidence_value(row, "decoded")
        if decoded is None:
            continue
        if key not in grouped:
            grouped[key] = (decoded, [])
        output = _evidence_value(row, "output")
        if output is not None:
            grouped[key][1].append(output)
    return tuple(
        _Field(ordinal, name, decoded, tuple(outputs))
        for (ordinal, name), (decoded, outputs) in grouped.items()
    )


def _complete_output(field: Optional[_Field], transform_name: str) -> Optional[_EvidenceValue]:
    if field is None:
        return None
    for output in field.outputs:
        if (
            output.transform_name == transform_name
            and output.transform_status == "complete"
            and not output.transform_truncated
        ):
            return output
    return None


def _target_parameter(action: str, action_parameter: str) -> Optional[str]:
    for match in BASE64_POST_PATTERN.finditer(action):
        name = match.group(1)
        if name.lower() != action_parameter.lower():
            return name
    return None


def _payload_parameter(action: str, excluded: set[str]) -> Optional[str]:
    for match in POST_FIELD_PATTERN.finditer(action):
        name = match.group(1)
        if name.lower() not in excluded:
            return name
    return None


def _insert_skip(
    connection: sqlite3.Connection,
    detector_run_id: int,
    scope_kind: str,
    scope_id: str,
    reason: str,
    detail: dict[str, object],
    *,
    count: int = 1,
) -> None:
    connection.execute(
        "INSERT INTO detector_skip"
        "(detector_run_id,scope_kind,scope_id,reason,count,detail_json) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(detector_run_id,scope_kind,scope_id,reason) DO UPDATE SET "
        "count=excluded.count,detail_json=excluded.detail_json",
        (
            detector_run_id,
            scope_kind,
            scope_id,
            reason,
            count,
            json.dumps(detail, ensure_ascii=False, sort_keys=True),
        ),
    )


def _worse_status(current: str, new: str) -> str:
    priority = {"completed": 0, "budget-limited": 1, "partial": 2, "failed": 3}
    return new if priority[new] > priority[current] else current


def _mark_failed(
    database: Database,
    detector_run_id: int,
    tool_run_id: int,
    run_id: str,
    error: Exception,
) -> None:
    ended_at = _now()
    error_text = f"{type(error).__name__}: {error}"[:4096]
    with database.connect() as connection:
        _insert_skip(
            connection,
            detector_run_id,
            "detector-run",
            run_id,
            "failed",
            {"error": error_text},
        )
        connection.execute(
            "UPDATE detector_run SET status='failed',inputs_skipped=inputs_skipped+1,"
            "ended_at=? WHERE id=?",
            (ended_at, detector_run_id),
        )
        connection.execute(
            "UPDATE tool_run SET status='failed',exit_code=1,stderr_text=?,ended_at=? WHERE id=?",
            (error_text, ended_at, tool_run_id),
        )


def _persist_event(
    connection: sqlite3.Connection,
    project: ProjectInfo,
    capture_id: int,
    detector_run_id: int,
    transaction: sqlite3.Row,
    classification: WebShellClassification,
    action: Optional[_EvidenceValue],
    action_data: bytes,
    wrapper: _EvidenceValue,
    target: str,
    target_evidence: Optional[_EvidenceValue],
    payload_evidence: Optional[_EvidenceValue],
    event_status: str,
    max_preview_bytes: int,
) -> tuple[int, int, str, float]:
    action_sha256 = hashlib.sha256(action_data).hexdigest()
    semantic_key = stable_id(
        "webshell-operation-semantic",
        {
            "event_kind": classification.event_kind,
            "target": target.casefold(),
            "action_sha256": action_sha256,
        },
    )
    event_public_id = stable_id(
        "behavior-event",
        {
            "detector": WEBSHELL_DETECTOR,
            "version": WEBSHELL_DETECTOR_VERSION,
            "transaction_id": str(transaction["transaction_id"]),
        },
    )
    duplicate = connection.execute(
        "SELECT id FROM behavior_event WHERE capture_id=? AND detector=? "
        "AND semantic_key=? AND request_frame<? ORDER BY request_frame,id LIMIT 1",
        (capture_id, WEBSHELL_DETECTOR, semantic_key, int(transaction["request_frame"])),
    ).fetchone()
    preview, preview_truncated = _bounded_preview(action_data, max_preview_bytes)
    detail = {
        "action_evidence_id": action.public_id if action is not None else None,
        "action_sha256": action_sha256,
        "markers": classification.markers,
        "payload": (
            {
                "byte_length": payload_evidence.byte_length,
                "evidence_id": payload_evidence.public_id,
            }
            if payload_evidence is not None
            else None
        ),
        "preview": preview,
        "preview_truncated": preview_truncated,
        "target_evidence_id": target_evidence.public_id if target_evidence is not None else None,
        "wrapper_evidence_id": wrapper.public_id,
    }
    confidence = classification.confidence if event_status == "complete" else min(
        classification.confidence, 0.70
    )
    connection.execute(
        "INSERT INTO behavior_event "
        "(event_id,capture_id,transaction_id,protocol_message_id,detector,detector_version,"
        "event_kind,status,request_frame,response_frame,target,semantic_key,confidence,"
        "detail_json,duplicate_of,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(event_id) DO UPDATE SET event_kind=excluded.event_kind,"
        "status=excluded.status,response_frame=excluded.response_frame,target=excluded.target,"
        "semantic_key=excluded.semantic_key,confidence=excluded.confidence,"
        "detail_json=excluded.detail_json,duplicate_of=excluded.duplicate_of",
        (
            event_public_id,
            capture_id,
            int(transaction["transaction_db_id"]),
            int(transaction["request_message_db_id"]),
            WEBSHELL_DETECTOR,
            WEBSHELL_DETECTOR_VERSION,
            classification.event_kind,
            event_status,
            int(transaction["request_frame"]),
            (
                int(transaction["response_frame"])
                if transaction["response_frame"] is not None
                else None
            ),
            target,
            semantic_key,
            confidence,
            json.dumps(detail, ensure_ascii=False, sort_keys=True),
            int(duplicate[0]) if duplicate is not None else None,
            _now(),
        ),
    )
    event_db_id = int(
        connection.execute(
            "SELECT id FROM behavior_event WHERE event_id=?", (event_public_id,)
        ).fetchone()[0]
    )
    connection.execute("DELETE FROM behavior_event_evidence WHERE event_id=?", (event_db_id,))
    links = [
        (wrapper.db_id, "wrapper"),
        (action.db_id if action is not None else None, "operation"),
        (target_evidence.db_id if target_evidence is not None else None, "target"),
        (payload_evidence.db_id if payload_evidence is not None else None, "payload"),
        (
            int(transaction["response_evidence_db_id"])
            if transaction["response_evidence_db_id"] is not None
            else None,
            "response",
        ),
    ]
    for evidence_db_id, role in links:
        if evidence_db_id is not None:
            connection.execute(
                "INSERT OR IGNORE INTO behavior_event_evidence(event_id,evidence_id,role) "
                "VALUES(?,?,?)",
                (event_db_id, evidence_db_id, role),
            )
    connection.execute(
        "INSERT OR IGNORE INTO behavior_event_run(event_id,detector_run_id) VALUES(?,?)",
        (event_db_id, detector_run_id),
    )
    finding_evidence_id = action.db_id if action is not None else wrapper.db_id
    return event_db_id, finding_evidence_id, event_public_id, confidence


def _run_webshell_detection(
    database: Database,
    project: ProjectInfo,
    run_id: str,
    capture_id: int,
    detector_run_id: int,
    tool_run_id: int,
    *,
    max_transactions: int,
    max_fields: int,
    max_value_bytes: int,
    max_events: int,
    max_findings: int,
    max_preview_bytes: int,
) -> WebShellDetectionSummary:
    status = "completed"
    fields_processed = event_count = finding_count = skip_count = 0
    finding_targets: dict[str, set[int]] = {}
    with database.connect() as connection:
        transactions = _transaction_rows(connection, capture_id)
        for transaction_index, transaction in enumerate(transactions):
            transaction_public_id = str(transaction["transaction_id"])
            if transaction_index >= max_transactions:
                _insert_skip(
                    connection,
                    detector_run_id,
                    "transaction",
                    transaction_public_id,
                    "transaction-limit",
                    {"max_transactions": max_transactions},
                )
                skip_count += 1
                status = _worse_status(status, "budget-limited")
                continue
            fields = _field_rows(connection, int(transaction["request_message_db_id"]))
            allowed_fields: list[_Field] = []
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
                    skip_count += 1
                    status = _worse_status(status, "budget-limited")
                    continue
                fields_processed += 1
                allowed_fields.append(field)
            fields_by_name = {field.name.lower(): field for field in allowed_fields}
            wrapper_field: Optional[_Field] = None
            wrapper_value: Optional[_EvidenceValue] = None
            action_parameter: Optional[str] = None
            for field in allowed_fields:
                if field.decoded.byte_length > max_value_bytes:
                    continue
                try:
                    decoded = _read_evidence(project.root, field.decoded, max_value_bytes).decode(
                        "utf-8", errors="replace"
                    )
                except (OSError, ValueError, OverflowError) as error:
                    _insert_skip(
                        connection,
                        detector_run_id,
                        "field",
                        f"{transaction_public_id}:{field.ordinal}",
                        "failed",
                        {"error": str(error)},
                    )
                    skip_count += 1
                    status = _worse_status(status, "partial")
                    continue
                referenced = wrapper_action_parameter(decoded)
                if referenced is not None:
                    wrapper_field = field
                    wrapper_value = field.decoded
                    action_parameter = referenced
                    break
            if wrapper_field is None or wrapper_value is None or action_parameter is None:
                continue
            if event_count >= max_events:
                _insert_skip(
                    connection,
                    detector_run_id,
                    "transaction",
                    transaction_public_id,
                    "event-limit",
                    {"max_events": max_events},
                )
                skip_count += 1
                status = _worse_status(status, "budget-limited")
                continue
            action_field = fields_by_name.get(action_parameter.lower())
            action_evidence = _complete_output(action_field, "base64")
            action_data = b""
            action_text = ""
            event_status = "complete"
            if action_evidence is None:
                event_status = "partial"
                classification = WebShellClassification("unknown-operation", 0.55, (), False)
                _insert_skip(
                    connection,
                    detector_run_id,
                    "transaction",
                    transaction_public_id,
                    "missing-action-transform",
                    {"action_parameter": action_parameter},
                )
                skip_count += 1
                status = _worse_status(status, "partial")
            else:
                try:
                    action_data = _read_evidence(project.root, action_evidence, max_value_bytes)
                    action_text = action_data.decode("utf-8", errors="replace")
                    classification = classify_webshell_action(action_text)
                except OverflowError as error:
                    event_status = "partial"
                    classification = WebShellClassification("unknown-operation", 0.55, (), False)
                    _insert_skip(
                        connection,
                        detector_run_id,
                        "field",
                        action_evidence.public_id,
                        "value-byte-limit",
                        {"error": str(error)},
                    )
                    skip_count += 1
                    status = _worse_status(status, "budget-limited")
                except (OSError, ValueError) as error:
                    event_status = "partial"
                    classification = WebShellClassification("unknown-operation", 0.55, (), False)
                    _insert_skip(
                        connection,
                        detector_run_id,
                        "field",
                        action_evidence.public_id,
                        "failed",
                        {"error": str(error)},
                    )
                    skip_count += 1
                    status = _worse_status(status, "partial")
            target = (
                "server-environment"
                if classification.event_kind == "system-information"
                else str(transaction["uri"] or "(unresolved)")
            )
            target_evidence: Optional[_EvidenceValue] = None
            target_parameter = _target_parameter(action_text, action_parameter)
            if target_parameter is not None:
                target_evidence = _complete_output(
                    fields_by_name.get(target_parameter.lower()), "base64"
                )
                if target_evidence is not None:
                    try:
                        target_data = _read_evidence(
                            project.root, target_evidence, max_value_bytes
                        )
                        target = normalize_webshell_target(
                            target_data.decode("utf-8", errors="replace")
                        )
                    except OverflowError as error:
                        event_status = "partial"
                        _insert_skip(
                            connection,
                            detector_run_id,
                            "field",
                            target_evidence.public_id,
                            "value-byte-limit",
                            {"error": str(error)},
                        )
                        skip_count += 1
                        status = _worse_status(status, "budget-limited")
                    except (OSError, ValueError) as error:
                        event_status = "partial"
                        _insert_skip(
                            connection,
                            detector_run_id,
                            "field",
                            target_evidence.public_id,
                            "failed",
                            {"error": str(error)},
                        )
                        skip_count += 1
                        status = _worse_status(status, "partial")
            elif classification.target_required:
                event_status = "partial"
                status = _worse_status(status, "partial")
            payload_evidence: Optional[_EvidenceValue] = None
            if classification.event_kind == "file-write":
                excluded = {action_parameter.lower()}
                if target_parameter is not None:
                    excluded.add(target_parameter.lower())
                payload_parameter = _payload_parameter(action_text, excluded)
                if payload_parameter is not None:
                    payload_field = fields_by_name.get(payload_parameter.lower())
                    if payload_field is not None:
                        payload_evidence = next(
                            (
                                output
                                for output in payload_field.outputs
                                if output.transform_status == "complete"
                                and not output.transform_truncated
                            ),
                            payload_field.decoded,
                        )
            event_db_id, finding_evidence_id, _, _ = _persist_event(
                connection,
                project,
                capture_id,
                detector_run_id,
                transaction,
                classification,
                action_evidence,
                action_data,
                wrapper_value,
                target,
                target_evidence,
                payload_evidence,
                event_status,
                max_preview_bytes,
            )
            del event_db_id
            endpoint = f"{str(transaction['method']).upper()} {transaction['uri']}"
            finding_targets.setdefault(endpoint, set()).add(finding_evidence_id)
            event_count += 1
        for endpoint, evidence_ids in sorted(finding_targets.items()):
            if finding_count >= max_findings:
                _insert_skip(
                    connection,
                    detector_run_id,
                    "finding",
                    endpoint,
                    "finding-limit",
                    {"max_findings": max_findings},
                )
                skip_count += 1
                status = _worse_status(status, "budget-limited")
                continue
            finding_public_id = stable_id(
                "finding",
                {
                    "capture_sha256": project.capture_sha256,
                    "detector": WEBSHELL_DETECTOR,
                    "endpoint": endpoint,
                },
            )
            connection.execute(
                "INSERT INTO finding(finding_id,detector,detector_version,title,description,"
                "severity,confidence,recommended_action,created_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(finding_id) DO UPDATE SET description=excluded.description,"
                "severity=excluded.severity,confidence=excluded.confidence",
                (
                    finding_public_id,
                    WEBSHELL_DETECTOR,
                    WEBSHELL_DETECTOR_VERSION,
                    "Static WebShell activity",
                    f"Decoded static WebShell operations were observed at {endpoint}.",
                    "critical",
                    0.97,
                    "Review the ordered operation timeline and linked request evidence.",
                    _now(),
                ),
            )
            finding_db_id = int(
                connection.execute(
                    "SELECT id FROM finding WHERE finding_id=?", (finding_public_id,)
                ).fetchone()[0]
            )
            connection.execute("DELETE FROM finding_evidence WHERE finding_id=?", (finding_db_id,))
            for evidence_db_id in sorted(evidence_ids):
                connection.execute(
                    "INSERT INTO finding_evidence(finding_id,evidence_id,role) "
                    "VALUES(?,?,'operation')",
                    (finding_db_id, evidence_db_id),
                )
            connection.execute(
                "INSERT OR IGNORE INTO finding_run(finding_id,tool_run_id) VALUES(?,?)",
                (finding_db_id, tool_run_id),
            )
            finding_count += 1
        connection.execute(
            "UPDATE detector_run SET status=?,inputs_processed=?,inputs_skipped=?,"
            "findings=?,events=?,ended_at=? WHERE id=?",
            (
                status,
                min(len(transactions), max_transactions),
                skip_count,
                finding_count,
                event_count,
                _now(),
                detector_run_id,
            ),
        )
        connection.execute(
            "UPDATE tool_run SET status='completed',exit_code=0,ended_at=? WHERE id=?",
            (_now(), tool_run_id),
        )
    return WebShellDetectionSummary(
        "auto-shark.webshell-detection/v1",
        str(project.root),
        run_id,
        status,
        min(len(transactions), max_transactions),
        fields_processed,
        skip_count,
        event_count,
        finding_count,
    )


def detect_webshell_activity(
    project_path: Path,
    *,
    max_transactions: int = 10_000,
    max_fields: int = 100_000,
    max_value_bytes: int = 64 * 1024,
    max_events: int = 10_000,
    max_findings: int = 1000,
    max_preview_bytes: int = 256,
) -> WebShellDetectionSummary:
    if min(
        max_transactions,
        max_fields,
        max_value_bytes,
        max_events,
        max_findings,
        max_preview_bytes,
    ) <= 0:
        raise ValueError("WebShell detector limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    run_id = str(uuid4())
    policy = {
        "max_events": max_events,
        "max_fields": max_fields,
        "max_findings": max_findings,
        "max_preview_bytes": max_preview_bytes,
        "max_transactions": max_transactions,
        "max_value_bytes": max_value_bytes,
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
                WEBSHELL_DETECTOR,
                WEBSHELL_DETECTOR_VERSION,
                json.dumps(policy, sort_keys=True),
                _now(),
            ),
        )
        detector_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
        tool_run_public = uuid4().hex
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,tool_version,argv_json,started_at,status) "
            "VALUES(?,?,?,?,?,'running')",
            (
                tool_run_public,
                "auto-shark-webshell-detector",
                WEBSHELL_DETECTOR_VERSION,
                json.dumps(policy, sort_keys=True),
                _now(),
            ),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
    try:
        return _run_webshell_detection(
            database,
            project,
            run_id,
            capture_id,
            detector_run_id,
            tool_run_id,
            max_transactions=max_transactions,
            max_fields=max_fields,
            max_value_bytes=max_value_bytes,
            max_events=max_events,
            max_findings=max_findings,
            max_preview_bytes=max_preview_bytes,
        )
    except Exception as error:
        _mark_failed(database, detector_run_id, tool_run_id, run_id, error)
        raise
