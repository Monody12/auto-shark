"""Bounded static reconstruction of HTTP SQL-injection behavior."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote_to_bytes, urlsplit
from uuid import uuid4

from .core.ids import EvidenceLocator, evidence_id, stable_id
from .project import ProjectInfo, inspect_project
from .storage import Database

SQL_DETECTOR = "http-sql-injection-behavior"
SQL_DETECTOR_VERSION = "1"
BOOLEAN_PATTERN = re.compile(
    r"(?is)(?:['\")\d]|\b)\s*(?:or|and)\s+(?:['\"]?\w+['\"]?\s*=\s*['\"]?\w+|\d+\s*[<>]=?\s*\d+)"
)
UNION_PATTERN = re.compile(r"(?is)\bunion\s+(?:all\s+)?select\b")
COMMENT_PATTERN = re.compile(r"(?s)(?:--(?:\s|$)|#|/\*)")
TIME_PATTERN = re.compile(r"(?is)\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b")
METADATA_PATTERN = re.compile(
    r"(?is)\b(?:information_schema|sqlite_master|pg_catalog|sysobjects|syscolumns)\b"
)
STACKED_PATTERN = re.compile(
    r"(?is);\s*(?:select|insert|update|delete|drop|alter|create|exec(?:ute)?)\b"
)
SELECT_PATTERN = re.compile(r"(?is)\bselect\b")


@dataclass(frozen=True)
class QueryParameter:
    ordinal: int
    name: str
    value: str
    value_offset: int
    raw_length: int


@dataclass(frozen=True)
class SqlClassification:
    signals: tuple[str, ...]
    confidence: float


@dataclass(frozen=True)
class SqlDetectionSummary:
    schema_version: str
    project: str
    run_id: str
    status: str
    transactions_processed: int
    parameters_processed: int
    inputs_skipped: int
    events: int
    findings: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class _Parameter:
    transaction_db_id: int
    transaction_public_id: str
    request_message_db_id: int
    request_message_public_id: str
    request_frame: int
    response_message_db_id: Optional[int]
    response_frame: Optional[int]
    response_code: Optional[int]
    response_length: Optional[int]
    response_body_status: Optional[str]
    response_evidence_db_id: Optional[int]
    method: str
    uri: str
    path: str
    ordinal: int
    name: str
    value: str
    source: str
    evidence_db_id: Optional[int]
    value_offset: Optional[int]
    raw_length: int

    @property
    def target(self) -> str:
        return f"{self.method} {self.path}#{self.name.lower()}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_query_parameters(uri: str, *, max_parameters: int = 1024) -> tuple[QueryParameter, ...]:
    if max_parameters <= 0:
        raise ValueError("max_parameters must be positive")
    marker = uri.find("?")
    if marker < 0:
        return ()
    query = uri[marker + 1 :].split("#", 1)[0]
    result: list[QueryParameter] = []
    cursor = 0
    for ordinal, part in enumerate(query.split("&")):
        if ordinal >= max_parameters:
            break
        separator = part.find("=")
        if separator < 0:
            raw_name, raw_value = part, ""
            value_character_offset = marker + 1 + cursor + len(part)
        else:
            raw_name, raw_value = part[:separator], part[separator + 1 :]
            value_character_offset = marker + 1 + cursor + separator + 1
        name = unquote_to_bytes(raw_name.replace("+", " ")).decode("utf-8", errors="replace")
        value = unquote_to_bytes(raw_value.replace("+", " ")).decode("utf-8", errors="replace")
        value_offset = len(uri[:value_character_offset].encode("utf-8"))
        raw_length = len(raw_value.encode("utf-8"))
        result.append(QueryParameter(ordinal, name, value, value_offset, raw_length))
        cursor += len(part) + 1
    return tuple(result)


def classify_sql_value(value: str) -> SqlClassification:
    signals: list[str] = []
    if BOOLEAN_PATTERN.search(value):
        signals.append("boolean-expression")
    if UNION_PATTERN.search(value):
        signals.append("union-select")
    if TIME_PATTERN.search(value):
        signals.append("time-delay")
    if STACKED_PATTERN.search(value):
        signals.append("stacked-statement")
    if METADATA_PATTERN.search(value) and SELECT_PATTERN.search(value):
        signals.append("metadata-query")
    if COMMENT_PATTERN.search(value) and ("'" in value or '"' in value or signals):
        signals.append("comment-truncation")
    weights = {
        "boolean-expression": 0.68,
        "union-select": 0.82,
        "time-delay": 0.88,
        "stacked-statement": 0.78,
        "metadata-query": 0.72,
        "comment-truncation": 0.35,
    }
    confidence = max((weights[item] for item in signals), default=0.0)
    if len(signals) > 1:
        confidence = min(0.97, confidence + 0.08 * (len(signals) - 1))
    return SqlClassification(tuple(signals), confidence)


def _safe_blob_path(root: Path, relative_path: str) -> Path:
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("blob path escapes the analysis project") from error
    return path


def _read_form_value(root: Path, row: sqlite3.Row, max_parameter_bytes: int) -> Optional[str]:
    if int(row["byte_length"]) > max_parameter_bytes:
        return None
    if row["text_value"] is not None:
        return str(row["text_value"])
    path = _safe_blob_path(root, str(row["relative_path"]))
    with path.open("rb") as stream:
        data = stream.read(max_parameter_bytes + 1)
    if len(data) > max_parameter_bytes:
        return None
    return data.decode("utf-8", errors="replace")


def _transaction_rows(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT tr.id transaction_db_id,tr.transaction_id,req.id request_message_db_id,"
        "req.message_id request_message_public_id,req.representative_frame request_frame,"
        "rhm.method,rhm.uri,resp.id response_message_db_id,"
        "resp.representative_frame response_frame,shm.response_code,shm.content_length,"
        "shb.extracted_length,shb.status response_body_status,se.id response_evidence_db_id "
        "FROM transaction_record tr "
        "JOIN protocol_message req ON req.id=tr.request_message_id "
        "JOIN http_message rhm ON rhm.protocol_message_id=req.id "
        "LEFT JOIN protocol_message resp ON resp.id=tr.response_message_id "
        "LEFT JOIN http_message shm ON shm.protocol_message_id=resp.id "
        "LEFT JOIN http_body shb ON shb.protocol_message_id=resp.id "
        "LEFT JOIN evidence se ON se.id=shb.evidence_id "
        "ORDER BY req.representative_frame,tr.id"
    ).fetchall()


def _collect_parameters(
    database: Database,
    project_root: Path,
    *,
    max_transactions: int,
    max_parameters: int,
    max_parameter_bytes: int,
) -> tuple[list[_Parameter], list[tuple[str, str, dict[str, object]]], int]:
    parameters: list[_Parameter] = []
    skips: list[tuple[str, str, dict[str, object]]] = []
    transaction_count = 0
    parameter_count = 0
    with database.connect() as connection:
        transactions = _transaction_rows(connection)
        for transaction_index, row in enumerate(transactions):
            if transaction_index >= max_transactions:
                skips.append(
                    ("transaction", str(row["transaction_id"]), {"reason": "transaction-limit"})
                )
                continue
            transaction_count += 1
            method = str(row["method"] or "").upper()
            uri = str(row["uri"] or "")
            path = urlsplit(uri).path or uri.split("?", 1)[0] or "/"
            response_length = (
                int(row["extracted_length"])
                if row["response_body_status"] == "complete"
                else (int(row["content_length"]) if row["content_length"] is not None else None)
            )
            common = {
                "transaction_db_id": int(row["transaction_db_id"]),
                "transaction_public_id": str(row["transaction_id"]),
                "request_message_db_id": int(row["request_message_db_id"]),
                "request_message_public_id": str(row["request_message_public_id"]),
                "request_frame": int(row["request_frame"]),
                "response_message_db_id": (
                    int(row["response_message_db_id"])
                    if row["response_message_db_id"] is not None
                    else None
                ),
                "response_frame": (
                    int(row["response_frame"]) if row["response_frame"] is not None else None
                ),
                "response_code": (
                    int(row["response_code"]) if row["response_code"] is not None else None
                ),
                "response_length": response_length,
                "response_body_status": (
                    str(row["response_body_status"])
                    if row["response_body_status"] is not None
                    else None
                ),
                "response_evidence_db_id": (
                    int(row["response_evidence_db_id"])
                    if row["response_evidence_db_id"] is not None
                    else None
                ),
                "method": method,
                "uri": uri,
                "path": path,
            }
            remaining_parameters = max(0, max_parameters - parameter_count)
            query_parameters = parse_query_parameters(
                uri, max_parameters=max(1, remaining_parameters + 1)
            )
            for query in query_parameters[:remaining_parameters]:
                parameter_count += 1
                if len(query.value.encode("utf-8")) > max_parameter_bytes:
                    skips.append(
                        (
                            "parameter",
                            f"{row['transaction_id']}:query:{query.ordinal}",
                            {"reason": "parameter-byte-limit"},
                        )
                    )
                    continue
                parameters.append(
                    _Parameter(
                        **common,
                        ordinal=query.ordinal,
                        name=query.name,
                        value=query.value,
                        source="query",
                        evidence_db_id=None,
                        value_offset=query.value_offset,
                        raw_length=query.raw_length,
                    )
                )
            omitted_queries = len(query_parameters) - remaining_parameters
            if omitted_queries > 0:
                skips.append(
                    (
                        "transaction",
                        str(row["transaction_id"]),
                        {
                            "reason": "parameter-limit",
                            "count": omitted_queries,
                        },
                    )
                )
            form_rows = connection.execute(
                "SELECT ff.ordinal,ff.name,e.id evidence_db_id,e.text_value,e.byte_length,"
                "b.relative_path FROM form_field ff JOIN evidence e "
                "ON e.id=ff.decoded_value_evidence_id JOIN blob b ON b.id=e.blob_id "
                "WHERE ff.protocol_message_id=? ORDER BY ff.ordinal",
                (row["request_message_db_id"],),
            ).fetchall()
            remaining_parameters = max(0, max_parameters - parameter_count)
            for form in form_rows[:remaining_parameters]:
                parameter_count += 1
                try:
                    value = _read_form_value(project_root, form, max_parameter_bytes)
                except (OSError, ValueError) as error:
                    skips.append(
                        (
                            "parameter",
                            f"{row['transaction_id']}:form:{form['ordinal']}",
                            {"reason": "failed", "error": str(error)},
                        )
                    )
                    continue
                if value is None:
                    skips.append(
                        (
                            "parameter",
                            f"{row['transaction_id']}:form:{form['ordinal']}",
                            {"reason": "parameter-byte-limit"},
                        )
                    )
                    continue
                parameters.append(
                    _Parameter(
                        **common,
                        ordinal=int(form["ordinal"]),
                        name=str(form["name"]),
                        value=value,
                        source="form",
                        evidence_db_id=int(form["evidence_db_id"]),
                        value_offset=None,
                        raw_length=int(form["byte_length"]),
                    )
                )
            if len(form_rows) > remaining_parameters:
                skips.append(
                    (
                        "transaction",
                        str(row["transaction_id"]),
                        {
                            "reason": "parameter-limit",
                            "count": len(form_rows) - remaining_parameters,
                        },
                    )
                )
    return parameters, skips, transaction_count


def _query_evidence(
    connection: sqlite3.Connection,
    capture_id: int,
    capture_sha256: str,
    parameter: _Parameter,
) -> int:
    if parameter.evidence_db_id is not None:
        return parameter.evidence_db_id
    locator = EvidenceLocator(
        capture_sha256=capture_sha256,
        source_kind="http-query-field",
        frame_start=parameter.request_frame,
        frame_end=parameter.request_frame,
        protocol_message=parameter.request_message_public_id,
        byte_offset=parameter.value_offset,
        byte_length=parameter.raw_length,
        field_name=parameter.name,
    )
    public_id = evidence_id(locator)
    connection.execute(
        "INSERT OR IGNORE INTO evidence "
        "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
        "transaction_id,byte_offset,byte_length,field_name,text_value,locator_json) "
        "VALUES(?,?, 'http-query-field',?,?,?,?,?,?,?,?,?)",
        (
            public_id,
            capture_id,
            parameter.request_frame,
            parameter.request_frame,
            parameter.request_message_db_id,
            parameter.transaction_db_id,
            parameter.value_offset,
            parameter.raw_length,
            parameter.name,
            parameter.value,
            json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
        ),
    )
    return int(
        connection.execute("SELECT id FROM evidence WHERE evidence_id=?", (public_id,)).fetchone()[
            0
        ]
    )


def _response_metadata_evidence(
    connection: sqlite3.Connection,
    capture_id: int,
    capture_sha256: str,
    parameter: _Parameter,
) -> Optional[int]:
    if parameter.response_evidence_db_id is not None:
        return parameter.response_evidence_db_id
    if parameter.response_message_db_id is None or parameter.response_frame is None:
        return None
    locator = EvidenceLocator(
        capture_sha256=capture_sha256,
        source_kind="http-response-metadata",
        frame_start=parameter.response_frame,
        frame_end=parameter.response_frame,
        protocol_message=parameter.transaction_public_id,
        field_name="status-and-length",
    )
    public_id = evidence_id(locator)
    text = json.dumps(
        {"response_code": parameter.response_code, "response_length": parameter.response_length},
        sort_keys=True,
    )
    connection.execute(
        "INSERT OR IGNORE INTO evidence "
        "(evidence_id,capture_id,source_kind,frame_start,frame_end,protocol_message_id,"
        "transaction_id,field_name,text_value,locator_json) "
        "VALUES(?,?,'http-response-metadata',?,?,?,?,?,?,?)",
        (
            public_id,
            capture_id,
            parameter.response_frame,
            parameter.response_frame,
            parameter.response_message_db_id,
            parameter.transaction_db_id,
            "status-and-length",
            text,
            json.dumps(locator.payload(), sort_keys=True),
        ),
    )
    return int(
        connection.execute("SELECT id FROM evidence WHERE evidence_id=?", (public_id,)).fetchone()[
            0
        ]
    )


def _response_difference(
    current: _Parameter, baseline: Optional[_Parameter]
) -> tuple[bool, dict[str, object]]:
    if baseline is None:
        return False, {"baseline": "missing"}
    code_changed = current.response_code != baseline.response_code
    length_changed = False
    if current.response_length is not None and baseline.response_length is not None:
        delta = abs(current.response_length - baseline.response_length)
        length_changed = delta >= 32 and delta >= max(1, baseline.response_length // 10)
    return code_changed or length_changed, {
        "baseline_request_frame": baseline.request_frame,
        "baseline_response_frame": baseline.response_frame,
        "code_changed": code_changed,
        "length_changed": length_changed,
    }


def _normalize_probe(value: str) -> str:
    return " ".join(value.lower().split())[:512]


def _bounded_preview(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def _response_is_usable(parameter: _Parameter) -> bool:
    return parameter.response_frame is not None and parameter.response_body_status not in {
        "missing",
        "partial",
        "limit-truncated",
        "length-mismatch",
    }


def _insert_detector_skip(
    connection: sqlite3.Connection,
    detector_run_id: int,
    scope_kind: str,
    scope_id: str,
    detail: dict[str, object],
) -> None:
    reason = str(detail["reason"])
    count = int(detail.get("count", 1))
    connection.execute(
        "INSERT INTO detector_skip "
        "(detector_run_id,scope_kind,scope_id,reason,count,detail_json) "
        "VALUES(?,?,?,?,?,?) ON CONFLICT(detector_run_id,scope_kind,scope_id,reason) "
        "DO UPDATE SET count=excluded.count,detail_json=excluded.detail_json",
        (detector_run_id, scope_kind, scope_id, reason, count, json.dumps(detail, sort_keys=True)),
    )


def _mark_detector_failed(
    database: Database,
    detector_run_id: int,
    tool_run_id: int,
    run_id: str,
    error: Exception,
) -> None:
    ended_at = _now()
    error_text = f"{type(error).__name__}: {error}"[:4096]
    with database.connect() as connection:
        _insert_detector_skip(
            connection,
            detector_run_id,
            "detector-run",
            run_id,
            {"reason": "failed", "error": error_text},
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


def _run_sql_detection(
    database: Database,
    project: ProjectInfo,
    run_id: str,
    capture_id: int,
    detector_run_id: int,
    tool_run_id: int,
    *,
    max_transactions: int,
    max_parameters: int,
    max_parameter_bytes: int,
    max_events: int,
    max_findings: int,
    max_preview_bytes: int,
) -> SqlDetectionSummary:
    parameters, skips, transactions_processed = _collect_parameters(
        database,
        project.root,
        max_transactions=max_transactions,
        max_parameters=max_parameters,
        max_parameter_bytes=max_parameter_bytes,
    )
    classified = [(item, classify_sql_value(item.value)) for item in parameters]
    clean_by_target: dict[str, list[_Parameter]] = {}
    for item, classification in classified:
        if not classification.signals:
            clean_by_target.setdefault(item.target, []).append(item)
    suspicious = [
        (item, classification) for item, classification in classified if classification.signals
    ]
    status = "completed"
    if any(detail["reason"] == "failed" for _, _, detail in skips):
        status = "partial"
    elif skips:
        status = "budget-limited"
    event_count = 0
    runtime_skip_count = 0
    partial_event = False
    finding_targets: dict[str, list[tuple[int, str, float]]] = {}
    with database.connect() as connection:
        for scope_kind, scope_id, detail in skips:
            _insert_detector_skip(connection, detector_run_id, scope_kind, scope_id, detail)
        for item, classification in suspicious:
            if event_count >= max_events:
                _insert_detector_skip(
                    connection,
                    detector_run_id,
                    "parameter",
                    f"{item.transaction_public_id}:{item.source}:{item.ordinal}",
                    {"reason": "event-limit"},
                )
                runtime_skip_count += 1
                status = "budget-limited"
                continue
            baseline_options = clean_by_target.get(item.target, [])
            baseline = (
                min(
                    baseline_options,
                    key=lambda candidate: (
                        abs(candidate.request_frame - item.request_frame),
                        candidate.request_frame,
                    ),
                )
                if baseline_options
                else None
            )
            differs, comparison = _response_difference(item, baseline)
            confidence = min(0.99, classification.confidence + (0.08 if differs else 0.0))
            complete = (
                baseline is not None
                and _response_is_usable(item)
                and _response_is_usable(baseline)
            )
            event_status = "complete" if complete else "partial"
            if not complete:
                confidence = min(confidence, 0.70)
                partial_event = True
            request_evidence_id = _query_evidence(
                connection, capture_id, project.capture_sha256, item
            )
            response_evidence_id = _response_metadata_evidence(
                connection, capture_id, project.capture_sha256, item
            )
            baseline_evidence_id = (
                _query_evidence(connection, capture_id, project.capture_sha256, baseline)
                if baseline is not None
                else None
            )
            semantic_key = stable_id(
                "sql-probe-semantic",
                {
                    "target": item.target,
                    "value": _normalize_probe(item.value),
                    "signals": classification.signals,
                },
            )
            public_event_id = stable_id(
                "behavior-event",
                {
                    "detector": SQL_DETECTOR,
                    "version": SQL_DETECTOR_VERSION,
                    "transaction_id": item.transaction_public_id,
                    "source": item.source,
                    "ordinal": item.ordinal,
                },
            )
            duplicate = connection.execute(
                "SELECT id FROM behavior_event WHERE capture_id=? AND detector=? "
                "AND semantic_key=? AND request_frame<? ORDER BY request_frame,id LIMIT 1",
                (capture_id, SQL_DETECTOR, semantic_key, item.request_frame),
            ).fetchone()
            preview, preview_truncated = _bounded_preview(item.value, max_preview_bytes)
            detail = {
                "comparison": comparison,
                "parameter": item.name,
                "preview": preview,
                "preview_truncated": preview_truncated,
                "signals": classification.signals,
                "source": item.source,
                "value_sha256": hashlib.sha256(item.value.encode("utf-8")).hexdigest(),
            }
            connection.execute(
                "INSERT INTO behavior_event "
                "(event_id,capture_id,transaction_id,protocol_message_id,detector,"
                "detector_version,event_kind,status,request_frame,response_frame,target,"
                "semantic_key,confidence,detail_json,duplicate_of,created_at) "
                "VALUES(?,?,?,?,?,?,'sql-injection-probe',?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(event_id) DO UPDATE SET status=excluded.status,"
                "response_frame=excluded.response_frame,target=excluded.target,"
                "semantic_key=excluded.semantic_key,confidence=excluded.confidence,"
                "detail_json=excluded.detail_json,duplicate_of=excluded.duplicate_of",
                (
                    public_event_id,
                    capture_id,
                    item.transaction_db_id,
                    item.request_message_db_id,
                    SQL_DETECTOR,
                    SQL_DETECTOR_VERSION,
                    event_status,
                    item.request_frame,
                    item.response_frame,
                    item.target,
                    semantic_key,
                    confidence,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    int(duplicate[0]) if duplicate is not None else None,
                    _now(),
                ),
            )
            event_db_id = int(
                connection.execute(
                    "SELECT id FROM behavior_event WHERE event_id=?", (public_event_id,)
                ).fetchone()[0]
            )
            for evidence_db_id, role in (
                (request_evidence_id, "request-parameter"),
                (response_evidence_id, "response"),
                (baseline_evidence_id, "clean-baseline"),
            ):
                if evidence_db_id is not None:
                    connection.execute(
                        "INSERT OR IGNORE INTO behavior_event_evidence"
                        "(event_id,evidence_id,role) VALUES(?,?,?)",
                        (event_db_id, evidence_db_id, role),
                    )
            connection.execute(
                "INSERT OR IGNORE INTO behavior_event_run(event_id,detector_run_id) VALUES(?,?)",
                (event_db_id, detector_run_id),
            )
            finding_targets.setdefault(item.target, []).append(
                (request_evidence_id, "probe", confidence)
            )
            if baseline_evidence_id is not None:
                finding_targets[item.target].append(
                    (baseline_evidence_id, "clean-baseline", confidence)
                )
            event_count += 1
        if partial_event and status == "completed":
            status = "partial"
        finding_count = 0
        for target, evidence_rows in sorted(finding_targets.items()):
            if finding_count >= max_findings:
                _insert_detector_skip(
                    connection,
                    detector_run_id,
                    "finding",
                    target,
                    {"reason": "finding-limit"},
                )
                runtime_skip_count += 1
                status = "budget-limited"
                continue
            evidence_roles = {(row[0], row[1]) for row in evidence_rows}
            confidence = max(row[2] for row in evidence_rows)
            public_finding_id = stable_id(
                "finding",
                {
                    "capture_sha256": project.capture_sha256,
                    "detector": SQL_DETECTOR,
                    "target": target,
                },
            )
            connection.execute(
                "INSERT INTO finding "
                "(finding_id,detector,detector_version,title,description,severity,"
                "confidence,recommended_action,created_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(finding_id) DO UPDATE SET description=excluded.description,"
                "confidence=excluded.confidence,severity=excluded.severity",
                (
                    public_finding_id,
                    SQL_DETECTOR,
                    SQL_DETECTOR_VERSION,
                    "Possible SQL-injection behavior",
                    f"Structured SQL-injection signals were observed for {target}.",
                    "high" if confidence >= 0.8 else "medium",
                    confidence,
                    "Review the ordered requests and comparison responses.",
                    _now(),
                ),
            )
            finding_db_id = int(
                connection.execute(
                    "SELECT id FROM finding WHERE finding_id=?", (public_finding_id,)
                ).fetchone()[0]
            )
            for evidence_db_id, role in sorted(evidence_roles):
                connection.execute(
                    "INSERT OR IGNORE INTO finding_evidence"
                    "(finding_id,evidence_id,role) VALUES(?,?,?)",
                    (finding_db_id, evidence_db_id, role),
                )
            connection.execute(
                "INSERT OR IGNORE INTO finding_run(finding_id,tool_run_id) VALUES(?,?)",
                (finding_db_id, tool_run_id),
            )
            finding_count += 1
        total_skips = len(skips) + runtime_skip_count
        connection.execute(
            "UPDATE detector_run SET status=?,inputs_processed=?,inputs_skipped=?,"
            "findings=?,events=?,ended_at=? WHERE id=?",
            (
                status,
                len(parameters),
                total_skips,
                finding_count,
                event_count,
                _now(),
                detector_run_id,
            ),
        )
        connection.execute(
            "UPDATE tool_run SET status='completed',ended_at=? WHERE id=?",
            (_now(), tool_run_id),
        )
    return SqlDetectionSummary(
        "auto-shark.sql-detection/v1",
        str(project.root),
        run_id,
        status,
        transactions_processed,
        len(parameters),
        total_skips,
        event_count,
        finding_count,
    )


def detect_sql_injection(
    project_path: Path,
    *,
    max_transactions: int = 10_000,
    max_parameters: int = 1024,
    max_parameter_bytes: int = 4096,
    max_events: int = 10_000,
    max_findings: int = 1000,
    max_preview_bytes: int = 256,
) -> SqlDetectionSummary:
    if (
        min(
            max_transactions,
            max_parameters,
            max_parameter_bytes,
            max_events,
            max_findings,
            max_preview_bytes,
        )
        <= 0
    ):
        raise ValueError("SQL detector limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    run_id = str(uuid4())
    policy = {
        "max_events": max_events,
        "max_findings": max_findings,
        "max_parameter_bytes": max_parameter_bytes,
        "max_parameters": max_parameters,
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
            "INSERT INTO detector_run "
            "(run_id,capture_id,detector_set,detector_version,policy_json,status,"
            "inputs_processed,inputs_skipped,candidates,findings,events,started_at) "
            "VALUES(?,?,?,?,?,'partial',0,0,0,0,0,?)",
            (
                run_id,
                capture_id,
                SQL_DETECTOR,
                SQL_DETECTOR_VERSION,
                json.dumps(policy, sort_keys=True),
                _now(),
            ),
        )
        detector_run_id = int(
            connection.execute("SELECT id FROM detector_run WHERE run_id=?", (run_id,)).fetchone()[
                0
            ]
        )
        tool_run_public = uuid4().hex
        connection.execute(
            "INSERT INTO tool_run "
            "(run_id,tool_name,tool_version,argv_json,started_at,status) "
            "VALUES(?,?,?,?,?,'running')",
            (
                tool_run_public,
                "auto-shark-sql-detector",
                SQL_DETECTOR_VERSION,
                json.dumps(policy, sort_keys=True),
                _now(),
            ),
        )
        tool_run_id = int(
            connection.execute(
                "SELECT id FROM tool_run WHERE run_id=?", (tool_run_public,)
            ).fetchone()[0]
        )
    try:
        return _run_sql_detection(
            database,
            project,
            run_id,
            capture_id,
            detector_run_id,
            tool_run_id,
            max_transactions=max_transactions,
            max_parameters=max_parameters,
            max_parameter_bytes=max_parameter_bytes,
            max_events=max_events,
            max_findings=max_findings,
            max_preview_bytes=max_preview_bytes,
        )
    except Exception as error:
        _mark_detector_failed(database, detector_run_id, tool_run_id, run_id, error)
        raise
