"""Top-level analysis orchestration for tested protocol slices."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import TlsRsaKey, probe_tshark
from .project import create_project
from .protocols.http import HttpMessage, parse_http_line, tshark_http_arguments
from .storage import Database


@dataclass(frozen=True)
class AnalysisSummary:
    project: str
    capture_sha256: str
    tshark_version: str
    http_requests: int
    http_responses: int
    http_transactions: int
    matched_transactions: int
    unmatched_requests: int
    orphan_responses: int
    matching_uri: Optional[str]
    matching_transactions: Optional[int]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_message(
    connection: sqlite3.Connection, capture_db_id: int, capture_sha256: str, message: HttpMessage
) -> None:
    connection.execute(
        "INSERT OR IGNORE INTO frame "
        "(capture_id, frame_number, time_epoch, captured_length, original_length) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            capture_db_id,
            message.frame_number,
            message.time_epoch,
            message.captured_length,
            message.frame_length,
        ),
    )
    endpoint_a = f"{message.source}:{message.source_port}"
    endpoint_b = f"{message.destination}:{message.destination_port}"
    conversation_public_id = stable_id(
        "conversation",
        {
            "capture_sha256": capture_sha256,
            "protocol": "tcp",
            "stream_index": message.tcp_stream,
        },
    )
    connection.execute(
        "INSERT OR IGNORE INTO conversation "
        "(conversation_id, capture_id, protocol, stream_index, endpoint_a, endpoint_b) "
        "VALUES (?, ?, 'tcp', ?, ?, ?)",
        (
            conversation_public_id,
            capture_db_id,
            message.tcp_stream,
            endpoint_a,
            endpoint_b,
        ),
    )
    conversation_db_id = int(
        connection.execute(
            "SELECT id FROM conversation WHERE conversation_id = ?", (conversation_public_id,)
        ).fetchone()[0]
    )
    message_public_id = stable_id(
        "protocol-message",
        {
            "capture_sha256": capture_sha256,
            "protocol": "http",
            "frame_number": message.frame_number,
            "kind": message.kind,
        },
    )
    connection.execute(
        "INSERT INTO protocol_message "
        "(message_id, capture_id, conversation_id, representative_frame, protocol, "
        "direction, message_kind, fields_json) VALUES (?, ?, ?, ?, 'http', ?, ?, ?)",
        (
            message_public_id,
            capture_db_id,
            conversation_db_id,
            message.frame_number,
            f"{endpoint_a}>{endpoint_b}",
            message.kind,
            json.dumps(message.fields(), ensure_ascii=False, sort_keys=True),
        ),
    )
    protocol_message_id = int(
        connection.execute(
            "SELECT id FROM protocol_message WHERE message_id = ?", (message_public_id,)
        ).fetchone()[0]
    )
    connection.execute(
        "INSERT INTO http_message "
        "(protocol_message_id, method, uri, full_uri, host, response_code, "
        "response_phrase, response_in_frame, request_in_frame, content_length, "
        "content_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            protocol_message_id,
            message.method,
            message.uri,
            message.full_uri,
            message.host,
            message.response_code,
            message.response_phrase,
            message.response_in_frame,
            message.request_in_frame,
            message.content_length,
            message.content_type,
        ),
    )


def _message_by_frame(
    connection: sqlite3.Connection, capture_db_id: int, frame_number: int, kind: str
) -> Optional[sqlite3.Row]:
    return connection.execute(
        "SELECT pm.id, pm.representative_frame FROM protocol_message pm "
        "WHERE pm.capture_id = ? AND pm.representative_frame = ? "
        "AND pm.protocol = 'http' AND pm.message_kind = ?",
        (capture_db_id, frame_number, kind),
    ).fetchone()


def _pair_http(connection: sqlite3.Connection, capture_db_id: int, capture_sha256: str) -> None:
    requests = connection.execute(
        "SELECT pm.id, pm.representative_frame, hm.response_in_frame "
        "FROM protocol_message pm JOIN http_message hm ON hm.protocol_message_id = pm.id "
        "WHERE pm.capture_id = ? AND pm.message_kind = 'request' "
        "ORDER BY pm.representative_frame",
        (capture_db_id,),
    ).fetchall()
    linked_responses: set[int] = set()
    for request in requests:
        response_rows = list(
            connection.execute(
                "SELECT pm.id, pm.representative_frame FROM protocol_message pm "
                "JOIN http_message hm ON hm.protocol_message_id = pm.id "
                "WHERE pm.capture_id = ? AND pm.message_kind = 'response' "
                "AND hm.request_in_frame = ? ORDER BY pm.representative_frame",
                (capture_db_id, request["representative_frame"]),
            ).fetchall()
        )
        response_in = request["response_in_frame"]
        if response_in is not None:
            direct = _message_by_frame(connection, capture_db_id, int(response_in), "response")
            if direct is not None and all(row["id"] != direct["id"] for row in response_rows):
                response_rows.append(direct)
                response_rows.sort(key=lambda row: int(row["representative_frame"]))
        transaction_public_id = stable_id(
            "http-transaction",
            {
                "capture_sha256": capture_sha256,
                "request_frame": request["representative_frame"],
            },
        )
        primary_response = int(response_rows[0]["id"]) if response_rows else None
        status = "matched" if response_rows else "unmatched-request"
        connection.execute(
            "INSERT INTO transaction_record "
            "(transaction_id, capture_id, protocol, request_message_id, "
            "response_message_id, status) VALUES (?, ?, 'http', ?, ?, ?)",
            (transaction_public_id, capture_db_id, request["id"], primary_response, status),
        )
        transaction_db_id = int(
            connection.execute(
                "SELECT id FROM transaction_record WHERE transaction_id = ?",
                (transaction_public_id,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO transaction_message "
            "(transaction_id, protocol_message_id, role, ordinal) VALUES (?, ?, 'request', 0)",
            (transaction_db_id, request["id"]),
        )
        for ordinal, response in enumerate(response_rows):
            response_id = int(response["id"])
            linked_responses.add(response_id)
            role = "response" if ordinal == 0 else "extra_response"
            connection.execute(
                "INSERT INTO transaction_message "
                "(transaction_id, protocol_message_id, role, ordinal) VALUES (?, ?, ?, ?)",
                (transaction_db_id, response_id, role, ordinal),
            )

    responses = connection.execute(
        "SELECT pm.id, pm.representative_frame FROM protocol_message pm "
        "WHERE pm.capture_id = ? AND pm.protocol = 'http' AND pm.message_kind = 'response' "
        "ORDER BY pm.representative_frame",
        (capture_db_id,),
    ).fetchall()
    for response in responses:
        if int(response["id"]) in linked_responses:
            continue
        transaction_public_id = stable_id(
            "http-orphan-transaction",
            {
                "capture_sha256": capture_sha256,
                "response_frame": response["representative_frame"],
            },
        )
        connection.execute(
            "INSERT INTO transaction_record "
            "(transaction_id, capture_id, protocol, response_message_id, status) "
            "VALUES (?, ?, 'http', ?, 'orphan-response')",
            (transaction_public_id, capture_db_id, response["id"]),
        )
        transaction_db_id = int(
            connection.execute(
                "SELECT id FROM transaction_record WHERE transaction_id = ?",
                (transaction_public_id,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO transaction_message "
            "(transaction_id, protocol_message_id, role, ordinal) VALUES (?, ?, 'response', 0)",
            (transaction_db_id, response["id"]),
        )


def _summary(
    database: Database,
    project: Path,
    capture_db_id: int,
    capture_sha256: str,
    tshark_version: str,
    matching_uri: Optional[str],
) -> AnalysisSummary:
    with database.connect() as connection:
        counts = {
            str(row["message_kind"]): int(row["count"])
            for row in connection.execute(
                "SELECT message_kind, count(*) AS count FROM protocol_message "
                "WHERE capture_id = ? AND protocol = 'http' GROUP BY message_kind",
                (capture_db_id,),
            )
        }
        statuses = {
            str(row["status"]): int(row["count"])
            for row in connection.execute(
                "SELECT status, count(*) AS count FROM transaction_record "
                "WHERE capture_id = ? AND protocol = 'http' GROUP BY status",
                (capture_db_id,),
            )
        }
        matching_count: Optional[int] = None
        if matching_uri is not None:
            matching_count = int(
                connection.execute(
                    "SELECT count(*) FROM transaction_record tr "
                    "JOIN http_message hm ON hm.protocol_message_id = tr.request_message_id "
                    "WHERE tr.capture_id = ? AND tr.protocol = 'http' AND hm.uri = ?",
                    (capture_db_id, matching_uri),
                ).fetchone()[0]
            )
    return AnalysisSummary(
        project=str(project),
        capture_sha256=capture_sha256,
        tshark_version=tshark_version,
        http_requests=counts.get("request", 0),
        http_responses=counts.get("response", 0),
        http_transactions=sum(statuses.values()),
        matched_transactions=statuses.get("matched", 0),
        unmatched_requests=statuses.get("unmatched-request", 0),
        orphan_responses=statuses.get("orphan-response", 0),
        matching_uri=matching_uri,
        matching_transactions=matching_count,
    )


def analyze_http(
    capture: Path,
    project: Path,
    tshark: Path,
    *,
    matching_uri: Optional[str] = None,
    tls_rsa_key: Optional[TlsRsaKey] = None,
) -> AnalysisSummary:
    capabilities = probe_tshark(tshark)
    if not capabilities.usable or not capabilities.features.get("http", False):
        raise ValueError("TShark lacks required HTTP capabilities")
    project_info = create_project(capture, project)
    database = Database(project_info.root / "project.sqlite")
    preferences = tls_rsa_key.arguments if tls_rsa_key is not None else ()
    argv = tshark_http_arguments(tshark, project_info.capture_path, preferences=preferences)
    provenance_argv = tls_rsa_key.redact_argv(argv) if tls_rsa_key is not None else argv
    run_public_id = uuid4().hex
    with database.connect() as connection:
        capture_db_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256 = ?", (project_info.capture_sha256,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO tool_run "
            "(run_id, tool_name, tool_version, argv_json, capability_json, "
            "started_at, status) VALUES (?, 'tshark', ?, ?, ?, ?, 'running')",
            (
                run_public_id,
                capabilities.version_line,
                json.dumps(provenance_argv, ensure_ascii=False),
                capabilities.to_provenance_json(tls_rsa_key=tls_rsa_key),
                _utc_now(),
            ),
        )
    status = "failed"
    exit_code = None
    stderr_text = "analysis failed; see caller error"
    stderr_truncated = 0
    try:
        with database.connect() as connection:

            def consume(line: bytes) -> None:
                if line:
                    _record_message(
                        connection,
                        capture_db_id,
                        project_info.capture_sha256,
                        parse_http_line(line),
                    )

            result = run_streaming_lines(
                argv,
                consume,
                timeout_seconds=300,
                max_line_bytes=4 * 1024 * 1024,
                stderr_limit=512 * 1024,
            )
            if result.timed_out:
                raise TimeoutError("TShark HTTP metadata extraction timed out")
            if result.output_limit_exceeded:
                raise ValueError("TShark emitted a metadata line above the configured limit")
            if result.returncode != 0:
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                raise ValueError(
                    f"TShark HTTP extraction exited {result.returncode}: {detail[:500]}"
                )
            _pair_http(connection, capture_db_id, project_info.capture_sha256)
        status = "completed"
        exit_code = result.returncode
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        stderr_truncated = int(result.stderr_truncated)
    finally:
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at = ?, status = ?, exit_code = ?, "
                "stderr_text = ?, stderr_truncated = ? WHERE run_id = ?",
                (_utc_now(), status, exit_code, stderr_text, stderr_truncated, run_public_id),
            )
    return _summary(
        database,
        project_info.root,
        capture_db_id,
        project_info.capture_sha256,
        capabilities.version_line,
        matching_uri,
    )
