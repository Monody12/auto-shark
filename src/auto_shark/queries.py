"""Stable bounded read models for transactions and TCP streams."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .project import inspect_project
from .storage import Database

DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 1000


@dataclass(frozen=True)
class QueryPage:
    schema_version: str
    project: str
    offset: int
    limit: int
    total: int
    count: int
    items: tuple[dict[str, object], ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _validate_page(offset: int, limit: int) -> None:
    if offset < 0:
        raise ValueError("query offset cannot be negative")
    if limit <= 0 or limit > MAX_PAGE_LIMIT:
        raise ValueError(f"query limit must be between 1 and {MAX_PAGE_LIMIT}")


def query_transactions(
    project_path: Path,
    *,
    offset: int = 0,
    limit: int = DEFAULT_PAGE_LIMIT,
    uri: Optional[str] = None,
) -> QueryPage:
    _validate_page(offset, limit)
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    where = "WHERE tr.protocol='http'"
    parameters: list[object] = []
    if uri is not None:
        where += " AND request_http.uri=?"
        parameters.append(uri)
    base = (
        " FROM transaction_record tr "
        "LEFT JOIN protocol_message request_pm ON request_pm.id=tr.request_message_id "
        "LEFT JOIN http_message request_http ON request_http.protocol_message_id=request_pm.id "
        "LEFT JOIN protocol_message response_pm ON response_pm.id=tr.response_message_id "
        "LEFT JOIN http_message response_http ON response_http.protocol_message_id=response_pm.id "
    )
    with database.connect() as connection:
        total = int(connection.execute("SELECT count(*)" + base + where, parameters).fetchone()[0])
        rows = connection.execute(
            "SELECT tr.id,tr.transaction_id,tr.status,"
            "request_pm.message_id request_id,request_pm.representative_frame request_frame,"
            "request_http.method,request_http.uri,request_http.host,"
            "response_pm.message_id response_id,response_pm.representative_frame response_frame,"
            "response_http.response_code,response_http.response_phrase "
            + base
            + where
            + " ORDER BY coalesce(request_pm.representative_frame,"
            "response_pm.representative_frame),"
            "tr.transaction_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
        transaction_ids = tuple(int(row["id"]) for row in rows)
        roles: dict[int, dict[str, int]] = {}
        body_states: dict[int, dict[str, int]] = {}
        task_states: dict[int, dict[str, int]] = {}
        if transaction_ids:
            placeholders = ",".join("?" for _ in transaction_ids)
            for item in connection.execute(
                "SELECT transaction_id,role,count(*) FROM transaction_message "
                f"WHERE transaction_id IN ({placeholders}) "
                "GROUP BY transaction_id,role ORDER BY transaction_id,role",
                transaction_ids,
            ):
                roles.setdefault(int(item[0]), {})[str(item[1])] = int(item[2])
            for item in connection.execute(
                "SELECT tm.transaction_id,hb.status,count(*) FROM transaction_message tm "
                "JOIN http_body hb ON hb.protocol_message_id=tm.protocol_message_id "
                f"WHERE tm.transaction_id IN ({placeholders}) "
                "GROUP BY tm.transaction_id,hb.status ORDER BY tm.transaction_id,hb.status",
                transaction_ids,
            ):
                body_states.setdefault(int(item[0]), {})[str(item[1])] = int(item[2])
            for item in connection.execute(
                "SELECT tm.transaction_id,bt.status,count(*) FROM transaction_message tm "
                "JOIN body_task bt ON bt.protocol_message_id=tm.protocol_message_id "
                f"WHERE tm.transaction_id IN ({placeholders}) "
                "GROUP BY tm.transaction_id,bt.status ORDER BY tm.transaction_id,bt.status",
                transaction_ids,
            ):
                task_states.setdefault(int(item[0]), {})[str(item[1])] = int(item[2])
        items: list[dict[str, object]] = []
        for row in rows:
            transaction_db_id = int(row["id"])
            items.append(
                {
                    "transaction_id": row["transaction_id"],
                    "status": row["status"],
                    "request": {
                        "message_id": row["request_id"],
                        "frame": row["request_frame"],
                        "method": row["method"],
                        "uri": row["uri"],
                        "host": row["host"],
                    },
                    "response": {
                        "message_id": row["response_id"],
                        "frame": row["response_frame"],
                        "code": row["response_code"],
                        "phrase": row["response_phrase"],
                    },
                    "message_roles": roles.get(transaction_db_id, {}),
                    "body_states": body_states.get(transaction_db_id, {}),
                    "task_states": task_states.get(transaction_db_id, {}),
                }
            )
    return QueryPage(
        schema_version="auto-shark.transactions/v1",
        project=str(project.root),
        offset=offset,
        limit=limit,
        total=total,
        count=len(items),
        items=tuple(items),
    )


def query_streams(
    project_path: Path,
    *,
    offset: int = 0,
    limit: int = DEFAULT_PAGE_LIMIT,
) -> QueryPage:
    _validate_page(offset, limit)
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    with database.connect() as connection:
        total = int(
            connection.execute(
                "SELECT count(*) FROM tcp_reconstruction tr "
                "JOIN conversation c ON c.id=tr.conversation_id"
            ).fetchone()[0]
        )
        rows = connection.execute(
            "SELECT c.conversation_id,c.stream_index,c.endpoint_a,c.endpoint_b,"
            "tr.reconstruction_id,tr.direction,tr.status,tr.sequence_start,tr.sequence_end,"
            "tr.unique_bytes,tr.output_bytes,tr.duplicate_bytes,tr.conflict_bytes,tr.gap_bytes,"
            "tr.capture_midstream,tr.max_output_bytes,e.evidence_id,e.frame_start,e.frame_end,"
            "b.sha256,b.byte_length,"
            "(SELECT count(*) FROM tcp_segment ts JOIN tcp_segment_run tsr "
            "ON tsr.segment_id=ts.id WHERE ts.conversation_id=c.id "
            "AND ts.direction=tr.direction AND tsr.tool_run_id=tr.tool_run_id) segment_count,"
            "(SELECT count(*) FROM tcp_gap tg WHERE tg.reconstruction_id=tr.id) gap_count,"
            "(SELECT count(*) FROM tcp_overlap_conflict tc "
            "WHERE tc.reconstruction_id=tr.id) conflict_count,"
            "(SELECT min(ts.frame_number) FROM tcp_reconstruction_source trs "
            "JOIN tcp_segment ts ON ts.id=trs.segment_id "
            "WHERE trs.reconstruction_id=tr.id AND trs.role='primary') source_frame_start,"
            "(SELECT max(ts.frame_number) FROM tcp_reconstruction_source trs "
            "JOIN tcp_segment ts ON ts.id=trs.segment_id "
            "WHERE trs.reconstruction_id=tr.id AND trs.role='primary') source_frame_end "
            "FROM tcp_reconstruction tr JOIN conversation c ON c.id=tr.conversation_id "
            "LEFT JOIN evidence e ON e.id=tr.evidence_id LEFT JOIN blob b ON b.id=e.blob_id "
            "ORDER BY c.stream_index,tr.direction,tr.reconstruction_id LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        items = tuple(
            {
                "conversation_id": row["conversation_id"],
                "stream_index": row["stream_index"],
                "endpoints": [row["endpoint_a"], row["endpoint_b"]],
                "reconstruction_id": row["reconstruction_id"],
                "direction": row["direction"],
                "status": row["status"],
                "sequence": {"start": row["sequence_start"], "end": row["sequence_end"]},
                "bytes": {
                    "unique": row["unique_bytes"],
                    "output": row["output_bytes"],
                    "duplicate": row["duplicate_bytes"],
                    "conflict": row["conflict_bytes"],
                    "gap": row["gap_bytes"],
                    "limit": row["max_output_bytes"],
                },
                "counts": {
                    "segments": row["segment_count"],
                    "gaps": row["gap_count"],
                    "conflicts": row["conflict_count"],
                },
                "capture_midstream": bool(row["capture_midstream"]),
                "evidence": {
                    "evidence_id": row["evidence_id"],
                    "frame_start": row["source_frame_start"] or row["frame_start"],
                    "frame_end": row["source_frame_end"] or row["frame_end"],
                    "recorded_frame_start": row["frame_start"],
                    "recorded_frame_end": row["frame_end"],
                    "blob_sha256": row["sha256"],
                    "byte_length": row["byte_length"],
                },
            }
            for row in rows
        )
    return QueryPage(
        schema_version="auto-shark.streams/v1",
        project=str(project.root),
        offset=offset,
        limit=limit,
        total=total,
        count=len(items),
        items=items,
    )
