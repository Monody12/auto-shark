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


@dataclass(frozen=True)
class TelnetQueryPage:
    schema_version: str
    project: str
    offset: int
    limit: int
    total: int
    count: int
    max_records_per_dialogue: int
    max_preview_bytes: int
    max_total_preview_bytes: int
    max_source_mappings: int
    max_relations: int
    max_candidates: int
    preview_bytes: int
    items: tuple[dict[str, object], ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class SummaryQueryPage:
    schema_version: str
    project: str
    protocol_offset: int
    protocol_limit: int
    conversation_offset: int
    conversation_limit: int
    protocol_total: int
    conversation_total: int
    coverage: dict[str, int]
    protocols: tuple[dict[str, object], ...]
    conversations: tuple[dict[str, object], ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class ManualQueuePage:
    schema_version: str
    project: str
    offset: int
    limit: int
    total: int
    count: int
    max_signals: int
    max_evidence_links: int
    max_detail_bytes: int
    signals_returned: int
    evidence_links_returned: int
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


def _escaped_preview(data: bytes) -> str:
    pieces: list[str] = []
    named = {9: r"\t", 10: r"\n", 13: r"\r"}
    for value in data:
        if value in named:
            pieces.append(named[value])
        elif value == 92:
            pieces.append(r"\\")
        elif 32 <= value <= 126:
            pieces.append(chr(value))
        else:
            pieces.append(f"\\x{value:02x}")
    return "".join(pieces)


def query_telnet_dialogues(
    project_path: Path,
    *,
    offset: int = 0,
    limit: int = DEFAULT_PAGE_LIMIT,
    stream: Optional[int] = None,
    max_records_per_dialogue: int = 1000,
    max_preview_bytes: int = 256,
    max_total_preview_bytes: int = 64 * 1024,
    max_source_mappings: int = 10_000,
    max_relations: int = 10_000,
    max_candidates: int = 10_000,
) -> TelnetQueryPage:
    _validate_page(offset, limit)
    if stream is not None and stream < 0:
        raise ValueError("TCP stream index cannot be negative")
    if min(
        max_records_per_dialogue,
        max_preview_bytes,
        max_total_preview_bytes,
        max_source_mappings,
        max_relations,
        max_candidates,
    ) <= 0:
        raise ValueError("Telnet query limits must be positive")
    if max_records_per_dialogue > 10_000:
        raise ValueError("Telnet records per dialogue cannot exceed 10000")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    where = ""
    parameters: list[object] = []
    if stream is not None:
        where = " WHERE c.stream_index=?"
        parameters.append(stream)
    base = (
        " FROM telnet_dialogue td JOIN conversation c ON c.id=td.conversation_id "
        "LEFT JOIN tcp_reconstruction client_tr ON client_tr.id=td.client_reconstruction_id "
        "LEFT JOIN evidence client_e ON client_e.id=client_tr.evidence_id "
        "LEFT JOIN blob client_b ON client_b.id=client_e.blob_id "
        "LEFT JOIN tcp_reconstruction server_tr ON server_tr.id=td.server_reconstruction_id "
        "LEFT JOIN evidence server_e ON server_e.id=server_tr.evidence_id "
        "LEFT JOIN blob server_b ON server_b.id=server_e.blob_id "
    )
    preview_remaining = max_total_preview_bytes
    preview_bytes = 0
    source_remaining = max_source_mappings
    relation_remaining = max_relations
    candidate_remaining = max_candidates
    items: list[dict[str, object]] = []
    with database.connect() as connection:
        total = int(connection.execute("SELECT count(*)" + base + where, parameters).fetchone()[0])
        dialogues = connection.execute(
            "SELECT td.id,td.dialogue_id,td.client_endpoint,td.server_endpoint,td.status,"
            "td.error,td.updated_at,c.stream_index,c.endpoint_a,c.endpoint_b,"
            "client_tr.reconstruction_id client_reconstruction_id,"
            "client_tr.direction client_direction,client_tr.status client_status,"
            "client_tr.updated_at client_updated_at,client_b.sha256 client_blob_sha256,"
            "client_b.byte_length client_blob_bytes,"
            "server_tr.reconstruction_id server_reconstruction_id,"
            "server_tr.direction server_direction,server_tr.status server_status,"
            "server_tr.updated_at server_updated_at,server_b.sha256 server_blob_sha256,"
            "server_b.byte_length server_blob_bytes "
            + base
            + where
            + " ORDER BY c.stream_index,td.dialogue_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
        for dialogue in dialogues:
            dialogue_id = int(dialogue["id"])
            total_records = int(
                connection.execute(
                    "SELECT count(*) FROM telnet_record WHERE dialogue_id=?", (dialogue_id,)
                ).fetchone()[0]
            )
            record_rows = connection.execute(
                "SELECT tr.id,tr.record_id,tr.direction_role,tr.record_kind,tr.stream_offset,"
                "tr.byte_length,tr.semantic_label,tr.command,tr.option_code,tr.frame_start,"
                "tr.frame_end,tr.time_start,tr.time_end,e.evidence_id,tcp_e.blob_id,"
                "tcp_b.sha256,tcp_b.relative_path,tcp_tr.updated_at reconstruction_updated_at "
                "FROM telnet_record tr "
                "JOIN tcp_reconstruction tcp_tr ON tcp_tr.id=tr.reconstruction_id "
                "LEFT JOIN evidence tcp_e ON tcp_e.id=tcp_tr.evidence_id "
                "LEFT JOIN blob tcp_b ON tcp_b.id=tcp_e.blob_id "
                "LEFT JOIN evidence e ON e.id=tr.evidence_id WHERE tr.dialogue_id=? "
                "ORDER BY tr.frame_start,tr.time_start,tr.direction_role,tr.stream_offset,"
                "tr.record_id LIMIT ?",
                (dialogue_id, max_records_per_dialogue),
            ).fetchall()
            record_ids = tuple(int(row["id"]) for row in record_rows)
            source_map: dict[int, list[dict[str, object]]] = {}
            relation_map: dict[int, list[dict[str, str]]] = {}
            candidate_map: dict[int, list[dict[str, object]]] = {}
            source_counts: dict[int, int] = {}
            relation_counts: dict[int, int] = {}
            candidate_counts: dict[int, int] = {}
            if record_ids:
                placeholders = ",".join("?" for _ in record_ids)
                for count_row in connection.execute(
                    "SELECT record_id,count(*) FROM telnet_record_source "
                    f"WHERE record_id IN ({placeholders}) GROUP BY record_id",
                    record_ids,
                ):
                    source_counts[int(count_row[0])] = int(count_row[1])
                for source in connection.execute(
                    "SELECT trs.record_id,ts.frame_number,trs.record_offset,trs.stream_offset,"
                    "trs.byte_length FROM telnet_record_source trs "
                    "JOIN tcp_segment ts ON ts.id=trs.segment_id "
                    f"WHERE trs.record_id IN ({placeholders}) "
                    "ORDER BY trs.record_id,trs.record_offset,ts.frame_number LIMIT ?",
                    (*record_ids, source_remaining),
                ):
                    source_map.setdefault(int(source["record_id"]), []).append(
                        {
                            "frame": int(source["frame_number"]),
                            "record_offset": int(source["record_offset"]),
                            "stream_offset": int(source["stream_offset"]),
                            "byte_length": int(source["byte_length"]),
                        }
                    )
                    source_remaining -= 1
                for count_row in connection.execute(
                    "SELECT record_id,count(*) FROM telnet_record_relation "
                    f"WHERE record_id IN ({placeholders}) GROUP BY record_id",
                    record_ids,
                ):
                    relation_counts[int(count_row[0])] = int(count_row[1])
                for relation in connection.execute(
                    "SELECT rel.record_id,target.record_id target_record_id,rel.relation "
                    "FROM telnet_record_relation rel "
                    "JOIN telnet_record target ON target.id=rel.related_record_id "
                    f"WHERE rel.record_id IN ({placeholders}) "
                    "ORDER BY rel.record_id,rel.relation,target.record_id LIMIT ?",
                    (*record_ids, relation_remaining),
                ):
                    relation_map.setdefault(int(relation["record_id"]), []).append(
                        {
                            "relation": str(relation["relation"]),
                            "record_id": str(relation["target_record_id"]),
                        }
                    )
                    relation_remaining -= 1
                candidate_base = (
                    " FROM telnet_record tr JOIN evidence re ON re.id=tr.evidence_id "
                    "JOIN evidence ce ON ce.blob_id=re.blob_id "
                    "AND ce.capture_id=re.capture_id AND ce.direction=re.direction "
                    "AND ce.byte_offset < tr.stream_offset+tr.byte_length "
                    "AND ce.byte_offset+ce.byte_length > tr.stream_offset "
                    "JOIN candidate_evidence link ON link.evidence_id=ce.id "
                    "JOIN candidate c ON c.id=link.candidate_id "
                    f"WHERE tr.id IN ({placeholders}) "
                )
                for count_row in connection.execute(
                    "SELECT record_db_id,count(*) FROM (SELECT DISTINCT tr.id record_db_id,"
                    "c.candidate_id,ce.evidence_id" + candidate_base + ") GROUP BY record_db_id",
                    record_ids,
                ):
                    candidate_counts[int(count_row[0])] = int(count_row[1])
                for candidate in connection.execute(
                    "SELECT DISTINCT tr.id record_db_id,c.candidate_id,c.kind,c.rank_score,"
                    "c.confidence,ce.evidence_id candidate_evidence_id"
                    + candidate_base
                    + "ORDER BY tr.id,c.rank_score DESC,c.candidate_id,ce.evidence_id LIMIT ?",
                    (*record_ids, candidate_remaining),
                ):
                    candidate_map.setdefault(int(candidate["record_db_id"]), []).append(
                        {
                            "candidate_id": str(candidate["candidate_id"]),
                            "evidence_id": str(candidate["candidate_evidence_id"]),
                            "kind": str(candidate["kind"]),
                            "rank_score": float(candidate["rank_score"]),
                            "confidence": float(candidate["confidence"]),
                        }
                    )
                    candidate_remaining -= 1
            records: list[dict[str, object]] = []
            for record in record_rows:
                requested = min(int(record["byte_length"]), max_preview_bytes, preview_remaining)
                data = b""
                if requested and record["relative_path"] is not None:
                    with (project.root / str(record["relative_path"])).open("rb") as source:
                        source.seek(int(record["stream_offset"]))
                        data = source.read(requested)
                    if len(data) != requested:
                        raise ValueError("short Telnet preview blob read")
                preview_remaining -= len(data)
                preview_bytes += len(data)
                record_id = int(record["id"])
                records.append(
                    {
                        "record_id": record["record_id"],
                        "direction_role": record["direction_role"],
                        "kind": record["record_kind"],
                        "range": {
                            "start": int(record["stream_offset"]),
                            "end": int(record["stream_offset"]) + int(record["byte_length"]),
                            "byte_length": int(record["byte_length"]),
                        },
                        "semantic_label": record["semantic_label"],
                        "command": record["command"],
                        "option": record["option_code"],
                        "frames": {
                            "start": record["frame_start"],
                            "end": record["frame_end"],
                        },
                        "time": {"start": record["time_start"], "end": record["time_end"]},
                        "evidence_id": record["evidence_id"],
                        "blob_sha256": record["sha256"],
                        "preview": _escaped_preview(data),
                        "preview_bytes": len(data),
                        "preview_truncated": len(data) < int(record["byte_length"]),
                        "sources": source_map.get(record_id, []),
                        "source_count": source_counts.get(record_id, 0),
                        "sources_truncated": len(source_map.get(record_id, []))
                        < source_counts.get(record_id, 0),
                        "relations": relation_map.get(record_id, []),
                        "relation_count": relation_counts.get(record_id, 0),
                        "relations_truncated": len(relation_map.get(record_id, []))
                        < relation_counts.get(record_id, 0),
                        "candidates": candidate_map.get(record_id, []),
                        "candidate_count": candidate_counts.get(record_id, 0),
                        "candidates_truncated": len(candidate_map.get(record_id, []))
                        < candidate_counts.get(record_id, 0),
                    }
                )
            reconstruction_updates = tuple(
                value
                for value in (
                    dialogue["client_updated_at"],
                    dialogue["server_updated_at"],
                )
                if value is not None
            )
            current = bool(reconstruction_updates) and all(
                str(dialogue["updated_at"]) >= str(value) for value in reconstruction_updates
            )
            items.append(
                {
                    "dialogue_id": dialogue["dialogue_id"],
                    "stream_index": int(dialogue["stream_index"]),
                    "status": dialogue["status"],
                    "error": dialogue["error"],
                    "current": current,
                    "endpoints": {
                        "capture": [dialogue["endpoint_a"], dialogue["endpoint_b"]],
                        "client": dialogue["client_endpoint"],
                        "server": dialogue["server_endpoint"],
                    },
                    "directions": {
                        "client": {
                            "reconstruction_id": dialogue["client_reconstruction_id"],
                            "direction": dialogue["client_direction"],
                            "status": dialogue["client_status"],
                            "blob_sha256": dialogue["client_blob_sha256"],
                            "byte_length": dialogue["client_blob_bytes"],
                        },
                        "server": {
                            "reconstruction_id": dialogue["server_reconstruction_id"],
                            "direction": dialogue["server_direction"],
                            "status": dialogue["server_status"],
                            "blob_sha256": dialogue["server_blob_sha256"],
                            "byte_length": dialogue["server_blob_bytes"],
                        },
                    },
                    "total_records": total_records,
                    "record_count": len(records),
                    "records_truncated": len(records) < total_records,
                    "records": records,
                }
            )
    return TelnetQueryPage(
        schema_version="auto-shark.telnet-dialogues/v1",
        project=str(project.root),
        offset=offset,
        limit=limit,
        total=total,
        count=len(items),
        max_records_per_dialogue=max_records_per_dialogue,
        max_preview_bytes=max_preview_bytes,
        max_total_preview_bytes=max_total_preview_bytes,
        max_source_mappings=max_source_mappings,
        max_relations=max_relations,
        max_candidates=max_candidates,
        preview_bytes=preview_bytes,
        items=tuple(items),
    )


def query_summary(
    project_path: Path,
    *,
    protocol_offset: int = 0,
    protocol_limit: int = DEFAULT_PAGE_LIMIT,
    conversation_offset: int = 0,
    conversation_limit: int = DEFAULT_PAGE_LIMIT,
) -> SummaryQueryPage:
    if min(protocol_offset, conversation_offset) < 0:
        raise ValueError("summary offsets cannot be negative")
    if not 0 < protocol_limit <= MAX_PAGE_LIMIT:
        raise ValueError("protocol limit must be between 1 and 1000")
    if not 0 < conversation_limit <= MAX_PAGE_LIMIT:
        raise ValueError("conversation limit must be between 1 and 1000")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        protocol_total = int(
            connection.execute(
                "SELECT count(*) FROM protocol_observation WHERE capture_id=?",
                (capture_id,),
            ).fetchone()[0]
        )
        conversation_total = int(
            connection.execute(
                "SELECT count(*) FROM conversation_profile WHERE capture_id=?",
                (capture_id,),
            ).fetchone()[0]
        )
        protocols = tuple(
            dict(row)
            for row in connection.execute(
                "SELECT po.observation_id,po.protocol_label,po.frame_count,"
                "po.first_frame,po.last_frame,ac.status coverage_status "
                "FROM protocol_observation po LEFT JOIN analysis_coverage ac "
                "ON ac.capture_id=po.capture_id AND ac.subject_kind='protocol' "
                "AND ac.subject_id=po.observation_id WHERE po.capture_id=? "
                "ORDER BY po.frame_count DESC,po.protocol_label LIMIT ? OFFSET ?",
                (capture_id, protocol_limit, protocol_offset),
            )
        )
        conversations = tuple(
            {
                **dict(row),
                "protocol_labels": json.loads(str(row["protocol_labels_json"])),
            }
            for row in connection.execute(
                "SELECT cp.profile_id,cp.protocol,cp.stream_index,cp.endpoint_a,"
                "cp.endpoint_b,cp.initiator_endpoint,cp.responder_endpoint,"
                "cp.first_frame,cp.last_frame,cp.first_time,cp.last_time,"
                "cp.frame_count,cp.captured_bytes,cp.wire_bytes,cp.payload_bytes,"
                "cp.protocol_labels_json,ac.status coverage_status "
                "FROM conversation_profile cp LEFT JOIN analysis_coverage ac "
                "ON ac.capture_id=cp.capture_id AND ac.subject_kind='conversation' "
                "AND ac.subject_id=cp.profile_id WHERE cp.capture_id=? "
                "ORDER BY cp.protocol,cp.stream_index LIMIT ? OFFSET ?",
                (capture_id, conversation_limit, conversation_offset),
            )
        )
        coverage = {
            str(row["status"]): int(row["count"])
            for row in connection.execute(
                "SELECT status,count(*) count FROM analysis_coverage "
                "WHERE capture_id=? GROUP BY status ORDER BY status",
                (capture_id,),
            )
        }
    return SummaryQueryPage(
        schema_version="auto-shark.summary/v1",
        project=str(project.root),
        protocol_offset=protocol_offset,
        protocol_limit=protocol_limit,
        conversation_offset=conversation_offset,
        conversation_limit=conversation_limit,
        protocol_total=protocol_total,
        conversation_total=conversation_total,
        coverage=coverage,
        protocols=protocols,
        conversations=conversations,
    )


def query_manual_queue(
    project_path: Path,
    *,
    state: Optional[str] = None,
    kind: Optional[str] = None,
    min_priority: int = 0,
    subject_kind: Optional[str] = None,
    subject_id: Optional[str] = None,
    offset: int = 0,
    limit: int = DEFAULT_PAGE_LIMIT,
    max_signals: int = 1000,
    max_evidence_links: int = 1000,
    max_detail_bytes: int = 4096,
) -> ManualQueuePage:
    if min(offset, min_priority) < 0 or min_priority > 100:
        raise ValueError("invalid manual queue offset or minimum priority")
    if not 0 < limit <= MAX_PAGE_LIMIT:
        raise ValueError("manual queue limit must be between 1 and 1000")
    if min(max_signals, max_evidence_links, max_detail_bytes) <= 0:
        raise ValueError("manual queue auxiliary limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    where = ["mt.capture_id=?", "mt.suggested_priority>=?"]
    parameters: list[object] = [None, min_priority]
    if state is not None:
        where.append("mt.state=?")
        parameters.append(state)
    if kind is not None:
        where.append("mt.task_kind=?")
        parameters.append(kind)
    if subject_kind is not None:
        where.append("mt.subject_kind=?")
        parameters.append(subject_kind)
    if subject_id is not None:
        where.append("mt.subject_id=?")
        parameters.append(subject_id)
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
                f"SELECT count(*) FROM manual_task mt WHERE {clause}", parameters
            ).fetchone()[0]
        )
        rows = connection.execute(
            "SELECT mt.id,mt.task_id,mt.subject_kind,mt.subject_id,mt.task_kind,"
            "mt.suggested_priority,mt.state,mt.created_at,mt.updated_at "
            f"FROM manual_task mt WHERE {clause} "
            "ORDER BY mt.suggested_priority DESC,mt.task_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
        signal_remaining = max_signals
        evidence_remaining = max_evidence_links
        items = []
        signals_returned = evidence_returned = 0
        for row in rows:
            signal_total = int(
                connection.execute(
                    "SELECT count(*) FROM manual_task_signal WHERE task_id=?",
                    (row["id"],),
                ).fetchone()[0]
            )
            signals = []
            if signal_remaining:
                for signal in connection.execute(
                    "SELECT rule_name,rule_version,score,detail_json "
                    "FROM manual_task_signal WHERE task_id=? "
                    "ORDER BY score DESC,rule_name LIMIT ?",
                    (row["id"], signal_remaining),
                ):
                    detail_json = str(signal["detail_json"])
                    detail_truncated = len(detail_json.encode("utf-8")) > max_detail_bytes
                    detail = (
                        detail_json.encode("utf-8")[:max_detail_bytes].decode(
                            "utf-8", errors="ignore"
                        )
                        if detail_truncated
                        else detail_json
                    )
                    signals.append(
                        {
                            "rule_name": signal["rule_name"],
                            "rule_version": signal["rule_version"],
                            "score": signal["score"],
                            "detail_json": detail,
                            "detail_truncated": detail_truncated,
                        }
                    )
                    signal_remaining -= 1
                    signals_returned += 1
            evidence_total = int(
                connection.execute(
                    "SELECT count(*) FROM manual_task_evidence WHERE task_id=?",
                    (row["id"],),
                ).fetchone()[0]
            )
            evidence = []
            if evidence_remaining:
                for link in connection.execute(
                    "SELECT e.evidence_id,mte.role FROM manual_task_evidence mte "
                    "JOIN evidence e ON e.id=mte.evidence_id WHERE mte.task_id=? "
                    "ORDER BY mte.role,e.evidence_id LIMIT ?",
                    (row["id"], evidence_remaining),
                ):
                    evidence.append(dict(link))
                    evidence_remaining -= 1
                    evidence_returned += 1
            item = dict(row)
            item.pop("id")
            item.update(
                {
                    "signal_count": signal_total,
                    "signals": signals,
                    "signals_truncated": len(signals) < signal_total,
                    "evidence_count": evidence_total,
                    "evidence": evidence,
                    "evidence_truncated": len(evidence) < evidence_total,
                }
            )
            items.append(item)
    return ManualQueuePage(
        schema_version="auto-shark.manual-queue/v1",
        project=str(project.root),
        offset=offset,
        limit=limit,
        total=total,
        count=len(items),
        max_signals=max_signals,
        max_evidence_links=max_evidence_links,
        max_detail_bytes=max_detail_bytes,
        signals_returned=signals_returned,
        evidence_links_returned=evidence_returned,
        items=tuple(items),
    )
