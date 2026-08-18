"""Bounded Telnet discovery and dialogue persistence over TCP reconstructions."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import EvidenceLocator, evidence_id, stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import TsharkCapabilities, probe_tshark
from .project import inspect_project
from .protocols.telnet import (
    TELNET_REQUIRED_FIELDS,
    TelnetByteRecord,
    TelnetFrame,
    TelnetParser,
    parse_telnet_line,
    selected_telnet_fields,
    tshark_telnet_arguments,
)
from .storage import Database
from .tcp import TcpReconstructionSummary, reconstruct_tcp_stream

PARSER_VERSION = 2
PARSER_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class TelnetIndexSummary:
    schema_version: str
    project: str
    metadata_frames: int
    skipped_metadata_frames: int
    streams: int
    complete: int
    partial: int
    conflicting: int
    truncated: int
    unresolved_role: int
    failed: int
    records: int
    parsed_bytes: int
    skipped_bytes: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class _StoredRecord:
    kind: str
    start: int
    end: int
    semantic_label: Optional[str]
    command: Optional[int]
    option: Optional[int]


@dataclass(frozen=True)
class _StreamDiscovery:
    stream_index: int
    capture_id: int
    conversation_id: int
    conversation_public_id: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_context(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    capture_sha256: str,
    frame: TelnetFrame,
) -> _StreamDiscovery:
    connection.execute(
        "INSERT OR IGNORE INTO frame "
        "(capture_id,frame_number,time_epoch,captured_length,original_length) "
        "VALUES (?,?,?,?,?)",
        (
            capture_id,
            frame.frame_number,
            frame.time_epoch,
            frame.captured_length,
            frame.frame_length,
        ),
    )
    public_id = stable_id(
        "conversation",
        {
            "capture_sha256": capture_sha256,
            "protocol": "tcp",
            "stream_index": frame.stream_index,
        },
    )
    connection.execute(
        "INSERT OR IGNORE INTO conversation "
        "(conversation_id,capture_id,protocol,stream_index,endpoint_a,endpoint_b) "
        "VALUES (?,?,'tcp',?,?,?)",
        (
            public_id,
            capture_id,
            frame.stream_index,
            f"{frame.source}:{frame.source_port}",
            f"{frame.destination}:{frame.destination_port}",
        ),
    )
    conversation_id = int(
        connection.execute(
            "SELECT id FROM conversation WHERE conversation_id=?", (public_id,)
        ).fetchone()[0]
    )
    return _StreamDiscovery(frame.stream_index, capture_id, conversation_id, public_id)


def _discover_streams(
    database: Database,
    project_root: Path,
    capture_path: Path,
    capture_sha256: str,
    tshark: Path,
    capabilities: TsharkCapabilities,
    *,
    max_metadata_frames: int,
) -> tuple[int, tuple[_StreamDiscovery, ...], tuple[int, ...], int, int]:
    available_fields = set(capabilities.fields)
    missing = sorted(set(TELNET_REQUIRED_FIELDS) - available_fields)
    ipv4 = {"ip.src", "ip.dst"}.issubset(available_fields)
    ipv6 = {"ipv6.src", "ipv6.dst"}.issubset(available_fields)
    if not capabilities.usable or missing or not (ipv4 or ipv6):
        if not (ipv4 or ipv6):
            missing.append("ip.src/ip.dst or ipv6.src/ipv6.dst")
        raise ValueError(f"TShark lacks required Telnet fields: {', '.join(missing)}")
    argv = tshark_telnet_arguments(tshark, capture_path, available_fields=available_fields)
    parsed_fields = selected_telnet_fields(available_fields)
    run_public_id = uuid4().hex
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO tool_run "
            "(run_id,tool_name,tool_version,argv_json,capability_json,started_at,status) "
            "VALUES (?,'tshark',?,?,?,?,'running')",
            (
                run_public_id,
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_provenance_json(),
                _utc_now(),
            ),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
    streams: dict[int, _StreamDiscovery] = {}
    skipped_streams: set[int] = set()
    metadata_frames = 0
    skipped_frames = 0
    run_status = "failed"
    exit_code = None
    stderr_text = "Telnet stream discovery failed; see caller error"
    stderr_truncated = 0
    try:

        def consume(line: bytes) -> None:
            nonlocal metadata_frames, skipped_frames
            frame = parse_telnet_line(line, parsed_fields)
            if metadata_frames >= max_metadata_frames:
                with database.connect() as connection:
                    discovery = _ensure_context(
                        connection,
                        capture_id=capture_id,
                        capture_sha256=capture_sha256,
                        frame=frame,
                    )
                    connection.execute(
                        "INSERT OR IGNORE INTO telnet_metadata_skip "
                        "(tool_run_id,capture_id,frame_number,stream_index,reason) "
                        "VALUES (?,?,?,?,'frame-limit')",
                        (tool_run_id, capture_id, frame.frame_number, frame.stream_index),
                    )
                streams.setdefault(frame.stream_index, discovery)
                skipped_frames += 1
                skipped_streams.add(frame.stream_index)
                return
            with database.connect() as connection:
                discovery = _ensure_context(
                    connection,
                    capture_id=capture_id,
                    capture_sha256=capture_sha256,
                    frame=frame,
                )
            streams.setdefault(frame.stream_index, discovery)
            metadata_frames += 1

        result = run_streaming_lines(
            argv,
            consume,
            timeout_seconds=300,
            max_line_bytes=1024 * 1024,
            stderr_limit=512 * 1024,
        )
        if result.timed_out:
            raise TimeoutError("TShark Telnet stream discovery timed out")
        if result.output_limit_exceeded:
            raise ValueError("TShark emitted a Telnet metadata line above the configured limit")
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"TShark Telnet discovery exited {result.returncode}: {detail[:500]}")
        run_status = "completed"
        exit_code = result.returncode
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        stderr_truncated = int(result.stderr_truncated)
    finally:
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
                "stderr_truncated=? WHERE id=?",
                (_utc_now(), run_status, exit_code, stderr_text, stderr_truncated, tool_run_id),
            )
    return (
        tool_run_id,
        tuple(streams[key] for key in sorted(streams)),
        tuple(sorted(skipped_streams)),
        metadata_frames,
        skipped_frames,
    )


class _RecordBuilder:
    def __init__(
        self, blob_path: Path, role: str, max_record_bytes: int, max_records: int
    ) -> None:
        self.blob_path = blob_path
        self.role = role
        self.max_record_bytes = max_record_bytes
        self.max_records = max_records
        self._start: Optional[int] = None
        self._data = bytearray()
        self._records: list[_StoredRecord] = []

    def _append_record(self, record: _StoredRecord) -> None:
        if len(self._records) < self.max_records:
            self._records.append(record)

    def _emit_application(self, label: Optional[str] = None) -> None:
        if self._start is None or not self._data:
            return
        self._append_record(
            _StoredRecord(
                "application",
                self._start,
                self._start + len(self._data),
                label,
                None,
                None,
            )
        )
        self._start = None
        self._data.clear()

    def _append_byte(self, offset: int, value: int) -> None:
        if self._data.endswith(b"\r"):
            if value in (0, 10):
                self._data.append(value)
                self._emit_application("line")
                return
            self._emit_application("line")
        if self._start is None:
            self._start = offset
        if value < 32 and value not in (10, 13):
            self._emit_application()
            self._start = offset
            self._data.append(value)
            self._emit_application("control")
            return
        self._data.append(value)
        if value == 10:
            self._emit_application("line")
        elif len(self._data) >= self.max_record_bytes:
            self._emit_application("bounded")

    def add(self, item: TelnetByteRecord) -> None:
        if item.kind != "application":
            self._emit_application()
            self._append_record(
                _StoredRecord(item.kind, item.start, item.end, None, item.command, item.option)
            )
            return
        with self.blob_path.open("rb") as stream:
            stream.seek(item.start)
            data = stream.read(item.byte_length)
        if len(data) != item.byte_length:
            raise ValueError("short Telnet reconstruction blob read")
        for index, value in enumerate(data):
            self._append_byte(item.start + index, value)

    def source_boundary(self) -> None:
        if self.role != "server" or not self._data:
            return
        if bytes(self._data).rstrip(b" \t").endswith(b":"):
            self._emit_application("prompt")

    def finish(self) -> tuple[_StoredRecord, ...]:
        self._emit_application("line" if self._data.endswith(b"\r") else None)
        result = tuple(self._records)
        self._records.clear()
        return result


def _source_rows(database: Database, reconstruction_id: int) -> list[sqlite3.Row]:
    with database.connect() as connection:
        return list(
            connection.execute(
                "SELECT trs.segment_id,trs.output_offset,trs.byte_length,ts.frame_number,"
                "f.time_epoch FROM tcp_reconstruction_source trs "
                "JOIN tcp_segment ts ON ts.id=trs.segment_id "
                "JOIN frame f ON f.capture_id=ts.capture_id AND f.frame_number=ts.frame_number "
                "WHERE trs.reconstruction_id=? AND trs.role='primary' "
                "ORDER BY trs.output_offset,ts.frame_number",
                (reconstruction_id,),
            ).fetchall()
        )


def _parse_records(
    database: Database,
    reconstruction_id: int,
    blob_path: Path,
    role: str,
    parse_bytes: int,
    max_record_bytes: int,
    max_records: int,
) -> tuple[_StoredRecord, ...]:
    parser = TelnetParser()
    builder = _RecordBuilder(blob_path, role, max_record_bytes, max_records)
    for source in _source_rows(database, reconstruction_id):
        start = int(source["output_offset"])
        if start >= parse_bytes:
            break
        length = min(int(source["byte_length"]), parse_bytes - start)
        with blob_path.open("rb") as stream:
            stream.seek(start)
            remaining = length
            while remaining:
                chunk = stream.read(min(remaining, PARSER_CHUNK_BYTES))
                if not chunk:
                    raise ValueError("short Telnet reconstruction source read")
                for item in parser.feed(chunk):
                    builder.add(item)
                remaining -= len(chunk)
        for item in parser.boundary():
            builder.add(item)
        builder.source_boundary()
    for item in parser.finish():
        builder.add(item)
    return builder.finish()


def _record_sources(
    sources: list[sqlite3.Row], start: int, end: int
) -> list[tuple[sqlite3.Row, int, int, int]]:
    result: list[tuple[sqlite3.Row, int, int, int]] = []
    for source in sources:
        source_start = int(source["output_offset"])
        source_end = source_start + int(source["byte_length"])
        overlap_start = max(start, source_start)
        overlap_end = min(end, source_end)
        if overlap_start < overlap_end:
            result.append(
                (source, overlap_start - start, overlap_start, overlap_end - overlap_start)
            )
    return result


def _prompt_label(data: bytes) -> Optional[str]:
    stripped = data.rstrip(b" \t")
    if not stripped.endswith(b":"):
        return None
    prefix = stripped[:-1].rstrip()
    token = prefix.rsplit(None, 1)[-1] if prefix else b""
    if not token or len(token) > 64 or any(value >= 128 for value in token):
        return None
    text = token.decode("ascii", errors="strict").lower()
    cleaned = "".join(character for character in text if character.isalnum() or character in "_-")
    return cleaned or None


def _persist_record(
    database: Database,
    project_root: Path,
    capture_sha256: str,
    dialogue_id: int,
    reconstruction: sqlite3.Row,
    role: str,
    item: _StoredRecord,
    sources: list[sqlite3.Row],
) -> int:
    public_id = stable_id(
        "telnet-record",
        {
            "reconstruction_id": reconstruction["reconstruction_id"],
            "stream_offset": item.start,
            "byte_length": item.end - item.start,
            "kind": item.kind,
            "parser_version": PARSER_VERSION,
        },
    )
    mappings = _record_sources(sources, item.start, item.end)
    if sum(mapping[3] for mapping in mappings) != item.end - item.start:
        raise ValueError("Telnet record lacks complete TCP source coverage")
    frame_start = min(int(mapping[0]["frame_number"]) for mapping in mappings)
    frame_end = max(int(mapping[0]["frame_number"]) for mapping in mappings)
    times = [float(mapping[0]["time_epoch"]) for mapping in mappings]
    semantic_label = item.semantic_label
    if semantic_label == "prompt":
        blob_path = project_root / reconstruction["relative_path"]
        with blob_path.open("rb") as stream:
            stream.seek(item.start)
            data = stream.read(item.end - item.start)
        prompt = _prompt_label(data)
        semantic_label = f"prompt:{prompt}" if prompt else "prompt"
    evidence_db_id = None
    if item.kind == "application":
        locator = EvidenceLocator(
            capture_sha256=capture_sha256,
            source_kind="telnet-record",
            frame_start=frame_start,
            frame_end=frame_end,
            protocol_message=f"{public_id}:{reconstruction['sha256']}",
            direction=reconstruction["direction"],
            byte_offset=item.start,
            byte_length=item.end - item.start,
        )
        evidence_public_id = evidence_id(locator)
        with database.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO evidence "
                "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,"
                "byte_offset,byte_length,blob_id,locator_json) VALUES "
                "(?,?,?,?,?,?,?,?,?,?)",
                (
                    evidence_public_id,
                    reconstruction["capture_id"],
                    "telnet-record",
                    frame_start,
                    frame_end,
                    reconstruction["direction"],
                    item.start,
                    item.end - item.start,
                    reconstruction["blob_id"],
                    json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
                ),
            )
            evidence_db_id = int(
                connection.execute(
                    "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public_id,)
                ).fetchone()[0]
            )
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO telnet_record "
            "(record_id,dialogue_id,reconstruction_id,evidence_id,direction_role,record_kind,"
            "stream_offset,byte_length,semantic_label,command,option_code,frame_start,frame_end,"
            "time_start,time_end,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(record_id) DO UPDATE SET dialogue_id=excluded.dialogue_id,"
            "evidence_id=excluded.evidence_id,direction_role=excluded.direction_role,"
            "semantic_label=excluded.semantic_label,command=excluded.command,"
            "option_code=excluded.option_code,frame_start=excluded.frame_start,"
            "frame_end=excluded.frame_end,time_start=excluded.time_start,time_end=excluded.time_end",
            (
                public_id,
                dialogue_id,
                reconstruction["id"],
                evidence_db_id,
                role,
                item.kind,
                item.start,
                item.end - item.start,
                semantic_label,
                item.command,
                item.option,
                frame_start,
                frame_end,
                min(times),
                max(times),
                _utc_now(),
            ),
        )
        record_id = int(
            connection.execute(
                "SELECT id FROM telnet_record WHERE record_id=?", (public_id,)
            ).fetchone()[0]
        )
        connection.execute("DELETE FROM telnet_record_source WHERE record_id=?", (record_id,))
        for source, record_offset, stream_offset, length in mappings:
            connection.execute(
                "INSERT INTO telnet_record_source "
                "(record_id,segment_id,record_offset,stream_offset,byte_length) "
                "VALUES (?,?,?,?,?)",
                (record_id, source["segment_id"], record_offset, stream_offset, length),
            )
    return record_id


def _current_reconstructions(database: Database, stream_index: int) -> list[sqlite3.Row]:
    with database.connect() as connection:
        return list(
            connection.execute(
                "SELECT tr.*,c.capture_id,c.conversation_id,c.endpoint_a,c.endpoint_b,"
                "e.blob_id,b.relative_path,b.sha256,b.byte_length FROM tcp_reconstruction tr "
                "JOIN conversation c ON c.id=tr.conversation_id "
                "LEFT JOIN evidence e ON e.id=tr.evidence_id "
                "LEFT JOIN blob b ON b.id=e.blob_id "
                "WHERE c.stream_index=? ORDER BY tr.direction",
                (stream_index,),
            ).fetchall()
        )


def _dialogue_status(reconstructions: list[sqlite3.Row], roles_resolved: bool) -> str:
    if not roles_resolved:
        return "unresolved-role"
    statuses = {str(row["status"]) for row in reconstructions}
    if len(reconstructions) != 2 or "partial" in statuses or "empty" in statuses:
        return "partial"
    if "truncated" in statuses:
        return "truncated"
    if "conflicting" in statuses:
        return "conflicting"
    return "complete"


def _create_dialogue(
    database: Database,
    capture_sha256: str,
    discovery: _StreamDiscovery,
    summary: Optional[TcpReconstructionSummary],
    reconstructions: list[sqlite3.Row],
    status: str,
    error: Optional[str] = None,
) -> int:
    public_id = stable_id(
        "telnet-dialogue",
        {"capture_sha256": capture_sha256, "stream_index": discovery.stream_index},
    )
    initiator = summary.initiator_endpoint if summary is not None else None
    responder = summary.responder_endpoint if summary is not None else None
    by_role: dict[str, int] = {}
    if initiator and responder:
        for row in reconstructions:
            direction = str(row["direction"])
            if direction.startswith(initiator + ">"):
                by_role["client"] = int(row["id"])
            elif direction.startswith(responder + ">"):
                by_role["server"] = int(row["id"])
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO telnet_dialogue "
            "(dialogue_id,capture_id,conversation_id,client_endpoint,server_endpoint,"
            "client_reconstruction_id,server_reconstruction_id,status,error,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(dialogue_id) DO UPDATE SET "
            "client_endpoint=excluded.client_endpoint,server_endpoint=excluded.server_endpoint,"
            "client_reconstruction_id=excluded.client_reconstruction_id,"
            "server_reconstruction_id=excluded.server_reconstruction_id,status=excluded.status,"
            "error=excluded.error,updated_at=excluded.updated_at",
            (
                public_id,
                discovery.capture_id,
                discovery.conversation_id,
                initiator,
                responder,
                by_role.get("client"),
                by_role.get("server"),
                status,
                error,
                _utc_now(),
            ),
        )
        return int(
            connection.execute(
                "SELECT id FROM telnet_dialogue WHERE dialogue_id=?", (public_id,)
            ).fetchone()[0]
        )


def _record_relations(database: Database, dialogue_id: int, project_root: Path) -> None:
    with database.connect() as connection:
        connection.execute(
            "DELETE FROM telnet_record_relation WHERE record_id IN "
            "(SELECT id FROM telnet_record WHERE dialogue_id=?)",
            (dialogue_id,),
        )
        rows = connection.execute(
            "SELECT tr.id,tr.direction_role,tr.semantic_label,tr.stream_offset,tr.byte_length,"
            "tr.frame_start,tr.time_start,b.relative_path FROM telnet_record tr "
            "LEFT JOIN evidence e ON e.id=tr.evidence_id LEFT JOIN blob b ON b.id=e.blob_id "
            "WHERE tr.dialogue_id=? AND tr.record_kind='application' "
            "ORDER BY tr.frame_start,tr.time_start,tr.direction_role,tr.stream_offset",
            (dialogue_id,),
        ).fetchall()
    pending_prompt: Optional[int] = None
    recent_client: list[tuple[int, bytes]] = []
    relations: list[tuple[int, int, str]] = []
    for row in rows:
        path = row["relative_path"]
        if path is None:
            continue
        with (project_root / path).open("rb") as stream:
            stream.seek(int(row["stream_offset"]))
            data = stream.read(int(row["byte_length"]))
        role = str(row["direction_role"])
        label = str(row["semantic_label"] or "")
        if role == "server" and label.startswith("prompt"):
            pending_prompt = int(row["id"])
        elif role == "client":
            if pending_prompt is not None and label == "line":
                relations.append((int(row["id"]), pending_prompt, "responds-to"))
                pending_prompt = None
            recent_client.append((int(row["id"]), data))
            recent_client = recent_client[-16:]
        elif role == "server":
            matched_echo = False
            for client_id, client_data in reversed(recent_client):
                if data == client_data:
                    relations.append((int(row["id"]), client_id, "echo-of"))
                    matched_echo = True
                    break
            if not matched_echo:
                pending_prompt = None
    with database.connect() as connection:
        connection.executemany(
            "INSERT OR IGNORE INTO telnet_record_relation "
            "(record_id,related_record_id,relation) VALUES (?,?,?)",
            relations,
        )


def index_telnet(
    project_path: Path,
    tshark: Path,
    *,
    max_metadata_frames: int = 100_000,
    max_streams: int = 10_000,
    max_records: int = 100_000,
    max_record_bytes: int = 1024 * 1024,
    max_index_payload_bytes: int = 512 * 1024 * 1024,
    max_direction_bytes: int = 256 * 1024 * 1024,
    max_total_bytes: int = 512 * 1024 * 1024,
    capabilities: Optional[TsharkCapabilities] = None,
) -> TelnetIndexSummary:
    if min(
        max_metadata_frames,
        max_streams,
        max_records,
        max_record_bytes,
        max_index_payload_bytes,
        max_direction_bytes,
        max_total_bytes,
    ) <= 0:
        raise ValueError("Telnet limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = capabilities or probe_tshark(tshark)
    tool_run_id, streams, metadata_skipped_streams, metadata_frames, skipped_frames = (
        _discover_streams(
        database,
        project.root,
        project.capture_path,
        project.capture_sha256,
        tshark,
        capabilities,
        max_metadata_frames=max_metadata_frames,
        )
    )
    remaining_total = max_total_bytes
    remaining_records = max_records
    total_records = parsed_bytes = skipped_bytes = 0
    for stream_ordinal, discovery in enumerate(streams):
        policy = json.dumps(
            {
                "max_direction_bytes": max_direction_bytes,
                "max_record_bytes": max_record_bytes,
                "max_records": max_records,
                "max_total_bytes": max_total_bytes,
                "parser_version": PARSER_VERSION,
            },
            sort_keys=True,
        )
        limit_reason = None
        if stream_ordinal >= max_streams:
            limit_reason = "stream-limit"
        elif discovery.stream_index in metadata_skipped_streams:
            limit_reason = "metadata-limit"
        if limit_reason is not None:
            summary = None
            error = None
            try:
                summary = reconstruct_tcp_stream(
                    project.root,
                    discovery.stream_index,
                    tshark,
                    max_index_payload_bytes=max_index_payload_bytes,
                    max_direction_bytes=max_direction_bytes,
                    max_total_output_bytes=min(max_total_bytes, max_direction_bytes * 2),
                    capabilities=capabilities,
                )
            except (OSError, TimeoutError, ValueError) as caught:
                error = str(caught)[:4096]
            reconstructions = _current_reconstructions(database, discovery.stream_index)
            skipped = sum(int(row["output_bytes"]) for row in reconstructions)
            dialogue_id = _create_dialogue(
                database,
                project.capture_sha256,
                discovery,
                summary,
                reconstructions,
                "failed" if error else "truncated",
                error,
            )
            with database.connect() as connection:
                connection.execute(
                    "INSERT INTO telnet_dialogue_run "
                    "(dialogue_id,tool_run_id,policy_json,status,record_count,parsed_bytes,"
                    "skipped_bytes,error,created_at) VALUES (?,?,?,?,0,0,?,?,?)",
                    (
                        dialogue_id,
                        tool_run_id,
                        policy,
                        "failed" if error else "truncated",
                        skipped,
                        error or f"{limit_reason} reached",
                        _utc_now(),
                    ),
                )
                run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
                connection.executemany(
                    "INSERT INTO telnet_parse_skip "
                    "(dialogue_run_id,reconstruction_id,stream_offset,byte_length,reason) "
                    "VALUES (?,?,0,?,?)",
                    (
                        (
                            run_id,
                            int(row["id"]),
                            int(row["output_bytes"]),
                            limit_reason,
                        )
                        for row in reconstructions
                    ),
                )
            skipped_bytes += skipped
            continue
        summary = None
        error = None
        try:
            summary = reconstruct_tcp_stream(
                project.root,
                discovery.stream_index,
                tshark,
                max_index_payload_bytes=max_index_payload_bytes,
                max_direction_bytes=max_direction_bytes,
                max_total_output_bytes=min(max_total_bytes, max_direction_bytes * 2),
                capabilities=capabilities,
            )
        except (OSError, TimeoutError, ValueError) as caught:
            error = str(caught)[:4096]
        reconstructions = _current_reconstructions(database, discovery.stream_index)
        roles_resolved = bool(
            summary and summary.initiator_endpoint and summary.responder_endpoint
        )
        status = "failed" if error else _dialogue_status(reconstructions, roles_resolved)
        dialogue_id = _create_dialogue(
            database,
            project.capture_sha256,
            discovery,
            summary,
            reconstructions,
            status,
            error,
        )
        with database.connect() as connection:
            connection.execute(
                "DELETE FROM telnet_record WHERE dialogue_id=?", (dialogue_id,)
            )
        run_record_count = run_parsed = run_skipped = 0
        skips: list[tuple[Optional[int], int, int, str]] = []
        if not error and roles_resolved:
            stream_remaining_total = remaining_total
            stream_remaining_records = remaining_records
            try:
                for reconstruction in reconstructions:
                    if reconstruction["relative_path"] is None:
                        length = int(reconstruction["output_bytes"])
                        skips.append(
                            (
                                int(reconstruction["id"]),
                                0,
                                length,
                                "reconstruction-unavailable",
                            )
                        )
                        run_skipped += length
                        continue
                    direction = str(reconstruction["direction"])
                    role = (
                        "client"
                        if direction.startswith(str(summary.initiator_endpoint) + ">")
                        else "server"
                    )
                    output_bytes = int(reconstruction["output_bytes"])
                    allowed = min(output_bytes, max_direction_bytes, remaining_total)
                    if allowed <= 0:
                        skips.append(
                            (
                                int(reconstruction["id"]),
                                0,
                                output_bytes,
                                "total-byte-budget",
                            )
                        )
                        run_skipped += output_bytes
                        continue
                    records = _parse_records(
                        database,
                        int(reconstruction["id"]),
                        project.root / reconstruction["relative_path"],
                        role,
                        allowed,
                        max_record_bytes,
                        remaining_records,
                    )
                    sources = _source_rows(database, int(reconstruction["id"]))
                    consumed = 0
                    for item in records:
                        _persist_record(
                            database,
                            project.root,
                            project.capture_sha256,
                            dialogue_id,
                            reconstruction,
                            role,
                            item,
                            sources,
                        )
                        consumed = item.end
                        remaining_records -= 1
                        run_record_count += 1
                    if consumed < allowed:
                        skips.append(
                            (
                                int(reconstruction["id"]),
                                consumed,
                                output_bytes - consumed,
                                "record-limit",
                            )
                        )
                        run_skipped += output_bytes - consumed
                    elif allowed < output_bytes:
                        reason = (
                            "direction-byte-budget"
                            if max_direction_bytes < output_bytes
                            else "total-byte-budget"
                        )
                        skips.append(
                            (int(reconstruction["id"]), allowed, output_bytes - allowed, reason)
                        )
                        run_skipped += output_bytes - allowed
                    run_parsed += consumed
                    remaining_total -= consumed
                _record_relations(database, dialogue_id, project.root)
            except (OSError, ValueError, sqlite3.Error) as caught:
                error = str(caught)[:4096]
                status = "failed"
                remaining_total = stream_remaining_total
                remaining_records = stream_remaining_records
                run_record_count = run_parsed = 0
                skips = []
                run_skipped = sum(int(row["output_bytes"]) for row in reconstructions)
                with database.connect() as connection:
                    connection.execute(
                        "DELETE FROM telnet_record WHERE dialogue_id=?", (dialogue_id,)
                    )
                    connection.execute(
                        "UPDATE telnet_dialogue SET status='failed',error=?,updated_at=? "
                        "WHERE id=?",
                        (error, _utc_now(), dialogue_id),
                    )
                skips.extend(
                    (
                        int(row["id"]),
                        0,
                        int(row["output_bytes"]),
                        "reconstruction-unavailable",
                    )
                    for row in reconstructions
                )
        elif reconstructions:
            for reconstruction in reconstructions:
                length = int(reconstruction["output_bytes"])
                skips.append((int(reconstruction["id"]), 0, length, "reconstruction-unavailable"))
                run_skipped += length
        run_status = "failed" if error else ("truncated" if skips else "completed")
        with database.connect() as connection:
            if skips and not error and status not in ("unresolved-role", "failed"):
                connection.execute(
                    "UPDATE telnet_dialogue SET status='truncated',updated_at=? WHERE id=?",
                    (_utc_now(), dialogue_id),
                )
            connection.execute(
                "INSERT INTO telnet_dialogue_run "
                "(dialogue_id,tool_run_id,policy_json,status,record_count,parsed_bytes,"
                "skipped_bytes,error,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    dialogue_id,
                    tool_run_id,
                    policy,
                    run_status,
                    run_record_count,
                    run_parsed,
                    run_skipped,
                    error,
                    _utc_now(),
                ),
            )
            run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.executemany(
                "INSERT INTO telnet_parse_skip "
                "(dialogue_run_id,reconstruction_id,stream_offset,byte_length,reason) "
                "VALUES (?,?,?,?,?)",
                ((run_id, *skip) for skip in skips),
            )
        total_records += run_record_count
        parsed_bytes += run_parsed
        skipped_bytes += run_skipped
    with database.connect() as connection:
        statuses = {
            str(row[0]): int(row[1])
            for row in connection.execute(
                "SELECT status,count(*) FROM telnet_dialogue GROUP BY status"
            )
        }
    return TelnetIndexSummary(
        schema_version="auto-shark.telnet-index/v1",
        project=str(project.root),
        metadata_frames=metadata_frames,
        skipped_metadata_frames=skipped_frames,
        streams=len(streams),
        complete=statuses.get("complete", 0),
        partial=statuses.get("partial", 0),
        conflicting=statuses.get("conflicting", 0),
        truncated=statuses.get("truncated", 0),
        unresolved_role=statuses.get("unresolved-role", 0),
        failed=statuses.get("failed", 0),
        records=total_records,
        parsed_bytes=parsed_bytes,
        skipped_bytes=skipped_bytes,
    )
