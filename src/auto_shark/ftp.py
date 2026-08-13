"""Persist structured FTP metadata and explicit data-transfer correlations."""

from __future__ import annotations

import json
import re
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
from .protocols.ftp import (
    FTP_REQUIRED_FIELDS,
    FtpPacket,
    parse_ftp_line,
    selected_ftp_fields,
    tshark_ftp_arguments,
)
from .storage import Database
from .tcp import reconstruct_tcp_stream


@dataclass(frozen=True)
class FtpMetadataSummary:
    schema_version: str
    project: str
    messages: int
    requests: int
    responses: int
    data_messages: int
    skipped_messages: int
    transfers: int
    indexed_transfers: int
    unresolved_transfers: int
    skipped_transfers: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass(frozen=True)
class FtpIndexSummary:
    schema_version: str
    project: str
    messages: int
    skipped_messages: int
    transfers: int
    complete: int
    unresolved: int
    skipped_limit: int
    skipped_budget: int
    partial: int
    conflicting: int
    truncated: int
    empty: int
    failed: int
    output_bytes: int
    artifacts: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_context(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    capture_sha256: str,
    packet: FtpPacket,
) -> tuple[int, int, str]:
    connection.execute(
        "INSERT OR IGNORE INTO frame "
        "(capture_id,frame_number,time_epoch,captured_length,original_length) "
        "VALUES (?,?,?,?,?)",
        (
            capture_id,
            packet.frame_number,
            packet.time_epoch,
            packet.captured_length,
            packet.frame_length,
        ),
    )
    conversation_public_id = stable_id(
        "conversation",
        {
            "capture_sha256": capture_sha256,
            "protocol": "tcp",
            "stream_index": packet.tcp_stream,
        },
    )
    connection.execute(
        "INSERT OR IGNORE INTO conversation "
        "(conversation_id,capture_id,protocol,stream_index,endpoint_a,endpoint_b) "
        "VALUES (?,?,'tcp',?,?,?)",
        (
            conversation_public_id,
            capture_id,
            packet.tcp_stream,
            f"{packet.source}:{packet.source_port}",
            f"{packet.destination}:{packet.destination_port}",
        ),
    )
    conversation_id = int(
        connection.execute(
            "SELECT id FROM conversation WHERE conversation_id=?", (conversation_public_id,)
        ).fetchone()[0]
    )
    protocol = "ftp-data" if packet.kind == "data" else "ftp"
    message_public_id = stable_id(
        "protocol-message",
        {
            "capture_sha256": capture_sha256,
            "protocol": protocol,
            "frame_number": packet.frame_number,
            "kind": packet.kind,
        },
    )
    connection.execute(
        "INSERT OR IGNORE INTO protocol_message "
        "(message_id,capture_id,conversation_id,representative_frame,protocol,direction,"
        "message_kind,fields_json) VALUES (?,?,?,?,?,?,?,?)",
        (
            message_public_id,
            capture_id,
            conversation_id,
            packet.frame_number,
            protocol,
            packet.direction,
            packet.kind,
            json.dumps(packet.fields(), ensure_ascii=False, sort_keys=True),
        ),
    )
    message_id = int(
        connection.execute(
            "SELECT id FROM protocol_message WHERE message_id=?", (message_public_id,)
        ).fetchone()[0]
    )
    return conversation_id, message_id, message_public_id


def _record_packet(
    database: Database,
    *,
    capture_id: int,
    capture_sha256: str,
    tool_run_id: int,
    packet: FtpPacket,
) -> None:
    with database.connect() as connection:
        _, message_id, _ = _ensure_context(
            connection,
            capture_id=capture_id,
            capture_sha256=capture_sha256,
            packet=packet,
        )
        if packet.kind == "data":
            connection.execute(
                "INSERT INTO ftp_data_message "
                "(protocol_message_id,setup_frame,setup_method,command_frame,command,"
                "payload_length) VALUES (?,?,?,?,?,?) ON CONFLICT(protocol_message_id) "
                "DO UPDATE SET setup_frame=excluded.setup_frame,"
                "setup_method=excluded.setup_method,command_frame=excluded.command_frame,"
                "command=excluded.command,payload_length=excluded.payload_length",
                (
                    message_id,
                    packet.setup_frame,
                    packet.setup_method,
                    packet.command_frame,
                    packet.data_command,
                    packet.payload_length,
                ),
            )
        else:
            connection.execute(
                "INSERT INTO ftp_message "
                "(protocol_message_id,request_command,request_argument,response_code,"
                "response_argument,passive_ip,passive_port) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(protocol_message_id) DO UPDATE SET "
                "request_command=excluded.request_command,"
                "request_argument=excluded.request_argument,"
                "response_code=excluded.response_code,"
                "response_argument=excluded.response_argument,"
                "passive_ip=excluded.passive_ip,passive_port=excluded.passive_port",
                (
                    message_id,
                    packet.request_command,
                    packet.request_argument,
                    packet.response_code,
                    packet.response_argument,
                    packet.passive_ip,
                    packet.passive_port,
                ),
            )
        connection.execute(
            "INSERT OR IGNORE INTO ftp_message_run (protocol_message_id,tool_run_id) VALUES (?,?)",
            (message_id, tool_run_id),
        )


def _record_skip(
    database: Database,
    *,
    capture_id: int,
    capture_sha256: str,
    tool_run_id: int,
    packet: FtpPacket,
) -> None:
    with database.connect() as connection:
        _ensure_context(
            connection,
            capture_id=capture_id,
            capture_sha256=capture_sha256,
            packet=packet,
        )
        connection.execute(
            "INSERT OR IGNORE INTO ftp_metadata_skip "
            "(tool_run_id,capture_id,frame_number,protocol,reason) "
            "VALUES (?,?,?,?,'message-limit')",
            (
                tool_run_id,
                capture_id,
                packet.frame_number,
                "ftp-data" if packet.kind == "data" else "ftp",
            ),
        )


def _message_at_frame(
    connection: sqlite3.Connection,
    capture_id: int,
    frame: Optional[int],
    protocol: str,
) -> Optional[int]:
    if frame is None:
        return None
    row = connection.execute(
        "SELECT id FROM protocol_message WHERE capture_id=? AND representative_frame=? "
        "AND protocol=? ORDER BY id LIMIT 1",
        (capture_id, frame, protocol),
    ).fetchone()
    return int(row[0]) if row is not None else None


def _suggested_name(argument: Optional[str]) -> Optional[str]:
    if not argument:
        return None
    basename = argument.replace("\\", "/").split("/")[-1]
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "_", basename).strip(" .")
    return cleaned[:255] or None


def _magic(path: Path) -> tuple[Optional[str], Optional[str]]:
    with path.open("rb") as stream:
        prefix = stream.read(8)
    if prefix.startswith(b"Rar!\x1a\x07\x00"):
        return "application/vnd.rar", "rar4"
    if prefix.startswith(b"Rar!\x1a\x07\x01\x00"):
        return "application/vnd.rar", "rar5"
    return None, None


def _correlate_transfers(
    database: Database,
    *,
    capture_id: int,
    capture_sha256: str,
    tool_run_id: int,
    max_transfers: int,
    max_output_bytes: int,
) -> tuple[int, int, int, int]:
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT pm.id data_message_id,pm.message_id,pm.representative_frame,"
            "pm.direction,c.stream_index,fdm.setup_frame,fdm.setup_method,"
            "fdm.command_frame,fdm.command FROM ftp_data_message fdm "
            "JOIN protocol_message pm ON pm.id=fdm.protocol_message_id "
            "JOIN conversation c ON c.id=pm.conversation_id "
            "JOIN ftp_message_run fmr ON fmr.protocol_message_id=pm.id "
            "WHERE fmr.tool_run_id=? ORDER BY pm.representative_frame,pm.message_id",
            (tool_run_id,),
        ).fetchall()
        groups: dict[tuple[object, ...], list[sqlite3.Row]] = {}
        for row in rows:
            unresolved_frame = (
                row["representative_frame"]
                if row["setup_frame"] is None or row["command_frame"] is None
                else None
            )
            key = (
                row["setup_frame"],
                row["command_frame"],
                row["stream_index"],
                row["direction"],
                unresolved_frame,
            )
            groups.setdefault(key, []).append(row)
        indexed = unresolved = skipped = 0
        for index, (key, messages) in enumerate(groups.items()):
            setup_frame, command_frame, stream_index, direction, unresolved_frame = key
            first = messages[0]
            setup_id = _message_at_frame(connection, capture_id, setup_frame, "ftp")
            command_id = _message_at_frame(connection, capture_id, command_frame, "ftp")
            command = None
            argument = None
            if command_id is not None:
                command_row = connection.execute(
                    "SELECT request_command,request_argument FROM ftp_message "
                    "WHERE protocol_message_id=?",
                    (command_id,),
                ).fetchone()
                if command_row is not None:
                    command = command_row["request_command"]
                    argument = command_row["request_argument"]
            status = "indexed"
            if setup_id is None or command_id is None:
                status = "unresolved"
                unresolved += 1
            elif index >= max_transfers:
                status = "skipped-limit"
                skipped += 1
            else:
                indexed += 1
            transfer_locator = {
                "capture_sha256": capture_sha256,
                "command_frame": command_frame,
                "data_stream_index": stream_index,
                "direction": direction,
                "setup_frame": setup_frame,
            }
            if unresolved_frame is not None:
                transfer_locator["unresolved_data_frame"] = unresolved_frame
            transfer_public_id = stable_id("ftp-transfer", transfer_locator)
            connection.execute(
                "INSERT INTO ftp_transfer "
                "(transfer_id,capture_id,setup_message_id,command_message_id,"
                "metadata_tool_run_id,data_stream_index,direction,command,argument,"
                "suggested_name,max_output_bytes,status,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(transfer_id) DO UPDATE SET "
                "setup_message_id=excluded.setup_message_id,"
                "command_message_id=excluded.command_message_id,"
                "metadata_tool_run_id=excluded.metadata_tool_run_id,"
                "command=excluded.command,argument=excluded.argument,"
                "suggested_name=excluded.suggested_name,"
                "max_output_bytes=excluded.max_output_bytes,status=excluded.status,"
                "reconstruction_id=NULL,evidence_id=NULL,artifact_id=NULL,output_bytes=0,"
                "error=NULL,updated_at=excluded.updated_at",
                (
                    transfer_public_id,
                    capture_id,
                    setup_id,
                    command_id,
                    tool_run_id,
                    stream_index,
                    direction,
                    command or first["command"],
                    argument,
                    _suggested_name(argument),
                    max_output_bytes,
                    status,
                    _utc_now(),
                ),
            )
            transfer_id = int(
                connection.execute(
                    "SELECT id FROM ftp_transfer WHERE transfer_id=?", (transfer_public_id,)
                ).fetchone()[0]
            )
            connection.execute(
                "DELETE FROM ftp_transfer_message WHERE transfer_id=?", (transfer_id,)
            )
            for ordinal, message in enumerate(messages):
                connection.execute(
                    "INSERT INTO ftp_transfer_message "
                    "(transfer_id,data_message_id,ordinal) VALUES (?,?,?)",
                    (transfer_id, message["data_message_id"], ordinal),
                )
    return len(groups), indexed, unresolved, skipped


def index_ftp_metadata(
    project_path: Path,
    tshark: Path,
    *,
    max_messages: int = 100_000,
    max_transfers: int = 10_000,
    max_output_bytes: int = 256 * 1024 * 1024,
    capabilities: Optional[TsharkCapabilities] = None,
) -> FtpMetadataSummary:
    if min(max_messages, max_transfers, max_output_bytes) <= 0:
        raise ValueError("FTP limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = capabilities or probe_tshark(tshark)
    available_fields = set(capabilities.fields)
    missing = sorted(set(FTP_REQUIRED_FIELDS) - available_fields)
    ipv4 = {"ip.src", "ip.dst"}.issubset(available_fields)
    ipv6 = {"ipv6.src", "ipv6.dst"}.issubset(available_fields)
    if not capabilities.usable or missing or not (ipv4 or ipv6):
        if not (ipv4 or ipv6):
            missing.append("ip.src/ip.dst or ipv6.src/ipv6.dst")
        raise ValueError(f"TShark lacks required FTP fields: {', '.join(missing)}")
    argv = tshark_ftp_arguments(tshark, project.capture_path, available_fields=available_fields)
    parsed_fields = selected_ftp_fields(available_fields)
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
                capabilities.to_json(),
                _utc_now(),
            ),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
    messages = skipped_messages = requests = responses = data_messages = 0
    result = None
    run_status = "failed"
    exit_code = None
    stderr_text = "FTP metadata indexing failed; see caller error"
    stderr_truncated = 0
    try:

        def consume(line: bytes) -> None:
            nonlocal messages, skipped_messages, requests, responses, data_messages
            packet = parse_ftp_line(line, parsed_fields)
            if messages >= max_messages:
                _record_skip(
                    database,
                    capture_id=capture_id,
                    capture_sha256=project.capture_sha256,
                    tool_run_id=tool_run_id,
                    packet=packet,
                )
                skipped_messages += 1
                return
            _record_packet(
                database,
                capture_id=capture_id,
                capture_sha256=project.capture_sha256,
                tool_run_id=tool_run_id,
                packet=packet,
            )
            messages += 1
            requests += int(packet.kind == "request")
            responses += int(packet.kind == "response")
            data_messages += int(packet.kind == "data")

        result = run_streaming_lines(
            argv,
            consume,
            timeout_seconds=300,
            max_line_bytes=1024 * 1024,
            stderr_limit=512 * 1024,
        )
        if result.timed_out:
            raise TimeoutError("TShark FTP metadata extraction timed out")
        if result.output_limit_exceeded:
            raise ValueError("TShark emitted an FTP metadata line above the configured limit")
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"TShark FTP extraction exited {result.returncode}: {detail[:500]}")
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
    transfers, indexed, unresolved, skipped_transfers = _correlate_transfers(
        database,
        capture_id=capture_id,
        capture_sha256=project.capture_sha256,
        tool_run_id=tool_run_id,
        max_transfers=max_transfers,
        max_output_bytes=max_output_bytes,
    )
    return FtpMetadataSummary(
        schema_version="auto-shark.ftp-metadata/v1",
        project=str(project.root),
        messages=messages,
        requests=requests,
        responses=responses,
        data_messages=data_messages,
        skipped_messages=skipped_messages,
        transfers=transfers,
        indexed_transfers=indexed,
        unresolved_transfers=unresolved,
        skipped_transfers=skipped_transfers,
    )


def _transfer_rows(database: Database) -> list[sqlite3.Row]:
    with database.connect() as connection:
        return list(
            connection.execute(
                "SELECT ft.id,ft.transfer_id,ft.status,ft.data_stream_index,ft.direction,"
                "ft.suggested_name,ft.max_output_bytes,pm.representative_frame,"
                "coalesce(sum(fdm.payload_length),0) expected_bytes "
                "FROM ftp_transfer ft JOIN ftp_transfer_message ftm ON ftm.transfer_id=ft.id "
                "JOIN protocol_message pm ON pm.id=ftm.data_message_id "
                "JOIN ftp_data_message fdm ON fdm.protocol_message_id=pm.id "
                "GROUP BY ft.id ORDER BY min(pm.representative_frame),ft.transfer_id"
            ).fetchall()
        )


def _current_reconstruction(
    database: Database, stream_index: int, direction: str
) -> Optional[sqlite3.Row]:
    with database.connect() as connection:
        return connection.execute(
            "SELECT tr.id reconstruction_id,tr.status,tr.output_bytes,tr.duplicate_bytes,"
            "tr.conflict_bytes,tr.gap_bytes,tr.capture_midstream,tr.evidence_id,"
            "e.evidence_id evidence_public_id,e.capture_id,e.frame_start,e.frame_end,e.blob_id,"
            "b.sha256,b.byte_length,b.relative_path FROM tcp_reconstruction tr "
            "JOIN conversation c ON c.id=tr.conversation_id "
            "LEFT JOIN evidence e ON e.id=tr.evidence_id LEFT JOIN blob b ON b.id=e.blob_id "
            "WHERE c.protocol='tcp' AND c.stream_index=? AND tr.direction=?",
            (stream_index, direction),
        ).fetchone()


def _transfer_covers_reconstruction(
    database: Database, transfer_id: int, reconstruction_id: int, output_bytes: int
) -> bool:
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT trs.output_offset,trs.byte_length FROM ftp_transfer_message ftm "
            "JOIN protocol_message pm ON pm.id=ftm.data_message_id "
            "JOIN tcp_reconstruction tr ON tr.id=? "
            "JOIN tcp_segment ts ON ts.frame_number=pm.representative_frame "
            "AND ts.capture_id=pm.capture_id AND ts.conversation_id=tr.conversation_id "
            "JOIN tcp_reconstruction_source trs ON trs.segment_id=ts.id "
            "WHERE ftm.transfer_id=? AND trs.reconstruction_id=? AND trs.role='primary' "
            "ORDER BY trs.output_offset",
            (reconstruction_id, transfer_id, reconstruction_id),
        ).fetchall()
    cursor = 0
    for row in rows:
        offset = int(row["output_offset"])
        length = int(row["byte_length"])
        if offset > cursor:
            return False
        cursor = max(cursor, offset + length)
    return cursor == output_bytes


def _persist_transfer_result(
    database: Database,
    project_root: Path,
    capture_sha256: str,
    transfer: sqlite3.Row,
    reconstruction: sqlite3.Row,
) -> None:
    output_bytes = int(reconstruction["output_bytes"])
    frames: list[int]
    with database.connect() as connection:
        frames = [
            int(row[0])
            for row in connection.execute(
                "SELECT pm.representative_frame FROM ftp_transfer_message ftm "
                "JOIN protocol_message pm ON pm.id=ftm.data_message_id "
                "WHERE ftm.transfer_id=? ORDER BY ftm.ordinal",
                (transfer["id"],),
            )
        ]
    locator = EvidenceLocator(
        capture_sha256=capture_sha256,
        source_kind="ftp-data",
        frame_start=min(frames),
        frame_end=max(frames),
        protocol_message=str(transfer["transfer_id"]),
        direction=str(transfer["direction"]),
        byte_offset=0,
        byte_length=output_bytes,
    )
    public_evidence_id = evidence_id(locator)
    path = project_root / str(reconstruction["relative_path"])
    media_type, magic_description = _magic(path)
    artifact_public_id = stable_id("artifact", {"sha256": reconstruction["sha256"]})
    with database.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO evidence "
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,"
            "byte_offset,byte_length,blob_id,locator_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                public_evidence_id,
                reconstruction["capture_id"],
                "ftp-data",
                min(frames),
                max(frames),
                transfer["direction"],
                0,
                output_bytes,
                reconstruction["blob_id"],
                json.dumps(locator.payload(), ensure_ascii=False, sort_keys=True),
            ),
        )
        evidence_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?", (public_evidence_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "UPDATE blob SET media_type=coalesce(media_type,?),"
            "magic_description=coalesce(magic_description,?) WHERE id=?",
            (media_type, magic_description, reconstruction["blob_id"]),
        )
        connection.execute(
            "INSERT OR IGNORE INTO artifact "
            "(artifact_id,blob_id,source_evidence_id,suggested_name,detected_media_type,"
            "review_state,created_at) VALUES (?,?,?,?,?,'unreviewed',?)",
            (
                artifact_public_id,
                reconstruction["blob_id"],
                evidence_db_id,
                transfer["suggested_name"],
                media_type,
                _utc_now(),
            ),
        )
        artifact_id = int(
            connection.execute(
                "SELECT id FROM artifact WHERE artifact_id=?", (artifact_public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO artifact_evidence (artifact_id,evidence_id,role) "
            "VALUES (?,?,'transferred-as')",
            (artifact_id, evidence_db_id),
        )
        connection.execute(
            "UPDATE ftp_transfer SET reconstruction_id=?,evidence_id=?,artifact_id=?,"
            "output_bytes=?,status='complete',error=NULL,updated_at=? WHERE id=?",
            (
                reconstruction["reconstruction_id"],
                evidence_db_id,
                artifact_id,
                output_bytes,
                _utc_now(),
                transfer["id"],
            ),
        )


def index_ftp(
    project_path: Path,
    tshark: Path,
    *,
    max_messages: int = 100_000,
    max_transfers: int = 10_000,
    max_index_payload_bytes: int = 512 * 1024 * 1024,
    max_transfer_bytes: int = 256 * 1024 * 1024,
    max_total_output_bytes: int = 512 * 1024 * 1024,
    capabilities: Optional[TsharkCapabilities] = None,
) -> FtpIndexSummary:
    if (
        min(
            max_messages,
            max_transfers,
            max_index_payload_bytes,
            max_transfer_bytes,
            max_total_output_bytes,
        )
        <= 0
    ):
        raise ValueError("FTP limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = capabilities or probe_tshark(tshark)
    metadata = index_ftp_metadata(
        project.root,
        tshark,
        max_messages=max_messages,
        max_transfers=max_transfers,
        max_output_bytes=max_transfer_bytes,
        capabilities=capabilities,
    )
    rows = _transfer_rows(database)
    eligible: list[sqlite3.Row] = []
    remaining_total = max_total_output_bytes
    for row in rows:
        if row["status"] != "indexed":
            continue
        expected = int(row["expected_bytes"])
        if expected > max_transfer_bytes or expected > remaining_total:
            with database.connect() as connection:
                connection.execute(
                    "UPDATE ftp_transfer SET status='skipped-budget',error=?,updated_at=? "
                    "WHERE id=?",
                    ("declared FTP-DATA payload exceeds output budget", _utc_now(), row["id"]),
                )
            continue
        eligible.append(row)
        remaining_total -= expected
    stream_errors: dict[int, str] = {}
    for stream_index in sorted({int(row["data_stream_index"]) for row in eligible}):
        try:
            reconstruct_tcp_stream(
                project.root,
                stream_index,
                tshark,
                max_index_payload_bytes=max_index_payload_bytes,
                max_direction_bytes=max_transfer_bytes,
                max_total_output_bytes=max_transfer_bytes,
                capabilities=capabilities,
            )
        except (OSError, TimeoutError, ValueError) as error:
            stream_errors[stream_index] = str(error)[:4096]
    for transfer in eligible:
        stream_index = int(transfer["data_stream_index"])
        if stream_index in stream_errors:
            with database.connect() as connection:
                connection.execute(
                    "UPDATE ftp_transfer SET reconstruction_id=NULL,evidence_id=NULL,"
                    "artifact_id=NULL,output_bytes=0,status='failed',error=?,updated_at=? "
                    "WHERE id=?",
                    (stream_errors[stream_index], _utc_now(), transfer["id"]),
                )
            continue
        reconstruction = _current_reconstruction(database, stream_index, str(transfer["direction"]))
        status = "failed"
        error = "expected FTP data direction was not reconstructed"
        if reconstruction is not None:
            status = str(reconstruction["status"])
            error = None
            if status == "complete" and not _transfer_covers_reconstruction(
                database,
                int(transfer["id"]),
                int(reconstruction["reconstruction_id"]),
                int(reconstruction["output_bytes"]),
            ):
                status = "partial"
                error = "FTP-DATA frames do not cover the complete reconstructed direction"
            if status == "complete":
                _persist_transfer_result(
                    database, project.root, project.capture_sha256, transfer, reconstruction
                )
                continue
        with database.connect() as connection:
            connection.execute(
                "UPDATE ftp_transfer SET reconstruction_id=?,evidence_id=NULL,artifact_id=NULL,"
                "output_bytes=?,status=?,error=?,updated_at=? WHERE id=?",
                (
                    reconstruction["reconstruction_id"] if reconstruction is not None else None,
                    reconstruction["output_bytes"] if reconstruction is not None else 0,
                    status,
                    error,
                    _utc_now(),
                    transfer["id"],
                ),
            )
    with database.connect() as connection:
        statuses = {
            str(row[0]): int(row[1])
            for row in connection.execute(
                "SELECT status,count(*) FROM ftp_transfer GROUP BY status"
            )
        }
        output_bytes = int(
            connection.execute("SELECT coalesce(sum(output_bytes),0) FROM ftp_transfer").fetchone()[
                0
            ]
        )
        artifacts = int(
            connection.execute(
                "SELECT count(*) FROM ftp_transfer WHERE status='complete' "
                "AND artifact_id IS NOT NULL"
            ).fetchone()[0]
        )
    return FtpIndexSummary(
        schema_version="auto-shark.ftp-index/v1",
        project=str(project.root),
        messages=metadata.messages,
        skipped_messages=metadata.skipped_messages,
        transfers=len(rows),
        complete=statuses.get("complete", 0),
        unresolved=statuses.get("unresolved", 0),
        skipped_limit=statuses.get("skipped-limit", 0),
        skipped_budget=statuses.get("skipped-budget", 0),
        partial=statuses.get("partial", 0),
        conflicting=statuses.get("conflicting", 0),
        truncated=statuses.get("truncated", 0),
        empty=statuses.get("empty", 0),
        failed=statuses.get("failed", 0),
        output_bytes=output_bytes,
        artifacts=artifacts,
    )
