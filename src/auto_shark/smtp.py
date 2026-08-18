"""Bounded SMTP DATA reconstruction and MIME attachment recovery."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from io import StringIO
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import TsharkCapabilities, probe_tshark
from .project import inspect_project
from .storage import BlobStore, Database
from .tcp import reconstruct_tcp_stream

SMTP_REQUIRED_FIELDS = frozenset(
    {
        "frame.number",
        "tcp.stream",
        "tcp.srcport",
        "tcp.dstport",
        "smtp.req.command",
        "smtp.data.reassembled.length",
    }
)
SMTP_FIELDS = (
    "frame.number",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "smtp.req.command",
    "smtp.data.reassembled.length",
)
PARSER_VERSION = "auto-shark.smtp-mime/v1"
_DATA_LINE = re.compile(rb"(?i)(?:^|\r\n)DATA\r\n")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded_text(value: Optional[str], limit: int = 4096) -> Optional[str]:
    if value is None:
        return None
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", errors="ignore")


def _safe_name(value: Optional[str], data_frame: int, ordinal: int) -> str:
    name = (value or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL.sub("_", name).strip().strip(".")
    return name[:240] or f"smtp-{data_frame}-part-{ordinal}.bin"


@dataclass(frozen=True)
class SmtpDiscovery:
    stream: int
    direction: str
    data_frame: int
    final_frame: int
    declared_length: int


@dataclass(frozen=True)
class SmtpAttachmentResult:
    attachment_id: str
    ordinal: int
    filename: str
    media_type: str
    transfer_encoding: str
    status: str
    source_offset: Optional[int]
    source_length: Optional[int]
    decoded_length: int
    sha256: Optional[str]
    evidence_id: Optional[str]
    artifact_id: Optional[str]
    error: Optional[str]


@dataclass(frozen=True)
class SmtpMessageResult:
    message_id: str
    stream: int
    direction: str
    data_frame: int
    final_frame: int
    declared_length: int
    status: str
    source_offset: Optional[int]
    source_length: Optional[int]
    sha256: Optional[str]
    subject: Optional[str]
    evidence_id: Optional[str]
    attachments: tuple[SmtpAttachmentResult, ...]
    error: Optional[str]


@dataclass(frozen=True)
class SmtpSummary:
    schema_version: str
    project: str
    status: str
    discovery_rows: int
    malformed_rows: int
    unmatched_data: int
    skipped_stream_limit: int
    skipped_message_limit: int
    skipped_message_budget: int
    skipped_attachment_limit: int
    skipped_attachment_budget: int
    messages: tuple[SmtpMessageResult, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def selected_smtp_fields(available_fields: set[str]) -> tuple[str, ...]:
    return tuple(
        name for name in SMTP_FIELDS if name in SMTP_REQUIRED_FIELDS or name in available_fields
    )


def tshark_smtp_arguments(
    executable: Path, capture: Path, *, available_fields: set[str]
) -> list[str]:
    arguments = [
        str(executable),
        "-2",
        "-r",
        str(capture),
        "-Y",
        'smtp.req.command == "DATA" || smtp.data.reassembled.length',
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=|",
    ]
    for name in selected_smtp_fields(available_fields):
        arguments.extend(("-e", name))
    return arguments


def parse_smtp_line(line: bytes, fields: tuple[str, ...]) -> dict[str, object]:
    rows = list(
        csv.reader(
            StringIO(line.decode("utf-8", errors="strict")),
            delimiter="\t",
            quotechar='"',
            strict=True,
        )
    )
    if len(rows) != 1 or len(rows[0]) != len(fields):
        actual = len(rows[0]) if rows else 0
        raise ValueError(f"expected {len(fields)} SMTP columns, received {actual}")
    values = dict(zip(fields, rows[0]))
    source = values.get("ip.src", "") or values.get("ipv6.src", "")
    destination = values.get("ip.dst", "") or values.get("ipv6.dst", "")
    if not source or not destination:
        raise ValueError("SMTP row lacks source or destination address")
    return {
        "frame": int(values["frame.number"]),
        "stream": int(values["tcp.stream"]),
        "direction": (
            f"{source}:{int(values['tcp.srcport'])}>{destination}:{int(values['tcp.dstport'])}"
        ),
        "commands": tuple(item.upper() for item in values["smtp.req.command"].split("|") if item),
        "reassembled_length": (
            int(values["smtp.data.reassembled.length"])
            if values["smtp.data.reassembled.length"]
            else None
        ),
    }


class _DiscoveryCollector:
    def __init__(self, max_streams: int, max_messages: int) -> None:
        self.max_streams = max_streams
        self.max_messages = max_messages
        self.rows = 0
        self.malformed = 0
        self.skipped_stream_limit = 0
        self.skipped_message_limit = 0
        self.unmatched = 0
        self.incomplete: list[tuple[int, int, str]] = []
        self.streams: set[int] = set()
        self.pending: dict[int, deque[tuple[int, str]]] = defaultdict(deque)
        self.ignored_pending: dict[int, int] = defaultdict(int)
        self.discoveries: list[SmtpDiscovery] = []

    def add(self, line: bytes, fields: tuple[str, ...]) -> None:
        self.rows += 1
        try:
            row = parse_smtp_line(line, fields)
        except (UnicodeError, ValueError):
            self.malformed += 1
            return
        stream = int(row["stream"])
        if "DATA" in row["commands"]:
            if stream not in self.streams and len(self.streams) >= self.max_streams:
                self.skipped_stream_limit += 1
                self.ignored_pending[stream] += 1
                return
            if len(self.discoveries) + sum(map(len, self.pending.values())) >= self.max_messages:
                self.skipped_message_limit += 1
                self.ignored_pending[stream] += 1
                return
            self.streams.add(stream)
            self.pending[stream].append((int(row["frame"]), str(row["direction"])))
        length = row["reassembled_length"]
        if length is None:
            return
        if self.pending[stream]:
            data_frame, direction = self.pending[stream].popleft()
            self.discoveries.append(
                SmtpDiscovery(
                    stream,
                    direction,
                    data_frame,
                    int(row["frame"]),
                    int(length),
                )
            )
        elif self.ignored_pending[stream]:
            self.ignored_pending[stream] -= 1
        else:
            self.unmatched += 1

    def finish(self) -> None:
        for stream, pending in self.pending.items():
            self.incomplete.extend(
                (stream, data_frame, direction) for data_frame, direction in pending
            )
        self.unmatched += len(self.incomplete)


def extract_smtp_data(stream: bytes, count: int) -> tuple[tuple[int, bytes], ...]:
    """Return stream offsets and exact on-wire EML bytes for sequential DATA commands."""
    results: list[tuple[int, bytes]] = []
    cursor = 0
    for match in _DATA_LINE.finditer(stream):
        command_end = match.end()
        if command_end <= cursor:
            continue
        start = command_end
        marker = stream.find(b"\r\n.\r\n", start)
        if marker < 0:
            break
        results.append((start, stream[start : marker + 2]))
        cursor = marker + 5
        if len(results) >= count:
            break
    return tuple(results)


def dot_unescape_with_map(raw: bytes) -> tuple[bytes, tuple[int, ...]]:
    output = bytearray()
    mapping: list[int] = []
    offset = 0
    for line in raw.splitlines(keepends=True):
        skipped = 1 if line.startswith(b"..") else 0
        for index, value in enumerate(line[skipped:], start=skipped):
            output.append(value)
            mapping.append(offset + index)
        offset += len(line)
    return bytes(output), tuple(mapping)


def _blob_row(
    connection: sqlite3.Connection,
    project_root: Path,
    data: bytes,
    *,
    media_type: Optional[str],
) -> tuple[int, str, int]:
    blob = BlobStore(project_root / "blobs").put_bytes(data)
    connection.execute(
        "INSERT OR IGNORE INTO blob"
        "(sha256,byte_length,relative_path,media_type,complete,created_at) "
        "VALUES(?,?,?,?,1,?)",
        (
            blob.sha256,
            blob.byte_length,
            blob.path.relative_to(project_root).as_posix(),
            media_type,
            _now(),
        ),
    )
    connection.execute(
        "UPDATE blob SET complete=1,media_type=coalesce(media_type,?) WHERE sha256=?",
        (media_type, blob.sha256),
    )
    blob_id = int(
        connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
    )
    return blob_id, blob.sha256, blob.byte_length


def _source_frames(
    connection: sqlite3.Connection, tcp_evidence_id: int, start: int, length: int
) -> list[int]:
    end = start + length
    return [
        int(row[0])
        for row in connection.execute(
            "SELECT DISTINCT ts.frame_number FROM tcp_reconstruction tr "
            "JOIN tcp_reconstruction_source trs ON trs.reconstruction_id=tr.id "
            "JOIN tcp_segment ts ON ts.id=trs.segment_id "
            "WHERE tr.evidence_id=? AND trs.role='primary' "
            "AND trs.output_offset<? AND trs.output_offset+trs.byte_length>? "
            "ORDER BY ts.frame_number",
            (tcp_evidence_id, end, start),
        )
    ]


def _reconstruction_blob(
    database: Database,
    project_root: Path,
    public_evidence_id: str,
) -> tuple[int, bytes]:
    with database.connect() as connection:
        row = connection.execute(
            "SELECT e.id,b.relative_path,b.byte_length,b.complete "
            "FROM evidence e JOIN blob b ON b.id=e.blob_id WHERE e.evidence_id=?",
            (public_evidence_id,),
        ).fetchone()
    if row is None or not int(row["complete"]):
        raise ValueError("SMTP TCP reconstruction has no complete evidence blob")
    path = (project_root / str(row["relative_path"])).resolve()
    try:
        path.relative_to(project_root.resolve())
    except ValueError as error:
        raise ValueError("SMTP TCP reconstruction blob escapes the project") from error
    data = path.read_bytes()
    if len(data) != int(row["byte_length"]):
        raise ValueError("SMTP TCP reconstruction blob length changed")
    return int(row["id"]), data


def _persist_skip(
    database: Database,
    tool_run_id: int,
    reason: str,
    count: int,
    *,
    stream: Optional[int] = None,
    frame: Optional[int] = None,
    detail: Optional[dict[str, object]] = None,
) -> None:
    if count <= 0:
        return
    with database.connect() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO smtp_skip"
            "(tool_run_id,tcp_stream,frame_number,reason,count,detail_json) VALUES(?,?,?,?,?,?)",
            (tool_run_id, stream, frame, reason, count, json.dumps(detail or {}, sort_keys=True)),
        )


def _message_row(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    tool_run_id: int,
    discovery: SmtpDiscovery,
    public_id: str,
    status: str,
    source_offset: Optional[int] = None,
    source_length: Optional[int] = None,
    tcp_evidence_id: Optional[int] = None,
    message_evidence_id: Optional[int] = None,
    subject: Optional[str] = None,
    attachment_count: int = 0,
    complete_attachments: int = 0,
    error: Optional[str] = None,
) -> int:
    connection.execute(
        "INSERT INTO smtp_message"
        "(message_id,capture_id,tool_run_id,tcp_stream,direction,data_frame,final_frame,"
        "declared_length,source_offset,source_length,tcp_evidence_id,message_evidence_id,"
        "subject,status,attachment_count,complete_attachments,error,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(message_id) DO UPDATE SET "
        "tool_run_id=excluded.tool_run_id,source_offset=excluded.source_offset,"
        "source_length=excluded.source_length,tcp_evidence_id=excluded.tcp_evidence_id,"
        "message_evidence_id=excluded.message_evidence_id,subject=excluded.subject,"
        "status=excluded.status,attachment_count=excluded.attachment_count,"
        "complete_attachments=excluded.complete_attachments,error=excluded.error,"
        "updated_at=excluded.updated_at",
        (
            public_id,
            capture_id,
            tool_run_id,
            discovery.stream,
            discovery.direction,
            discovery.data_frame,
            discovery.final_frame,
            discovery.declared_length,
            source_offset,
            source_length,
            tcp_evidence_id,
            message_evidence_id,
            subject,
            status,
            attachment_count,
            complete_attachments,
            error,
            _now(),
        ),
    )
    return int(
        connection.execute(
            "SELECT id FROM smtp_message WHERE message_id=?", (public_id,)
        ).fetchone()[0]
    )


def _persist_complete_message(
    database: Database,
    project_root: Path,
    capture_id: int,
    capture_sha256: str,
    tool_run_id: int,
    discovery: SmtpDiscovery,
    tcp_evidence_id: int,
    source_offset: int,
    raw: bytes,
    *,
    attachment_budget: list[int],
    max_attachments: int,
    max_attachment_bytes: int,
    max_total_attachment_bytes: int,
    max_mime_parts: int,
) -> tuple[SmtpMessageResult, int, int]:
    public_id = stable_id(
        "smtp-message",
        {
            "capture_sha256": capture_sha256,
            "data_frame": discovery.data_frame,
            "parser": PARSER_VERSION,
            "stream": discovery.stream,
        },
    )
    unescaped, source_map = dot_unescape_with_map(raw)
    parsed = BytesParser(policy=policy.default).parsebytes(unescaped)
    subject = _bounded_text(parsed.get("subject"))
    with database.connect() as connection:
        message_blob_id, message_sha256, _ = _blob_row(
            connection, project_root, raw, media_type="message/rfc822"
        )
        frames = _source_frames(connection, tcp_evidence_id, source_offset, len(raw))
        locator = {
            "capture_sha256": capture_sha256,
            "contributing_frames": frames,
            "data_frame": discovery.data_frame,
            "direction": discovery.direction,
            "final_frame": discovery.final_frame,
            "parser": PARSER_VERSION,
            "source_kind": "smtp-message",
            "source_stream_range": [source_offset, source_offset + len(raw)],
            "tcp_stream": discovery.stream,
        }
        message_evidence_public = stable_id("smtp-message-evidence", locator)
        connection.execute(
            "INSERT INTO evidence"
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,byte_offset,"
            "byte_length,field_name,blob_id,locator_json) VALUES(?,?,'smtp-message',?,?,?,?,"
            "?,'smtp.data',?,?) ON CONFLICT(evidence_id) DO UPDATE SET "
            "frame_start=excluded.frame_start,frame_end=excluded.frame_end,"
            "direction=excluded.direction,byte_length=excluded.byte_length,"
            "blob_id=excluded.blob_id,locator_json=excluded.locator_json",
            (
                message_evidence_public,
                capture_id,
                min(frames + [discovery.data_frame]),
                max(frames + [discovery.final_frame]),
                discovery.direction,
                0,
                len(raw),
                message_blob_id,
                json.dumps(locator, ensure_ascii=False, sort_keys=True),
            ),
        )
        message_evidence_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?", (message_evidence_public,)
            ).fetchone()[0]
        )
        smtp_message_id = _message_row(
            connection,
            capture_id=capture_id,
            tool_run_id=tool_run_id,
            discovery=discovery,
            public_id=public_id,
            status="complete",
            source_offset=source_offset,
            source_length=len(raw),
            tcp_evidence_id=tcp_evidence_id,
            message_evidence_id=message_evidence_id,
            subject=subject,
        )

        attachments: list[SmtpAttachmentResult] = []
        search_offset = 0
        skipped_limit = skipped_budget = 0
        attachment_ordinal = 0
        mime_parts = 0
        for part in parsed.walk():
            if part.is_multipart():
                continue
            mime_parts += 1
            filename = part.get_filename()
            disposition = part.get_content_disposition()
            if filename is None and disposition != "attachment":
                continue
            ordinal = attachment_ordinal
            attachment_ordinal += 1
            if mime_parts > max_mime_parts or attachment_budget[0] >= max_attachments:
                skipped_limit += 1
                continue
            media_type = part.get_content_type()
            transfer_encoding = str(part.get("Content-Transfer-Encoding", "")).lower()
            safe_name = _safe_name(filename, discovery.data_frame, ordinal)
            attachment_public_id = stable_id(
                "smtp-attachment",
                {"message_id": public_id, "ordinal": ordinal, "parser": PARSER_VERSION},
            )
            status = "complete"
            error = None
            decoded: Optional[bytes]
            try:
                decoded = part.get_payload(decode=True)
                if decoded is None:
                    raise ValueError("MIME part has no decodable payload")
            except (LookupError, UnicodeError, ValueError) as decode_error:
                decoded = None
                status = "failed"
                error = str(decode_error)

            payload = part.get_payload(decode=False)
            encoded = (
                payload.encode("utf-8", errors="surrogateescape")
                if isinstance(payload, str)
                else b""
            )
            local_start = unescaped.find(encoded, search_offset) if encoded else -1
            if local_start < 0 and encoded:
                local_start = unescaped.find(encoded)
            local_end = local_start + len(encoded) if local_start >= 0 else -1
            if local_start < 0 or local_end <= local_start or local_end > len(source_map):
                status = "failed"
                error = "MIME payload could not be mapped to exact SMTP source bytes"
                encoded_start = encoded_length = None
            else:
                search_offset = local_end
                raw_start = source_map[local_start]
                raw_end = source_map[local_end - 1] + 1
                encoded_start = source_offset + raw_start
                encoded_length = raw_end - raw_start

            decoded_length = len(decoded) if decoded is not None else 0
            if status == "complete" and (
                decoded_length > max_attachment_bytes
                or attachment_budget[1] + decoded_length > max_total_attachment_bytes
            ):
                status = "skipped-budget"
                error = "decoded attachment exceeds configured output budget"
                skipped_budget += 1

            evidence_public = artifact_public = sha256 = None
            evidence_db_id = artifact_db_id = None
            contributing_frames: list[int] = []
            if encoded_start is not None and encoded_length is not None:
                contributing_frames = _source_frames(
                    connection, tcp_evidence_id, encoded_start, encoded_length
                )
            if status == "complete" and decoded is not None:
                blob_id, sha256, decoded_length = _blob_row(
                    connection, project_root, decoded, media_type=media_type
                )
                locator = {
                    "capture_sha256": capture_sha256,
                    "contributing_frames": contributing_frames,
                    "data_frame": discovery.data_frame,
                    "decoded_range": [0, decoded_length],
                    "direction": discovery.direction,
                    "filename": safe_name,
                    "media_type": media_type,
                    "mime_ordinal": ordinal,
                    "parent_message_evidence_id": message_evidence_public,
                    "parser": PARSER_VERSION,
                    "source_kind": "smtp-attachment",
                    "source_stream_range": [encoded_start, encoded_start + encoded_length],
                    "tcp_stream": discovery.stream,
                    "transfer_encoding": transfer_encoding,
                }
                evidence_public = stable_id("smtp-attachment-evidence", locator)
                connection.execute(
                    "INSERT INTO evidence"
                    "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,"
                    "byte_offset,byte_length,field_name,blob_id,locator_json) "
                    "VALUES(?,?,'smtp-attachment',?,?,?,?,?,'mime-payload',?,?) "
                    "ON CONFLICT(evidence_id) DO UPDATE SET frame_start=excluded.frame_start,"
                    "frame_end=excluded.frame_end,direction=excluded.direction,"
                    "byte_length=excluded.byte_length,blob_id=excluded.blob_id,"
                    "locator_json=excluded.locator_json",
                    (
                        evidence_public,
                        capture_id,
                        min(contributing_frames),
                        max(contributing_frames),
                        discovery.direction,
                        0,
                        decoded_length,
                        blob_id,
                        json.dumps(locator, ensure_ascii=False, sort_keys=True),
                    ),
                )
                evidence_db_id = int(
                    connection.execute(
                        "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public,)
                    ).fetchone()[0]
                )
                artifact_public = stable_id(
                    "smtp-artifact", {"attachment_id": attachment_public_id, "sha256": sha256}
                )
                connection.execute(
                    "INSERT INTO artifact"
                    "(artifact_id,blob_id,source_evidence_id,suggested_name,declared_media_type,"
                    "detected_media_type,review_state,created_at) "
                    "VALUES(?,?,?,?,?,?,'unreviewed',?) "
                    "ON CONFLICT(artifact_id) DO UPDATE SET blob_id=excluded.blob_id,"
                    "source_evidence_id=excluded.source_evidence_id,"
                    "suggested_name=excluded.suggested_name,"
                    "declared_media_type=excluded.declared_media_type,"
                    "detected_media_type=excluded.detected_media_type",
                    (
                        artifact_public,
                        blob_id,
                        evidence_db_id,
                        safe_name,
                        media_type,
                        media_type,
                        _now(),
                    ),
                )
                artifact_db_id = int(
                    connection.execute(
                        "SELECT id FROM artifact WHERE artifact_id=?", (artifact_public,)
                    ).fetchone()[0]
                )
                connection.execute(
                    "INSERT OR IGNORE INTO artifact_evidence(artifact_id,evidence_id,role) "
                    "VALUES(?,?,'smtp-mime-part')",
                    (artifact_db_id, evidence_db_id),
                )
                attachment_budget[1] += decoded_length

            detail = {
                "contributing_frames": contributing_frames,
                "error": error,
                "parser": PARSER_VERSION,
                "source_stream_range": (
                    [encoded_start, encoded_start + encoded_length]
                    if encoded_start is not None and encoded_length is not None
                    else None
                ),
            }
            connection.execute(
                "INSERT INTO smtp_attachment"
                "(attachment_id,smtp_message_id,ordinal,filename,declared_media_type,"
                "transfer_encoding,source_offset,source_length,decoded_length,status,"
                "evidence_id,artifact_id,detail_json,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(attachment_id) DO UPDATE SET filename=excluded.filename,"
                "declared_media_type=excluded.declared_media_type,"
                "transfer_encoding=excluded.transfer_encoding,source_offset=excluded.source_offset,"
                "source_length=excluded.source_length,decoded_length=excluded.decoded_length,"
                "status=excluded.status,evidence_id=excluded.evidence_id,"
                "artifact_id=excluded.artifact_id,detail_json=excluded.detail_json,"
                "updated_at=excluded.updated_at",
                (
                    attachment_public_id,
                    smtp_message_id,
                    ordinal,
                    safe_name,
                    media_type,
                    transfer_encoding,
                    encoded_start,
                    encoded_length,
                    decoded_length,
                    status,
                    evidence_db_id,
                    artifact_db_id,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    _now(),
                ),
            )
            attachment_budget[0] += 1
            attachments.append(
                SmtpAttachmentResult(
                    attachment_public_id,
                    ordinal,
                    safe_name,
                    media_type,
                    transfer_encoding,
                    status,
                    encoded_start,
                    encoded_length,
                    decoded_length,
                    sha256,
                    evidence_public,
                    artifact_public,
                    error,
                )
            )

        complete_attachments = sum(item.status == "complete" for item in attachments)
        message_status = (
            "partial" if any(item.status != "complete" for item in attachments) else "complete"
        )
        _message_row(
            connection,
            capture_id=capture_id,
            tool_run_id=tool_run_id,
            discovery=discovery,
            public_id=public_id,
            status=message_status,
            source_offset=source_offset,
            source_length=len(raw),
            tcp_evidence_id=tcp_evidence_id,
            message_evidence_id=message_evidence_id,
            subject=subject,
            attachment_count=attachment_ordinal,
            complete_attachments=complete_attachments,
            error=(
                "one or more MIME attachments were not recovered"
                if message_status != "complete"
                else None
            ),
        )
    return (
        SmtpMessageResult(
            public_id,
            discovery.stream,
            discovery.direction,
            discovery.data_frame,
            discovery.final_frame,
            discovery.declared_length,
            message_status,
            source_offset,
            len(raw),
            message_sha256,
            subject,
            message_evidence_public,
            tuple(attachments),
            "one or more MIME attachments were not recovered"
            if message_status != "complete"
            else None,
        ),
        skipped_limit,
        skipped_budget,
    )


def _update_coverage(database: Database, capture_id: int, capture_sha256: str, status: str) -> None:
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT observation_id FROM protocol_observation "
            "WHERE capture_id=? AND protocol_label='smtp'",
            (capture_id,),
        ).fetchall()
        for row in rows:
            subject_id = str(row["observation_id"])
            coverage_id = stable_id(
                "analysis-coverage",
                {
                    "capture_sha256": capture_sha256,
                    "subject_kind": "protocol",
                    "subject_id": subject_id,
                },
            )
            connection.execute(
                "INSERT INTO analysis_coverage"
                "(coverage_id,capture_id,subject_kind,subject_id,status,detail_json,updated_at) "
                "VALUES(?,?,'protocol',?,?,?,?) ON CONFLICT(capture_id,subject_kind,subject_id) "
                "DO UPDATE SET status=excluded.status,detail_json=excluded.detail_json,"
                "updated_at=excluded.updated_at",
                (
                    coverage_id,
                    capture_id,
                    subject_id,
                    status,
                    json.dumps(
                        {"analyzer": PARSER_VERSION, "protocol_label": "smtp"}, sort_keys=True
                    ),
                    _now(),
                ),
            )


def extract_smtp_messages(
    project_path: Path,
    tshark: Path,
    *,
    max_streams: int = 64,
    max_messages: int = 256,
    max_stream_bytes: int = 64 * 1024 * 1024,
    max_message_bytes: int = 16 * 1024 * 1024,
    max_total_message_bytes: int = 64 * 1024 * 1024,
    max_attachments: int = 256,
    max_attachment_bytes: int = 32 * 1024 * 1024,
    max_total_attachment_bytes: int = 128 * 1024 * 1024,
    max_mime_parts: int = 2048,
    capabilities: Optional[TsharkCapabilities] = None,
) -> SmtpSummary:
    if (
        min(
            max_streams,
            max_messages,
            max_stream_bytes,
            max_message_bytes,
            max_total_message_bytes,
            max_attachments,
            max_attachment_bytes,
            max_total_attachment_bytes,
            max_mime_parts,
        )
        <= 0
    ):
        raise ValueError("SMTP extraction limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = capabilities or probe_tshark(tshark)
    available = set(capabilities.fields)
    missing = sorted(SMTP_REQUIRED_FIELDS - available)
    if not (
        {"ip.src", "ip.dst"}.issubset(available) or {"ipv6.src", "ipv6.dst"}.issubset(available)
    ):
        missing.append("ip.src/ip.dst or ipv6.src/ipv6.dst")
    if not capabilities.usable or missing:
        raise ValueError(f"TShark lacks required SMTP fields: {', '.join(missing)}")
    fields = selected_smtp_fields(available)
    argv = tshark_smtp_arguments(tshark, project.capture_path, available_fields=available)
    run_public_id = uuid4().hex
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO tool_run"
            "(run_id,tool_name,tool_version,argv_json,capability_json,started_at,status) "
            "VALUES(?,?,?,?,?,?,'running')",
            (
                run_public_id,
                "tshark",
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_provenance_json(),
                _now(),
            ),
        )
        tool_run_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])

    collector = _DiscoveryCollector(max_streams, max_messages)
    result = None
    tool_status = "failed"
    try:
        result = run_streaming_lines(
            argv,
            lambda line: collector.add(line, fields),
            timeout_seconds=300,
            max_line_bytes=1024 * 1024,
            stderr_limit=512 * 1024,
        )
        if result.timed_out:
            raise TimeoutError("TShark SMTP discovery timed out")
        if result.output_limit_exceeded:
            raise ValueError("TShark SMTP discovery exceeded the row limit")
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"TShark SMTP discovery exited {result.returncode}: {detail[:500]}")
        collector.finish()
        tool_status = (
            "budget-limited"
            if collector.skipped_stream_limit or collector.skipped_message_limit
            else "partial"
            if collector.malformed or collector.unmatched
            else "completed"
        )
    finally:
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
                "stderr_truncated=? WHERE id=?",
                (
                    _now(),
                    tool_status,
                    result.returncode if result else None,
                    result.stderr.decode("utf-8", errors="replace")
                    if result
                    else "SMTP discovery failed",
                    int(result.stderr_truncated) if result else 0,
                    tool_run_id,
                ),
            )

    _persist_skip(database, tool_run_id, "stream-limit", collector.skipped_stream_limit)
    _persist_skip(database, tool_run_id, "message-limit", collector.skipped_message_limit)
    _persist_skip(database, tool_run_id, "malformed-row", collector.malformed)
    _persist_skip(database, tool_run_id, "unmatched-data", collector.unmatched)
    for stream, frame, direction in collector.incomplete:
        _persist_skip(
            database,
            tool_run_id,
            "data-not-reassembled",
            1,
            stream=stream,
            frame=frame,
            detail={"direction": direction},
        )

    by_stream: dict[int, list[SmtpDiscovery]] = defaultdict(list)
    for discovery in collector.discoveries:
        by_stream[discovery.stream].append(discovery)
    message_results: list[SmtpMessageResult] = []
    skipped_message_budget = skipped_attachment_limit = skipped_attachment_budget = 0
    total_message_bytes = 0
    attachment_budget = [0, 0]
    for stream, discoveries in sorted(by_stream.items()):
        try:
            reconstruction = reconstruct_tcp_stream(
                project.root,
                stream,
                tshark,
                max_index_payload_bytes=max_stream_bytes,
                max_direction_bytes=max_stream_bytes,
                max_total_output_bytes=max_stream_bytes,
                capabilities=capabilities,
            )
        except (OSError, TimeoutError, ValueError) as error:
            for discovery in discoveries:
                public_id = stable_id(
                    "smtp-message",
                    {
                        "capture_sha256": project.capture_sha256,
                        "data_frame": discovery.data_frame,
                        "parser": PARSER_VERSION,
                        "stream": discovery.stream,
                    },
                )
                with database.connect() as connection:
                    _message_row(
                        connection,
                        capture_id=capture_id,
                        tool_run_id=tool_run_id,
                        discovery=discovery,
                        public_id=public_id,
                        status="failed",
                        error=str(error),
                    )
                message_results.append(
                    SmtpMessageResult(
                        public_id,
                        stream,
                        discovery.direction,
                        discovery.data_frame,
                        discovery.final_frame,
                        discovery.declared_length,
                        "failed",
                        None,
                        None,
                        None,
                        None,
                        None,
                        (),
                        str(error),
                    )
                )
            continue
        directions = {item.direction: item for item in reconstruction.directions}
        for direction, direction_discoveries in _group_by_direction(discoveries).items():
            summary = directions.get(direction)
            if summary is None or summary.status != "complete" or summary.evidence_id is None:
                error = "SMTP client TCP direction is incomplete or conflicting"
                for discovery in direction_discoveries:
                    public_id = stable_id(
                        "smtp-message",
                        {
                            "capture_sha256": project.capture_sha256,
                            "data_frame": discovery.data_frame,
                            "parser": PARSER_VERSION,
                            "stream": discovery.stream,
                        },
                    )
                    with database.connect() as connection:
                        _message_row(
                            connection,
                            capture_id=capture_id,
                            tool_run_id=tool_run_id,
                            discovery=discovery,
                            public_id=public_id,
                            status="partial",
                            error=error,
                        )
                    message_results.append(
                        SmtpMessageResult(
                            public_id,
                            stream,
                            direction,
                            discovery.data_frame,
                            discovery.final_frame,
                            discovery.declared_length,
                            "partial",
                            None,
                            None,
                            None,
                            None,
                            None,
                            (),
                            error,
                        )
                    )
                continue
            tcp_evidence_id, stream_bytes = _reconstruction_blob(
                database, project.root, summary.evidence_id
            )
            extracted = extract_smtp_data(stream_bytes, len(direction_discoveries))
            for index, discovery in enumerate(direction_discoveries):
                public_id = stable_id(
                    "smtp-message",
                    {
                        "capture_sha256": project.capture_sha256,
                        "data_frame": discovery.data_frame,
                        "parser": PARSER_VERSION,
                        "stream": discovery.stream,
                    },
                )
                if index >= len(extracted):
                    error = "SMTP DATA terminator was not found in the reconstructed stream"
                    with database.connect() as connection:
                        _message_row(
                            connection,
                            capture_id=capture_id,
                            tool_run_id=tool_run_id,
                            discovery=discovery,
                            public_id=public_id,
                            status="partial",
                            tcp_evidence_id=tcp_evidence_id,
                            error=error,
                        )
                    message_results.append(
                        SmtpMessageResult(
                            public_id,
                            stream,
                            direction,
                            discovery.data_frame,
                            discovery.final_frame,
                            discovery.declared_length,
                            "partial",
                            None,
                            None,
                            None,
                            None,
                            None,
                            (),
                            error,
                        )
                    )
                    continue
                source_offset, raw = extracted[index]
                if len(raw) != discovery.declared_length:
                    error = (
                        f"SMTP DATA length mismatch: TShark declared {discovery.declared_length}, "
                        f"reconstruction produced {len(raw)}"
                    )
                    with database.connect() as connection:
                        _message_row(
                            connection,
                            capture_id=capture_id,
                            tool_run_id=tool_run_id,
                            discovery=discovery,
                            public_id=public_id,
                            status="partial",
                            source_offset=source_offset,
                            source_length=len(raw),
                            tcp_evidence_id=tcp_evidence_id,
                            error=error,
                        )
                    message_results.append(
                        SmtpMessageResult(
                            public_id,
                            stream,
                            direction,
                            discovery.data_frame,
                            discovery.final_frame,
                            discovery.declared_length,
                            "partial",
                            source_offset,
                            len(raw),
                            None,
                            None,
                            None,
                            (),
                            error,
                        )
                    )
                    continue
                if (
                    len(raw) > max_message_bytes
                    or total_message_bytes + len(raw) > max_total_message_bytes
                ):
                    skipped_message_budget += 1
                    error = "SMTP message exceeds configured message budget"
                    with database.connect() as connection:
                        _message_row(
                            connection,
                            capture_id=capture_id,
                            tool_run_id=tool_run_id,
                            discovery=discovery,
                            public_id=public_id,
                            status="skipped-budget",
                            source_offset=source_offset,
                            source_length=len(raw),
                            tcp_evidence_id=tcp_evidence_id,
                            error=error,
                        )
                    message_results.append(
                        SmtpMessageResult(
                            public_id,
                            stream,
                            direction,
                            discovery.data_frame,
                            discovery.final_frame,
                            discovery.declared_length,
                            "skipped-budget",
                            source_offset,
                            len(raw),
                            None,
                            None,
                            None,
                            (),
                            error,
                        )
                    )
                    continue
                total_message_bytes += len(raw)
                try:
                    persisted, skipped_limit, skipped_budget = _persist_complete_message(
                        database,
                        project.root,
                        capture_id,
                        project.capture_sha256,
                        tool_run_id,
                        discovery,
                        tcp_evidence_id,
                        source_offset,
                        raw,
                        attachment_budget=attachment_budget,
                        max_attachments=max_attachments,
                        max_attachment_bytes=max_attachment_bytes,
                        max_total_attachment_bytes=max_total_attachment_bytes,
                        max_mime_parts=max_mime_parts,
                    )
                except (OSError, UnicodeError, ValueError) as error_value:
                    with database.connect() as connection:
                        _message_row(
                            connection,
                            capture_id=capture_id,
                            tool_run_id=tool_run_id,
                            discovery=discovery,
                            public_id=public_id,
                            status="failed",
                            source_offset=source_offset,
                            source_length=len(raw),
                            tcp_evidence_id=tcp_evidence_id,
                            error=str(error_value),
                        )
                    persisted = SmtpMessageResult(
                        public_id,
                        stream,
                        direction,
                        discovery.data_frame,
                        discovery.final_frame,
                        discovery.declared_length,
                        "failed",
                        source_offset,
                        len(raw),
                        None,
                        None,
                        None,
                        (),
                        str(error_value),
                    )
                    skipped_limit = skipped_budget = 0
                message_results.append(persisted)
                skipped_attachment_limit += skipped_limit
                skipped_attachment_budget += skipped_budget

    _persist_skip(database, tool_run_id, "message-budget", skipped_message_budget)
    _persist_skip(database, tool_run_id, "attachment-limit", skipped_attachment_limit)
    _persist_skip(database, tool_run_id, "attachment-budget", skipped_attachment_budget)
    states = {item.status for item in message_results}
    budget_limited = bool(
        collector.skipped_stream_limit
        or collector.skipped_message_limit
        or skipped_message_budget
        or skipped_attachment_limit
        or skipped_attachment_budget
    )
    overall = (
        "budget-limited"
        if budget_limited
        else "failed"
        if states and states <= {"failed"}
        else "partial"
        if collector.malformed or collector.unmatched or states - {"complete"}
        else "completed"
    )
    coverage = (
        "budget-limited"
        if budget_limited
        else "failed"
        if overall == "failed"
        else "partial"
        if overall == "partial"
        else "complete"
    )
    _update_coverage(database, capture_id, project.capture_sha256, coverage)
    return SmtpSummary(
        PARSER_VERSION,
        str(project.root),
        overall,
        collector.rows,
        collector.malformed,
        collector.unmatched,
        collector.skipped_stream_limit,
        collector.skipped_message_limit,
        skipped_message_budget,
        skipped_attachment_limit,
        skipped_attachment_budget,
        tuple(message_results),
    )


def _group_by_direction(
    discoveries: list[SmtpDiscovery],
) -> dict[str, list[SmtpDiscovery]]:
    grouped: dict[str, list[SmtpDiscovery]] = defaultdict(list)
    for discovery in discoveries:
        grouped[discovery.direction].append(discovery)
    return grouped
