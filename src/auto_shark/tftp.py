"""Bounded TFTP transfer discovery, reassembly, and artifact persistence."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import sqlite3
import tempfile
from bisect import bisect_right
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import stable_id
from .engines.stream import StreamProcessResult, run_streaming_lines
from .engines.tshark import TsharkCapabilities, probe_tshark
from .project import inspect_project
from .storage import BlobStore, Database

DISCOVERY_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "tftp.opcode",
    "tftp.source_file",
    "tftp.destination_file",
    "tftp.type",
    "tftp.block",
    "tftp.request_frame",
    "tftp.error.code",
    "tftp.error.message",
    "tftp.option.name",
    "tftp.option.value",
)
DATA_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "udp.payload",
)
REQUIRED_FIELDS = frozenset(
    {
        "frame.number",
        "frame.time_epoch",
        "udp.srcport",
        "udp.dstport",
        "udp.payload",
        "tftp.opcode",
        "tftp.source_file",
        "tftp.destination_file",
        "tftp.block",
        "tftp.request_frame",
    }
)
TRANSFORM_VERSION = "auto-shark.tftp-reassembly/v1"
_SAFE_NAME = re.compile(r"[\x00-\x1f\x7f]")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class _DiscoveryPacket:
    frame_number: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    opcode: int
    source_file: str
    destination_file: str
    mode: str
    block: Optional[int]
    request_frame: Optional[int]
    error_code: Optional[int]
    error_message: str
    option_name: str
    option_value: str


@dataclass(frozen=True)
class _DataPacket:
    frame_number: int
    source: str
    source_port: int
    destination: str
    destination_port: int
    block: int
    data: bytes


@dataclass
class _Transfer:
    request_frame: int
    opcode: int
    filename: str
    mode: str
    client: str
    client_port: int
    server: str
    server_port: Optional[int] = None
    response_frame: Optional[int] = None
    block_size: int = 512
    error_code: Optional[int] = None
    error_message: str = ""
    packets: list[_DataPacket] = field(default_factory=list)
    payload_bytes_selected: int = 0
    skipped_packet_limit: int = 0
    skipped_transfer_budget: int = 0
    skipped_total_budget: int = 0

    @property
    def operation(self) -> str:
        return "read" if self.opcode == 1 else "write"

    @property
    def direction(self) -> str:
        return "server-to-client" if self.opcode == 1 else "client-to-server"

    def data_route(self) -> Optional[tuple[str, int, str, int]]:
        if self.server_port is None:
            return None
        if self.opcode == 1:
            return self.server, self.server_port, self.client, self.client_port
        return self.client, self.client_port, self.server, self.server_port


@dataclass(frozen=True)
class TftpTransferResult:
    evidence_id: str
    artifact_id: Optional[str]
    operation: str
    filename: str
    mode: str
    status: str
    client: str
    client_port: int
    server: str
    server_port: Optional[int]
    request_frame: int
    response_frame: Optional[int]
    first_data_frame: Optional[int]
    last_data_frame: Optional[int]
    block_size: int
    data_packets: int
    duplicate_packets: int
    conflicting_blocks: int
    missing_blocks: int
    output_bytes: int
    output_sha256: Optional[str]
    detected_media_type: Optional[str]
    suggested_name: str
    error_code: Optional[int]
    error_message: str


@dataclass(frozen=True)
class TftpSummary:
    schema_version: str
    project: str
    status: str
    discovery_packets: int
    data_packets_seen: int
    malformed_rows: int
    skipped_transfer_limit: int
    skipped_packet_limit: int
    skipped_transfer_budget: int
    skipped_total_budget: int
    transfers: tuple[TftpTransferResult, ...]
    hints: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _parse_row(line: bytes, fields: tuple[str, ...]) -> dict[str, str]:
    rows = list(
        csv.reader(
            StringIO(line.decode("utf-8", errors="strict")),
            delimiter="\t",
            quotechar='"',
        )
    )
    if len(rows) != 1 or len(rows[0]) != len(fields):
        raise ValueError("invalid TFTP field row")
    return dict(zip(fields, rows[0]))


def _endpoint(data: dict[str, str], prefix: str) -> str:
    value = data[f"ip.{prefix}"] or data[f"ipv6.{prefix}"]
    if not value:
        raise ValueError("TFTP row lacks an IP endpoint")
    return str(ipaddress.ip_address(value))


def parse_discovery_line(line: bytes) -> _DiscoveryPacket:
    data = _parse_row(line, DISCOVERY_FIELDS)
    return _DiscoveryPacket(
        frame_number=int(data["frame.number"]),
        source=_endpoint(data, "src"),
        source_port=int(data["udp.srcport"]),
        destination=_endpoint(data, "dst"),
        destination_port=int(data["udp.dstport"]),
        opcode=int(data["tftp.opcode"]),
        source_file=data["tftp.source_file"],
        destination_file=data["tftp.destination_file"],
        mode=data["tftp.type"],
        block=int(data["tftp.block"]) if data["tftp.block"] else None,
        request_frame=(
            int(data["tftp.request_frame"]) if data["tftp.request_frame"] else None
        ),
        error_code=(
            int(data["tftp.error.code"]) if data["tftp.error.code"] else None
        ),
        error_message=data["tftp.error.message"],
        option_name=data["tftp.option.name"],
        option_value=data["tftp.option.value"],
    )


def parse_data_line(line: bytes) -> _DataPacket:
    row = _parse_row(line, DATA_FIELDS)
    raw = bytes.fromhex(row["udp.payload"].replace(":", ""))
    if len(raw) < 4 or int.from_bytes(raw[:2], "big") != 3:
        raise ValueError("UDP payload is not a TFTP DATA packet")
    return _DataPacket(
        frame_number=int(row["frame.number"]),
        source=_endpoint(row, "src"),
        source_port=int(row["udp.srcport"]),
        destination=_endpoint(row, "dst"),
        destination_port=int(row["udp.dstport"]),
        block=int.from_bytes(raw[2:4], "big"),
        data=raw[4:],
    )


def _field_arguments(fields: tuple[str, ...]) -> list[str]:
    result = [
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
        "-E",
        "occurrence=f",
    ]
    for name in fields:
        result.extend(("-e", name))
    return result


def tshark_tftp_discovery_arguments(executable: Path, capture: Path) -> list[str]:
    display_filter = (
        "(udp.port == 69 && tftp) || "
        "(tftp && (tftp.opcode == 5 || tftp.opcode == 6 || "
        "tftp.block == 0 || tftp.block == 1))"
    )
    return [
        str(executable),
        "-r",
        str(capture),
        "-Y",
        display_filter,
        *_field_arguments(DISCOVERY_FIELDS),
    ]


def _route_expression(route: tuple[str, int, str, int]) -> str:
    source, source_port, destination, destination_port = route
    family = "ipv6" if ":" in source else "ip"
    return (
        f"({family}.src == {source} && udp.srcport == {source_port} && "
        f"{family}.dst == {destination} && udp.dstport == {destination_port})"
    )


def tshark_tftp_data_arguments(
    executable: Path,
    capture: Path,
    transfers: list[_Transfer],
) -> list[str]:
    routes = sorted({item.data_route() for item in transfers if item.data_route() is not None})
    if not routes:
        raise ValueError("TFTP data extraction requires at least one negotiated route")
    display_filter = "udp.payload && (" + " || ".join(
        _route_expression(route) for route in routes if route is not None
    ) + ")"
    return [
        str(executable),
        "-r",
        str(capture),
        "-Y",
        display_filter,
        *_field_arguments(DATA_FIELDS),
    ]


class _DiscoveryCollector:
    def __init__(self, max_packets: int, max_transfers: int) -> None:
        self.max_packets = max_packets
        self.max_transfers = max_transfers
        self.packets_seen = 0
        self.malformed_rows = 0
        self.skipped_packet_limit = 0
        self.skipped_transfer_limit = 0
        self.transfers: list[_Transfer] = []
        self.by_request_frame: dict[int, _Transfer] = {}

    @property
    def budget_limited(self) -> bool:
        return bool(self.skipped_packet_limit or self.skipped_transfer_limit)

    def add_line(self, line: bytes) -> None:
        self.packets_seen += 1
        if self.packets_seen > self.max_packets:
            self.skipped_packet_limit += 1
            return
        try:
            packet = parse_discovery_line(line)
        except (UnicodeError, ValueError):
            self.malformed_rows += 1
            return
        if packet.opcode in (1, 2) and packet.destination_port == 69:
            if len(self.transfers) >= self.max_transfers:
                self.skipped_transfer_limit += 1
                return
            filename = (
                packet.source_file if packet.opcode == 1 else packet.destination_file
            )
            transfer = _Transfer(
                request_frame=packet.frame_number,
                opcode=packet.opcode,
                filename=filename or f"tftp-frame-{packet.frame_number}.bin",
                mode=packet.mode or "octet",
                client=packet.source,
                client_port=packet.source_port,
                server=packet.destination,
            )
            self.transfers.append(transfer)
            self.by_request_frame[packet.frame_number] = transfer
            return
        if packet.request_frame is None:
            return
        transfer = self.by_request_frame.get(packet.request_frame)
        if transfer is None:
            return
        if packet.source == transfer.server and packet.destination == transfer.client:
            transfer.server_port = packet.source_port
            if transfer.response_frame is None:
                transfer.response_frame = packet.frame_number
        if packet.error_code is not None:
            transfer.error_code = packet.error_code
            transfer.error_message = packet.error_message
        if packet.option_name.lower() == "blksize":
            try:
                size = int(packet.option_value)
            except ValueError:
                return
            if 8 <= size <= 65464:
                transfer.block_size = size


class _DataCollector:
    def __init__(
        self,
        transfers: list[_Transfer],
        *,
        max_packets: int,
        max_transfer_bytes: int,
        max_total_bytes: int,
    ) -> None:
        self.max_packets = max_packets
        self.max_transfer_bytes = max_transfer_bytes
        self.max_total_bytes = max_total_bytes
        self.packets_seen = 0
        self.malformed_rows = 0
        self.total_bytes = 0
        self.routes: dict[tuple[str, int, str, int], list[_Transfer]] = {}
        for transfer in transfers:
            route = transfer.data_route()
            if route is not None and transfer.error_code is None:
                self.routes.setdefault(route, []).append(transfer)
        for items in self.routes.values():
            items.sort(key=lambda item: item.request_frame)

    @property
    def budget_limited(self) -> bool:
        return any(
            item.skipped_packet_limit
            or item.skipped_transfer_budget
            or item.skipped_total_budget
            for items in self.routes.values()
            for item in items
        )

    def _select_transfer(self, packet: _DataPacket) -> Optional[_Transfer]:
        key = (
            packet.source,
            packet.source_port,
            packet.destination,
            packet.destination_port,
        )
        items = self.routes.get(key)
        if not items:
            return None
        frames = [item.request_frame for item in items]
        index = bisect_right(frames, packet.frame_number) - 1
        return items[index] if index >= 0 else None

    def add_line(self, line: bytes) -> None:
        try:
            packet = parse_data_line(line)
        except (UnicodeError, ValueError):
            self.malformed_rows += 1
            return
        transfer = self._select_transfer(packet)
        if transfer is None:
            self.malformed_rows += 1
            return
        self.packets_seen += 1
        if self.packets_seen > self.max_packets:
            transfer.skipped_packet_limit += 1
            return
        length = len(packet.data)
        if transfer.payload_bytes_selected + length > self.max_transfer_bytes:
            transfer.skipped_transfer_budget += 1
            return
        if self.total_bytes + length > self.max_total_bytes:
            transfer.skipped_total_budget += 1
            return
        transfer.packets.append(packet)
        transfer.payload_bytes_selected += length
        self.total_bytes += length


@dataclass(frozen=True)
class _Reconstruction:
    status: str
    packets: tuple[_DataPacket, ...]
    duplicate_packets: int
    conflicting_blocks: int
    missing_blocks: int
    terminal_block_seen: bool


def _reconstruct(transfer: _Transfer) -> _Reconstruction:
    if transfer.error_code is not None:
        return _Reconstruction("server-error", (), 0, 0, 0, False)
    if transfer.server_port is None:
        return _Reconstruction("unresolved", (), 0, 0, 0, False)
    if not transfer.packets:
        status = "budget-limited" if (
            transfer.skipped_packet_limit
            or transfer.skipped_transfer_budget
            or transfer.skipped_total_budget
        ) else "no-data"
        return _Reconstruction(status, (), 0, 0, 0, False)

    extended: list[tuple[int, _DataPacket]] = []
    last_raw = transfer.packets[0].block
    last_extended = last_raw
    for packet in transfer.packets:
        delta = ((packet.block - last_raw + 32768) % 65536) - 32768
        value = last_extended + delta
        extended.append((value, packet))
        if value > last_extended:
            last_raw = packet.block
            last_extended = value

    unique: dict[int, _DataPacket] = {}
    conflicts = 0
    for block, packet in extended:
        existing = unique.get(block)
        if existing is None:
            unique[block] = packet
        elif existing.data != packet.data:
            conflicts += 1
    ordered = sorted(unique.items())
    duplicates = len(extended) - len(ordered)
    missing = max(0, ordered[0][0] - 1)
    for previous, current in zip(ordered, ordered[1:]):
        missing += max(0, current[0] - previous[0] - 1)
    packets = tuple(packet for _, packet in ordered)
    terminal = bool(packets and len(packets[-1].data) < transfer.block_size)
    budget_limited = bool(
        transfer.skipped_packet_limit
        or transfer.skipped_transfer_budget
        or transfer.skipped_total_budget
    )
    if budget_limited:
        status = "budget-limited"
    elif conflicts:
        status = "conflicting"
    elif missing or ordered[0][0] != 1 or not terminal:
        status = "partial"
    elif sum(len(item.data) for item in packets) == 0:
        status = "empty"
    else:
        status = "complete"
    return _Reconstruction(status, packets, duplicates, conflicts, missing, terminal)


def _suggested_name(value: str, frame: int) -> str:
    basename = value.replace("\\", "/").split("/")[-1]
    cleaned = _SAFE_NAME.sub("_", basename).strip(" .")
    return cleaned[:255] or f"tftp-frame-{frame}.bin"


def _detect_media(prefix: bytes, filename: str) -> tuple[str, str]:
    lower = filename.lower()
    if prefix.startswith(b"BM"):
        return "image/bmp", "BMP image"
    if prefix.startswith(b"!<arch>\n") and lower.endswith(".deb"):
        return "application/vnd.debian.binary-package", "Debian binary package"
    if prefix.startswith(b"PK\x03\x04"):
        return "application/zip", "ZIP archive"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "PNG image"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "JPEG image"
    if prefix.startswith(b"Rar!\x1a\x07"):
        return "application/vnd.rar", "RAR archive"
    if prefix.startswith(b"%PDF-"):
        return "application/pdf", "PDF document"
    if prefix.startswith(b"MZ"):
        return "application/vnd.microsoft.portable-executable", "PE executable"
    if prefix:
        printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in prefix)
        if printable / len(prefix) >= 0.9:
            return "text/plain", "printable text"
    return "application/octet-stream", "TFTP transferred bytes"


def _store_blob(
    connection: sqlite3.Connection,
    project_root: Path,
    packets: tuple[_DataPacket, ...],
    filename: str,
    *,
    complete: bool,
) -> tuple[int, str, int, str]:
    prefix = b"".join(packet.data for packet in packets[:2])[:4096]
    media_type, description = _detect_media(prefix, filename)
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as stream:
        for packet in packets:
            stream.write(packet.data)
        stream.seek(0)
        blob = BlobStore(project_root / "blobs").put_stream(stream)
    relative = blob.path.relative_to(project_root).as_posix()
    connection.execute(
        "INSERT OR IGNORE INTO blob"
        "(sha256,byte_length,relative_path,media_type,magic_description,complete,created_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (
            blob.sha256,
            blob.byte_length,
            relative,
            media_type,
            description,
            int(complete),
            _now(),
        ),
    )
    if complete:
        connection.execute("UPDATE blob SET complete=1 WHERE sha256=?", (blob.sha256,))
    blob_id = int(
        connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
    )
    return blob_id, blob.sha256, blob.byte_length, media_type


def _persist_transfer(
    connection: sqlite3.Connection,
    project_root: Path,
    capture_id: int,
    capture_sha256: str,
    transfer: _Transfer,
) -> TftpTransferResult:
    reconstruction = _reconstruct(transfer)
    complete = reconstruction.status == "complete"
    name = _suggested_name(transfer.filename, transfer.request_frame)
    blob_id = None
    output_sha256 = None
    output_bytes = 0
    media_type = None
    if reconstruction.packets:
        blob_id, output_sha256, output_bytes, media_type = _store_blob(
            connection,
            project_root,
            reconstruction.packets,
            name,
            complete=complete,
        )
    data_frames = [packet.frame_number for packet in reconstruction.packets]
    first_data = min(data_frames) if data_frames else None
    last_data = max(data_frames) if data_frames else None
    frame_end = max(
        item
        for item in (transfer.request_frame, transfer.response_frame, last_data)
        if item is not None
    )
    route = transfer.data_route()
    locator = {
        "block_size": transfer.block_size,
        "capture_sha256": capture_sha256,
        "client": transfer.client,
        "client_port": transfer.client_port,
        "conflicting_blocks": reconstruction.conflicting_blocks,
        "data_packets": len(reconstruction.packets),
        "direction": transfer.direction,
        "duplicate_packets": reconstruction.duplicate_packets,
        "error_code": transfer.error_code,
        "error_message": transfer.error_message,
        "filename": transfer.filename,
        "first_data_frame": first_data,
        "frame_samples": data_frames[:8] + data_frames[-8:],
        "last_data_frame": last_data,
        "missing_blocks": reconstruction.missing_blocks,
        "mode": transfer.mode,
        "operation": transfer.operation,
        "reassembly": TRANSFORM_VERSION,
        "request_frame": transfer.request_frame,
        "response_frame": transfer.response_frame,
        "route": list(route) if route is not None else None,
        "server": transfer.server,
        "server_port": transfer.server_port,
        "skipped_packet_limit": transfer.skipped_packet_limit,
        "skipped_total_budget": transfer.skipped_total_budget,
        "skipped_transfer_budget": transfer.skipped_transfer_budget,
        "status": reconstruction.status,
        "terminal_block_seen": reconstruction.terminal_block_seen,
    }
    identity = {
        "capture_sha256": capture_sha256,
        "request_frame": transfer.request_frame,
        "operation": transfer.operation,
        "reassembly": TRANSFORM_VERSION,
    }
    evidence_public_id = stable_id("tftp-data-evidence", identity)
    connection.execute(
        "INSERT INTO evidence"
        "(evidence_id,capture_id,source_kind,frame_start,frame_end,direction,byte_offset,"
        "byte_length,field_name,blob_id,locator_json) VALUES(?,?,'tftp-data',?,?,?,?,?,"
        "'udp.payload',?,?) ON CONFLICT(evidence_id) DO UPDATE SET "
        "frame_start=excluded.frame_start,frame_end=excluded.frame_end,"
        "direction=excluded.direction,byte_offset=excluded.byte_offset,"
        "byte_length=excluded.byte_length,blob_id=excluded.blob_id,"
        "locator_json=excluded.locator_json",
        (
            evidence_public_id,
            capture_id,
            transfer.request_frame,
            frame_end,
            transfer.direction,
            0,
            output_bytes,
            blob_id,
            json.dumps(locator, ensure_ascii=False, sort_keys=True),
        ),
    )
    evidence_db_id = int(
        connection.execute(
            "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public_id,)
        ).fetchone()[0]
    )
    artifact_public_id = None
    if complete and blob_id is not None and output_bytes > 0:
        artifact_public_id = stable_id(
            "tftp-artifact", {**identity, "sha256": output_sha256}
        )
        connection.execute(
            "INSERT INTO artifact"
            "(artifact_id,blob_id,source_evidence_id,suggested_name,declared_media_type,"
            "detected_media_type,review_state,created_at) VALUES(?,?,?, ?,NULL,?,"
            "'unreviewed',?) ON CONFLICT(artifact_id) DO UPDATE SET "
            "blob_id=excluded.blob_id,source_evidence_id=excluded.source_evidence_id,"
            "suggested_name=excluded.suggested_name,"
            "detected_media_type=excluded.detected_media_type",
            (
                artifact_public_id,
                blob_id,
                evidence_db_id,
                name,
                media_type,
                _now(),
            ),
        )
        artifact_db_id = int(
            connection.execute(
                "SELECT id FROM artifact WHERE artifact_id=?", (artifact_public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO artifact_evidence(artifact_id,evidence_id,role) "
            "VALUES(?,?,'transferred-by')",
            (artifact_db_id, evidence_db_id),
        )
    return TftpTransferResult(
        evidence_id=evidence_public_id,
        artifact_id=artifact_public_id,
        operation=transfer.operation,
        filename=transfer.filename,
        mode=transfer.mode,
        status=reconstruction.status,
        client=transfer.client,
        client_port=transfer.client_port,
        server=transfer.server,
        server_port=transfer.server_port,
        request_frame=transfer.request_frame,
        response_frame=transfer.response_frame,
        first_data_frame=first_data,
        last_data_frame=last_data,
        block_size=transfer.block_size,
        data_packets=len(reconstruction.packets),
        duplicate_packets=reconstruction.duplicate_packets,
        conflicting_blocks=reconstruction.conflicting_blocks,
        missing_blocks=reconstruction.missing_blocks,
        output_bytes=output_bytes,
        output_sha256=output_sha256,
        detected_media_type=media_type,
        suggested_name=name,
        error_code=transfer.error_code,
        error_message=transfer.error_message,
    )


def _record_tool_start(
    database: Database,
    *,
    run_id: str,
    tool_name: str,
    capabilities: TsharkCapabilities,
    argv: list[str],
) -> None:
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run"
            "(run_id,tool_name,tool_version,argv_json,capability_json,started_at,status) "
            "VALUES(?,?,?,?,?,?,'running')",
            (
                run_id,
                tool_name,
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_json(),
                _now(),
            ),
        )


def _record_tool_end(
    database: Database,
    run_id: str,
    result: StreamProcessResult,
    *,
    budget_limited: bool,
) -> None:
    failed = result.timed_out or result.output_limit_exceeded or result.returncode != 0
    status = "failed" if failed else "budget-limited" if budget_limited else "completed"
    with database.connect() as connection:
        connection.execute(
            "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
            "stderr_truncated=? WHERE run_id=?",
            (
                _now(),
                status,
                result.returncode,
                result.stderr.decode("utf-8", errors="replace"),
                int(result.stderr_truncated),
                run_id,
            ),
        )


def _run_tshark(
    database: Database,
    capabilities: TsharkCapabilities,
    argv: list[str],
    callback,
    *,
    tool_name: str,
    budget_limited,
) -> StreamProcessResult:
    run_id = uuid4().hex
    _record_tool_start(
        database,
        run_id=run_id,
        tool_name=tool_name,
        capabilities=capabilities,
        argv=argv,
    )
    result = run_streaming_lines(
        argv,
        callback,
        timeout_seconds=600,
        max_line_bytes=2 * 1024 * 1024,
        stderr_limit=512 * 1024,
    )
    _record_tool_end(database, run_id, result, budget_limited=budget_limited())
    if result.timed_out or result.output_limit_exceeded or result.returncode != 0:
        raise RuntimeError(f"TShark TFTP extraction failed with exit {result.returncode}")
    return result


def extract_tftp_transfers(
    project_path: Path,
    tshark: Path,
    *,
    max_discovery_packets: int = 100_000,
    max_data_packets: int = 500_000,
    max_transfers: int = 256,
    max_transfer_bytes: int = 64 * 1024 * 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
    capabilities: Optional[TsharkCapabilities] = None,
) -> TftpSummary:
    if min(
        max_discovery_packets,
        max_data_packets,
        max_transfers,
        max_transfer_bytes,
        max_total_bytes,
    ) <= 0:
        raise ValueError("TFTP extraction limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = capabilities or probe_tshark(tshark)
    available = set(capabilities.fields)
    missing = sorted(REQUIRED_FIELDS - available)
    ipv4 = {"ip.src", "ip.dst"}.issubset(available)
    ipv6 = {"ipv6.src", "ipv6.dst"}.issubset(available)
    if not capabilities.usable or missing or not (ipv4 or ipv6):
        if not (ipv4 or ipv6):
            missing.append("ip.src/ip.dst or ipv6.src/ipv6.dst")
        raise ValueError("TShark lacks required TFTP fields: " + ", ".join(missing))

    discovery = _DiscoveryCollector(max_discovery_packets, max_transfers)
    discovery_argv = tshark_tftp_discovery_arguments(tshark, project.capture_path)
    _run_tshark(
        database,
        capabilities,
        discovery_argv,
        discovery.add_line,
        tool_name="tshark-tftp-discovery",
        budget_limited=lambda: discovery.budget_limited,
    )

    candidates = [
        item
        for item in discovery.transfers
        if item.server_port is not None and item.error_code is None
    ]
    data = _DataCollector(
        discovery.transfers,
        max_packets=max_data_packets,
        max_transfer_bytes=max_transfer_bytes,
        max_total_bytes=max_total_bytes,
    )
    if candidates:
        data_argv = tshark_tftp_data_arguments(tshark, project.capture_path, candidates)
        _run_tshark(
            database,
            capabilities,
            data_argv,
            data.add_line,
            tool_name="tshark-tftp-data",
            budget_limited=lambda: data.budget_limited,
        )

    results: list[TftpTransferResult] = []
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        for transfer in discovery.transfers:
            results.append(
                _persist_transfer(
                    connection,
                    project.root,
                    capture_id,
                    project.capture_sha256,
                    transfer,
                )
            )

    skipped_packet_limit = discovery.skipped_packet_limit + sum(
        item.skipped_packet_limit for item in discovery.transfers
    )
    skipped_transfer_budget = sum(
        item.skipped_transfer_budget for item in discovery.transfers
    )
    skipped_total_budget = sum(item.skipped_total_budget for item in discovery.transfers)
    budget_limited = bool(
        discovery.budget_limited
        or skipped_packet_limit
        or skipped_transfer_budget
        or skipped_total_budget
    )
    return TftpSummary(
        schema_version="auto-shark.tftp/v1",
        project=str(project.root),
        status="budget-limited" if budget_limited else "completed",
        discovery_packets=discovery.packets_seen,
        data_packets_seen=data.packets_seen,
        malformed_rows=discovery.malformed_rows + data.malformed_rows,
        skipped_transfer_limit=discovery.skipped_transfer_limit,
        skipped_packet_limit=skipped_packet_limit,
        skipped_transfer_budget=skipped_transfer_budget,
        skipped_total_budget=skipped_total_budget,
        transfers=tuple(results),
        hints=(
            "Review both RRQ downloads and WRQ uploads; TFTP provides no encryption.",
            "Only complete, gap-free, conflict-free transfers become artifacts; partial "
            "bytes remain evidence.",
            "Do not execute transferred packages. Inspect text and file metadata first, "
            "then use declared analyzers for images or archives.",
        ),
    )
