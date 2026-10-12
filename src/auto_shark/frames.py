"""Wireshark-style packet list columns for the GUI Frames page.

One tshark pass extracts per-frame display columns (time, endpoints,
protocol, Info, length, stream indexes) into the ``frame_column`` table so
the GUI can show every packet unconditionally — no detector has to fire
first. This is the generic fallback a player needs on unseen challenges.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .engines.stream import run_streaming_lines
from .engines.tshark import probe_tshark
from .project import inspect_project
from .storage import Database

FRAME_DETECTOR_VERSION = "frame-columns/v1"
FRAME_MAX_FRAMES = 200_000
FRAME_INFO_MAX_CHARS = 512

FRAME_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "_ws.col.protocol",
    "_ws.col.info",
    "frame.len",
    "tcp.stream",
    "udp.stream",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class FrameColumnsSummary:
    schema_version: str
    project: str
    status: str
    frames: int
    truncated: bool
    notes: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


def tshark_frame_arguments(executable: Path, capture: Path) -> list[str]:
    arguments = [
        str(executable),
        "-r",
        str(capture),
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in FRAME_FIELDS:
        arguments.extend(("-e", field))
    return arguments


def parse_frame_line(line: bytes) -> tuple | None:
    parts = line.decode("utf-8", errors="replace").split("\t")
    if len(parts) != len(FRAME_FIELDS):
        return None
    values = dict(zip(FRAME_FIELDS, (item.strip('"') for item in parts)))
    try:
        frame = int(values["frame.number"])
        epoch = float(values["frame.time_epoch"] or 0)
        length = int(values["frame.len"] or 0)
    except ValueError:
        return None
    tcp_stream = values.get("tcp.stream")
    udp_stream = values.get("udp.stream")
    return (
        frame,
        epoch,
        values.get("ip.src") or values.get("ipv6.src") or "",
        values.get("ip.dst") or values.get("ipv6.dst") or "",
        values.get("_ws.col.protocol") or "",
        values.get("_ws.col.info") or "",
        length,
        int(tcp_stream) if tcp_stream else None,
        int(udp_stream) if udp_stream else None,
    )


def extract_frame_columns(
    project_path: Path,
    tshark: Path,
    *,
    max_frames: int = FRAME_MAX_FRAMES,
) -> FrameColumnsSummary:
    """Populate frame_column for the whole capture (idempotent refresh)."""

    if max_frames <= 0:
        raise ValueError("frame limits must be positive")
    project = inspect_project(project_path)
    capabilities = probe_tshark(tshark)
    if not capabilities.usable:
        return FrameColumnsSummary(
            FRAME_DETECTOR_VERSION,
            str(project.root),
            "unavailable",
            0,
            False,
            ("TShark is not usable for frame extraction.",),
        )
    argv = tshark_frame_arguments(tshark, project.capture_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    run_id = uuid4().hex
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,tool_version,argv_json,capability_json,"
            "started_at,status) VALUES(?,?,?,?,?,?,'running')",
            (
                run_id,
                "tshark-frame-columns",
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_provenance_json(),
                _now(),
            ),
        )
    rows: list[tuple] = []
    truncated = False

    def consume(line: bytes) -> None:
        nonlocal truncated
        if len(rows) >= max_frames:
            truncated = True
            return
        parsed = parse_frame_line(line)
        if parsed is None:
            return
        # Info column can be arbitrarily long; bound it for storage.
        row = list(parsed)
        if len(row[5]) > FRAME_INFO_MAX_CHARS:
            row[5] = row[5][:FRAME_INFO_MAX_CHARS]
        rows.append(tuple(row))

    process = run_streaming_lines(
        argv,
        consume,
        timeout_seconds=300,
        max_line_bytes=64 * 1024,
        stderr_limit=256 * 1024,
    )
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        connection.execute("DELETE FROM frame_column WHERE capture_id=?", (capture_id,))
        connection.executemany(
            "INSERT INTO frame_column(capture_id,frame_number,time_epoch,src,dst,"
            "protocol,info,frame_len,tcp_stream,udp_stream) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(capture_id, *row) for row in rows],
        )
        status = "completed" if process.returncode == 0 else f"tshark-exited-{process.returncode}"
        connection.execute(
            "UPDATE tool_run SET ended_at=?, status=?, exit_code=? WHERE run_id=?",
            (_now(), status, process.returncode, run_id),
        )
    return FrameColumnsSummary(
        FRAME_DETECTOR_VERSION,
        str(project.root),
        status,
        len(rows),
        truncated,
        () if not truncated else ("frame limit reached; listing truncated",),
    )
