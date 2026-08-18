"""Detect text concealed in TCP urgent pointers.

TCP urgent data is uncommon in ordinary application traffic.  CTF authors
occasionally use the urgent pointer as a one-byte side channel, so this
detector preserves the contributing frames and surfaces printable sequences
without assuming that every urgent pointer is malicious.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from uuid import uuid4

from .core.ids import candidate_id, stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import probe_tshark
from .project import inspect_project
from .storage import Database

URGENT_FIELDS = (
    "frame.number",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.flags.urg",
    "tcp.urgent_pointer",
)
URGENT_REQUIRED_FIELDS = frozenset(URGENT_FIELDS)
DETECTOR = "tcp-urgent-pointer"
DETECTOR_VERSION = "auto-shark.tcp-urgent-pointer/v1"
_FLAG = re.compile(r"(?i)(?:flag|ctf)\{[^\r\n\x00]{1,240}\}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class _Group:
    stream: int
    source: str
    destination: str
    frames: list[int]
    values: list[int]


@dataclass(frozen=True)
class TcpUrgentGroup:
    stream: int
    source: str
    destination: str
    first_frame: int
    last_frame: int
    values: int
    printable: int
    text: str
    flags: tuple[str, ...]
    evidence_id: str


@dataclass(frozen=True)
class TcpUrgentSummary:
    schema_version: str
    status: str
    frames_seen: int
    urgent_frames: int
    malformed_rows: int
    skipped_frame_limit: int
    skipped_group_limit: int
    groups: tuple[TcpUrgentGroup, ...]
    hints: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def tshark_urgent_arguments(executable: Path, capture: Path) -> list[str]:
    arguments = [
        str(executable),
        "-r",
        str(capture),
        "-Y",
        "tcp.flags.urg == 1 && tcp.urgent_pointer > 0",
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
    for field in URGENT_FIELDS:
        arguments.extend(("-e", field))
    return arguments


def parse_urgent_line(line: bytes) -> tuple[int, int, str, str, int] | None:
    rows = list(csv.reader(StringIO(line.decode("utf-8", errors="strict")), delimiter="\t"))
    if len(rows) != 1 or len(rows[0]) != len(URGENT_FIELDS):
        raise ValueError("invalid TCP urgent field row")
    values = dict(zip(URGENT_FIELDS, rows[0]))
    if values["tcp.flags.urg"] not in {"1", "true", "True"}:
        return None
    source = values["ip.src"] or values["ipv6.src"]
    destination = values["ip.dst"] or values["ipv6.dst"]
    if (
        not source
        or not destination
        or not values["tcp.stream"]
        or not values["tcp.urgent_pointer"]
    ):
        return None
    pointer = int(values["tcp.urgent_pointer"])
    if pointer <= 0:
        return None
    return int(values["frame.number"]), int(values["tcp.stream"]), source, destination, pointer


def _persist_group(
    database: Database,
    capture_id: int,
    capture_sha256: str,
    group: _Group,
) -> TcpUrgentGroup:
    text_chars = [chr(value) if 32 <= value <= 126 else "?" for value in group.values]
    text = "".join(text_chars)
    printable = sum(char != "?" for char in text_chars)
    flags = tuple(dict.fromkeys(match.group(0) for match in _FLAG.finditer(text)))
    locator = {
        "capture_sha256": capture_sha256,
        "detector": DETECTOR_VERSION,
        "direction": f"{group.source}->{group.destination}",
        "frame_count": len(group.frames),
        "values": group.values[:256],
    }
    evidence_public_id = stable_id(
        "tcp-urgent-evidence",
        {
            "capture_sha256": capture_sha256,
            "stream": group.stream,
            "source": group.source,
            "destination": group.destination,
        },
    )
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "direction,byte_offset,byte_length,field_name,text_value,locator_json) "
            "VALUES(?,?,'tcp-urgent-pointer',?,?,?,0,?,?,?,?) "
            "ON CONFLICT(evidence_id) DO UPDATE SET frame_start=excluded.frame_start,"
            "frame_end=excluded.frame_end,byte_length=excluded.byte_length,"
            "text_value=excluded.text_value,locator_json=excluded.locator_json",
            (
                evidence_public_id,
                capture_id,
                min(group.frames),
                max(group.frames),
                f"{group.source}->{group.destination}",
                len(group.values),
                "tcp.urgent_pointer",
                text,
                json.dumps(locator, ensure_ascii=False, sort_keys=True),
            ),
        )
        evidence_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public_id,)
            ).fetchone()[0]
        )
        for value in flags:
            public_id = candidate_id("tcp-urgent-flag", value)
            connection.execute(
                "INSERT INTO candidate(candidate_id,kind,raw_value,normalized_value,"
                "confidence,rank_score,created_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(candidate_id) DO UPDATE SET "
                "confidence=max(candidate.confidence,excluded.confidence),"
                "rank_score=max(candidate.rank_score,excluded.rank_score)",
                (public_id, "tcp-urgent-flag", value, value, 0.98, 98.0, _now()),
            )
            candidate_db_id = int(
                connection.execute(
                    "SELECT id FROM candidate WHERE candidate_id=?", (public_id,)
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT OR IGNORE INTO candidate_evidence(candidate_id,evidence_id,role) "
                "VALUES(?,?,?)",
                (candidate_db_id, evidence_db_id, "tcp-urgent-pointer"),
            )
        if printable >= 4 and printable / max(len(group.values), 1) >= 0.8:
            finding_public_id = stable_id(
                "tcp-urgent-finding",
                {"capture_sha256": capture_sha256, "stream": group.stream},
            )
            title = "Printable data in TCP urgent pointers"
            description = (
                f"TCP stream {group.stream} contains {len(group.values)} non-zero urgent pointers; "
                f"the printable reconstruction is {text!r}."
            )
            connection.execute(
                "INSERT INTO finding(finding_id,detector,detector_version,title,description,"
                "severity,confidence,recommended_action,created_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(finding_id) DO UPDATE SET description=excluded.description,"
                "confidence=excluded.confidence,recommended_action=excluded.recommended_action",
                (
                    finding_public_id,
                    DETECTOR,
                    DETECTOR_VERSION,
                    title,
                    description,
                    "high" if flags else "medium",
                    0.98 if flags else 0.82,
                    "Review tcp.urgent_pointer in capture order and verify any flag candidate.",
                    _now(),
                ),
            )
            finding_db_id = int(
                connection.execute(
                    "SELECT id FROM finding WHERE finding_id=?", (finding_public_id,)
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT OR IGNORE INTO finding_evidence(finding_id,evidence_id,role) "
                "VALUES(?,?,?)",
                (finding_db_id, evidence_db_id, "urgent-pointer-sequence"),
            )
    return TcpUrgentGroup(
        stream=group.stream,
        source=group.source,
        destination=group.destination,
        first_frame=min(group.frames),
        last_frame=max(group.frames),
        values=len(group.values),
        printable=printable,
        text=text,
        flags=flags,
        evidence_id=evidence_public_id,
    )


def triage_tcp_urgent(
    project_path: Path,
    tshark: Path,
    *,
    max_frames: int = 100_000,
    max_groups: int = 256,
) -> TcpUrgentSummary:
    if min(max_frames, max_groups) <= 0:
        raise ValueError("TCP urgent limits must be positive")
    project = inspect_project(project_path)
    capabilities = probe_tshark(tshark)
    missing = URGENT_REQUIRED_FIELDS - set(capabilities.fields)
    if not capabilities.usable or missing:
        return TcpUrgentSummary(
            "auto-shark.tcp-urgent-pointer/v1",
            "unavailable",
            0,
            0,
            0,
            0,
            0,
            (),
            ("TShark does not expose tcp.flags.urg and tcp.urgent_pointer",),
        )
    database = Database(project.root / "project.sqlite")
    database.initialize()
    argv = tshark_urgent_arguments(tshark, project.capture_path)
    run_id = uuid4().hex
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,tool_version,argv_json,capability_json,"
            "started_at,status) VALUES(?,?,?,?,?,?,'running')",
            (
                run_id,
                "tshark-tcp-urgent-triage",
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_provenance_json(),
                _now(),
            ),
        )
    groups: dict[tuple[int, str, str], _Group] = {}
    frames_seen = urgent_frames = malformed = 0
    skipped_frame_limit = skipped_group_limit = 0

    def on_line(line: bytes) -> None:
        nonlocal frames_seen, urgent_frames, malformed
        nonlocal skipped_frame_limit, skipped_group_limit
        frames_seen += 1
        if frames_seen > max_frames:
            skipped_frame_limit += 1
            return
        try:
            parsed = parse_urgent_line(line)
        except (UnicodeError, ValueError, TypeError):
            malformed += 1
            return
        if parsed is None:
            return
        frame, stream, source, destination, pointer = parsed
        urgent_frames += 1
        key = (stream, source, destination)
        group = groups.get(key)
        if group is None:
            if len(groups) >= max_groups:
                skipped_group_limit += 1
                return
            group = _Group(stream, source, destination, [], [])
            groups[key] = group
        group.frames.append(frame)
        group.values.append(pointer)

    try:
        result = run_streaming_lines(
            argv,
            on_line,
            timeout_seconds=120,
            max_line_bytes=64 * 1024,
            stderr_limit=256 * 1024,
        )
    except BaseException as error:
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at=?,status='failed',stderr_text=? WHERE run_id=?",
                (_now(), f"{type(error).__name__}: {error}"[:4096], run_id),
            )
        raise
    failed = result.timed_out or result.output_limit_exceeded or result.returncode != 0
    tool_status = (
        "failed"
        if failed
        else "budget-limited"
        if skipped_frame_limit or skipped_group_limit
        else "completed"
    )
    with database.connect() as connection:
        connection.execute(
            "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
            "stderr_truncated=? WHERE run_id=?",
            (
                _now(),
                tool_status,
                result.returncode,
                result.stderr.decode("utf-8", errors="replace"),
                int(result.stderr_truncated),
                run_id,
            ),
        )
    if failed:
        return TcpUrgentSummary(
            "auto-shark.tcp-urgent-pointer/v1",
            "error",
            frames_seen,
            urgent_frames,
            malformed,
            skipped_frame_limit,
            skipped_group_limit,
            (),
            (result.stderr.decode("utf-8", errors="replace")[-1000:],),
        )
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
    persisted = tuple(
        _persist_group(database, capture_id, project.capture_sha256, group)
        for group in sorted(groups.values(), key=lambda item: (min(item.frames), item.stream))
        if group.values
    )
    flags = sum(len(group.flags) for group in persisted)
    hints = (
        "Non-zero TCP urgent pointers were found; inspect the reconstructed text in capture order.",
    ) if urgent_frames else ("No non-zero TCP urgent pointers were observed.",)
    if flags:
        hints += (f"Detected {flags} flag-shaped candidate(s) in urgent-pointer text.",)
    return TcpUrgentSummary(
        "auto-shark.tcp-urgent-pointer/v1",
        "budget-limited" if skipped_frame_limit or skipped_group_limit else "completed",
        frames_seen,
        urgent_frames,
        malformed,
        skipped_frame_limit,
        skipped_group_limit,
        persisted,
        hints,
    )
