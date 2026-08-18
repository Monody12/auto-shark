"""Bounded ICMP echo side-channel triage.

The first supported pattern is a printable IPv4 TTL oracle: a challenge client
tries candidate character values in ``ip.ttl`` and the remote endpoint replies
only when a guess is accepted. The detector requires both printable variation
and selective replies, so ordinary constant-TTL ping traffic stays
inconclusive.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from uuid import uuid4

from .core.ids import stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import probe_tshark
from .project import inspect_project
from .storage import Database

ICMP_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "icmp.type",
    "icmp.code",
    "icmp.ident",
    "icmp.seq",
    "icmp.resp_to",
)
ICMP_REQUIRED_FIELDS = frozenset(ICMP_FIELDS)
DETECTOR = "icmp-ttl-oracle"
DETECTOR_VERSION = "auto-shark.icmp-triage/v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class IcmpEchoPacket:
    frame: int
    timestamp: float
    source: str
    destination: str
    ttl: int
    message_type: int
    code: int
    identifier: int | None
    sequence: int | None
    response_to: int | None


@dataclass(frozen=True)
class IcmpRouteResult:
    source: str
    destination: str
    first_frame: int
    last_frame: int
    requests: int
    replies: int
    unanswered: int
    unique_ttls: int
    printable_ttls: int
    score: int
    classification: str
    attempt_text: str
    response_bitmap: str
    accepted_text: str
    evidence_id: str | None


@dataclass(frozen=True)
class IcmpTriageSummary:
    schema_version: str
    project: str
    status: str
    packets_seen: int
    requests_seen: int
    replies_seen: int
    malformed_rows: int
    skipped_packet_limit: int
    skipped_route_limit: int
    routes: tuple[IcmpRouteResult, ...]
    hints: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _optional_int(value: str) -> int | None:
    return int(value, 0) if value else None


def parse_icmp_line(line: bytes) -> IcmpEchoPacket:
    rows = list(
        csv.reader(
            StringIO(line.decode("utf-8", errors="strict")),
            delimiter="\t",
            quotechar='"',
        )
    )
    if len(rows) != 1 or len(rows[0]) != len(ICMP_FIELDS):
        raise ValueError("invalid ICMP field row")
    values = dict(zip(ICMP_FIELDS, rows[0]))
    required = (
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "ip.ttl",
        "icmp.type",
        "icmp.code",
    )
    if any(not values[name] for name in required):
        raise ValueError("ICMP row lacks a required echo field")
    message_type = int(values["icmp.type"], 0)
    if message_type not in {0, 8}:
        raise ValueError("ICMP row is not an echo request or reply")
    return IcmpEchoPacket(
        frame=int(values["frame.number"]),
        timestamp=float(values["frame.time_epoch"]),
        source=values["ip.src"],
        destination=values["ip.dst"],
        ttl=int(values["ip.ttl"], 0),
        message_type=message_type,
        code=int(values["icmp.code"], 0),
        identifier=_optional_int(values["icmp.ident"]),
        sequence=_optional_int(values["icmp.seq"]),
        response_to=_optional_int(values["icmp.resp_to"]),
    )


def tshark_icmp_arguments(executable: Path, capture: Path) -> list[str]:
    arguments = [
        str(executable),
        "-r",
        str(capture),
        "-Y",
        "icmp && (icmp.type == 8 || icmp.type == 0)",
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
    for field in ICMP_FIELDS:
        arguments.extend(("-e", field))
    return arguments


def _ttl_char(ttl: int) -> str:
    return chr(ttl) if 32 <= ttl <= 126 else "."


def _oracle_score(requests: list[IcmpEchoPacket], replied: set[int]) -> int:
    printable = sum(32 <= packet.ttl <= 126 for packet in requests)
    unique = len({packet.ttl for packet in requests})
    replies = sum(packet.frame in replied for packet in requests)
    unanswered = len(requests) - replies
    if (
        len(requests) < 8
        or printable / len(requests) < 0.9
        or unique < 4
        or replies < 2
        or unanswered < 2
    ):
        return 0
    score = 40
    score += 20 if printable == len(requests) else 15
    score += 15
    score += 10
    score += 15
    return min(score, 100)


def _persist_route(
    database: Database,
    capture_id: int,
    capture_sha256: str,
    requests: list[IcmpEchoPacket],
    reply_by_request: dict[int, int],
    *,
    max_preview_attempts: int,
) -> IcmpRouteResult:
    replied = set(reply_by_request)
    printable = sum(32 <= packet.ttl <= 126 for packet in requests)
    unique = len({packet.ttl for packet in requests})
    reply_count = sum(packet.frame in replied for packet in requests)
    unanswered = len(requests) - reply_count
    score = _oracle_score(requests, replied)
    classification = (
        "printable-ttl-selective-replies" if score else "ordinary-or-inconclusive"
    )
    preview = requests[:max_preview_attempts]
    attempt_text = "".join(_ttl_char(packet.ttl) for packet in preview)
    response_bitmap = "".join("1" if packet.frame in replied else "0" for packet in preview)
    accepted_text = "".join(
        _ttl_char(packet.ttl) for packet in preview if packet.frame in replied
    )
    evidence_public_id: str | None = None
    if score:
        identity = {
            "capture_sha256": capture_sha256,
            "detector": DETECTOR_VERSION,
            "source": requests[0].source,
            "destination": requests[0].destination,
        }
        evidence_public_id = stable_id("icmp-echo-probe-series-evidence", identity)
        attempts = [
            {
                "char": _ttl_char(packet.ttl),
                "frame": packet.frame,
                "identifier": packet.identifier,
                "reply_frame": reply_by_request.get(packet.frame),
                "sequence": packet.sequence,
                "ttl": packet.ttl,
            }
            for packet in preview
        ]
        locator = {
            **identity,
            "accepted_text": accepted_text,
            "attempt_text": attempt_text,
            "attempts": attempts,
            "classification": classification,
            "preview_truncated": len(requests) > len(preview),
            "replies": reply_count,
            "response_bitmap": response_bitmap,
            "score": score,
            "unanswered": unanswered,
            "unique_ttls": unique,
        }
        with database.connect() as connection:
            connection.execute(
                "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
                "direction,byte_offset,byte_length,field_name,text_value,locator_json) "
                "VALUES(?,?,'icmp-echo-probe-series',?,?,?,0,?,'ip.ttl',?,?) "
                "ON CONFLICT(evidence_id) DO UPDATE SET frame_start=excluded.frame_start,"
                "frame_end=excluded.frame_end,byte_length=excluded.byte_length,"
                "text_value=excluded.text_value,locator_json=excluded.locator_json",
                (
                    evidence_public_id,
                    capture_id,
                    min(packet.frame for packet in requests),
                    max(packet.frame for packet in requests),
                    f"{requests[0].source}->{requests[0].destination}",
                    len(requests),
                    attempt_text,
                    json.dumps(locator, ensure_ascii=False, sort_keys=True),
                ),
            )
            evidence_db_id = int(
                connection.execute(
                    "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public_id,)
                ).fetchone()[0]
            )
            finding_public_id = stable_id("icmp-ttl-oracle-finding", identity)
            description = (
                f"ICMP echo route {requests[0].source} -> {requests[0].destination} has "
                f"{len(requests)} requests with printable TTL attempts {attempt_text!r}; "
                f"{reply_count} received replies and {unanswered} did not. Explicit TShark "
                f"request/reply references yield accepted-value preview {accepted_text!r}."
            )
            action = (
                "Interpret ip.ttl as candidate ASCII only after verifying the explicit echo "
                "reply mapping. Treat replied values as accepted oracle guesses; a partial "
                "capture cannot prove omitted prefix or suffix characters."
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
                    "Printable TTL values with selective ICMP echo replies",
                    description,
                    "high",
                    0.92,
                    action,
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
                "VALUES(?,?,'icmp-ttl-probe-series')",
                (finding_db_id, evidence_db_id),
            )
    return IcmpRouteResult(
        source=requests[0].source,
        destination=requests[0].destination,
        first_frame=min(packet.frame for packet in requests),
        last_frame=max(packet.frame for packet in requests),
        requests=len(requests),
        replies=reply_count,
        unanswered=unanswered,
        unique_ttls=unique,
        printable_ttls=printable,
        score=score,
        classification=classification,
        attempt_text=attempt_text,
        response_bitmap=response_bitmap,
        accepted_text=accepted_text,
        evidence_id=evidence_public_id,
    )


def triage_icmp(
    project_path: Path,
    tshark: Path,
    *,
    max_packets: int = 100_000,
    max_routes: int = 256,
    max_preview_attempts: int = 256,
) -> IcmpTriageSummary:
    if min(max_packets, max_routes, max_preview_attempts) <= 0:
        raise ValueError("ICMP triage limits must be positive")
    project = inspect_project(project_path)
    capabilities = probe_tshark(tshark)
    missing = ICMP_REQUIRED_FIELDS - set(capabilities.fields)
    if not capabilities.usable or missing:
        return IcmpTriageSummary(
            DETECTOR_VERSION,
            str(project.root),
            "unavailable",
            0,
            0,
            0,
            0,
            0,
            0,
            (),
            ("TShark does not expose the required IPv4 ICMP echo fields.",),
        )

    database = Database(project.root / "project.sqlite")
    database.initialize()
    argv = tshark_icmp_arguments(tshark, project.capture_path)
    run_id = uuid4().hex
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,tool_version,argv_json,capability_json,"
            "started_at,status) VALUES(?,?,?,?,?,?,'running')",
            (
                run_id,
                "tshark-icmp-triage",
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_provenance_json(),
                _now(),
            ),
        )

    packets: list[IcmpEchoPacket] = []
    packets_seen = malformed = skipped_packet_limit = 0

    def on_line(line: bytes) -> None:
        nonlocal packets_seen, malformed, skipped_packet_limit
        packets_seen += 1
        if packets_seen > max_packets:
            skipped_packet_limit += 1
            return
        try:
            packets.append(parse_icmp_line(line))
        except (UnicodeError, ValueError, TypeError):
            malformed += 1

    try:
        process = run_streaming_lines(
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
    process_failed = (
        process.timed_out or process.output_limit_exceeded or process.returncode != 0
    )
    tool_status = (
        "failed" if process_failed else "budget-limited" if skipped_packet_limit else "completed"
    )
    with database.connect() as connection:
        connection.execute(
            "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
            "stderr_truncated=? WHERE run_id=?",
            (
                _now(),
                tool_status,
                process.returncode,
                process.stderr.decode("utf-8", errors="replace"),
                int(process.stderr_truncated),
                run_id,
            ),
        )
    if process_failed:
        return IcmpTriageSummary(
            DETECTOR_VERSION,
            str(project.root),
            "error",
            packets_seen,
            sum(packet.message_type == 8 for packet in packets),
            sum(packet.message_type == 0 for packet in packets),
            malformed,
            skipped_packet_limit,
            0,
            (),
            (process.stderr.decode("utf-8", errors="replace")[-1000:],),
        )

    requests = [packet for packet in packets if packet.message_type == 8]
    replies = [packet for packet in packets if packet.message_type == 0]
    reply_by_request = {
        packet.response_to: packet.frame
        for packet in replies
        if packet.response_to is not None
    }
    grouped: dict[tuple[str, str], list[IcmpEchoPacket]] = {}
    skipped_route_limit = 0
    for packet in requests:
        key = (packet.source, packet.destination)
        if key not in grouped and len(grouped) >= max_routes:
            skipped_route_limit += 1
            continue
        grouped.setdefault(key, []).append(packet)

    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
    routes = tuple(
        _persist_route(
            database,
            capture_id,
            project.capture_sha256,
            route,
            reply_by_request,
            max_preview_attempts=max_preview_attempts,
        )
        for route in sorted(grouped.values(), key=lambda items: min(item.frame for item in items))
    )
    suspicious = sum(route.score > 0 for route in routes)
    status = "budget-limited" if skipped_packet_limit or skipped_route_limit else "completed"
    if suspicious:
        hints = (
            f"Found {suspicious} ICMP route(s) with printable TTL guesses and selective replies.",
            "Use explicit request/reply frame references; do not infer uncaptured oracle steps.",
        )
    else:
        hints = ("No high-confidence printable-TTL echo oracle was found.",)
    return IcmpTriageSummary(
        DETECTOR_VERSION,
        str(project.root),
        status,
        packets_seen,
        len(requests),
        len(replies),
        malformed,
        skipped_packet_limit,
        skipped_route_limit,
        routes,
        hints,
    )
