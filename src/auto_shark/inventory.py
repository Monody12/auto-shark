"""Bounded capture inventory and derived analysis coverage."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .core.ids import stable_id
from .engines.stream import StreamProcessResult, run_streaming_lines
from .engines.tshark import TsharkCapabilities, probe_tshark
from .project import inspect_project
from .protocols.inventory import (
    INVENTORY_REQUIRED_FIELDS,
    InventoryRow,
    parse_inventory_line,
    selected_inventory_fields,
    tshark_inventory_arguments,
)
from .storage import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class InventorySummary:
    project: str
    schema_version: str
    inventory_run_id: str
    status: str
    processed_frames: int
    skipped_frames: int
    skipped_conversations: int
    skipped_protocol_labels: int
    protocol_observations: int
    conversation_profiles: int
    coverage: dict[str, int]
    multipart_parts: int = 0
    findings: int = 0
    manual_tasks: int = 0
    manual_signals: int = 0

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


@dataclass
class _ConversationAggregate:
    transport: str
    stream_index: int
    endpoint_a: str
    endpoint_b: str
    first_frame: int
    last_frame: int
    first_time: str
    last_time: str
    frame_count: int = 0
    captured_bytes: int = 0
    wire_bytes: int = 0
    payload_bytes: int = 0
    labels: set[str] = field(default_factory=set)
    initiator: Optional[str] = None
    responder: Optional[str] = None

    def add(self, row: InventoryRow) -> None:
        self.last_frame = row.frame_number
        self.last_time = row.time_epoch
        self.frame_count += 1
        self.captured_bytes += row.captured_length
        self.wire_bytes += row.frame_length
        self.payload_bytes += row.payload_length or 0
        self.labels.update(row.protocols)
        if self.transport == "tcp" and row.syn and not row.ack and self.initiator is None:
            self.initiator = _endpoint(row.source, row.source_port)
            self.responder = _endpoint(row.destination, row.destination_port)


class _FrameLimitReached(ValueError):
    pass


def _endpoint(address: Optional[str], port: Optional[int]) -> str:
    if address is None:
        return ""
    return f"{address}:{port}" if port is not None else address


def derive_coverage_status(
    *,
    capability_available: bool,
    analyzer_status: Optional[str] = None,
    reconstruction_status: Optional[str] = None,
    budget_limited: bool = False,
) -> str:
    if not capability_available:
        return "unavailable"
    if analyzer_status == "failed":
        return "failed"
    if budget_limited:
        return "budget-limited"
    incomplete = {"partial", "truncated", "conflicting"}
    if analyzer_status in incomplete or reconstruction_status in incomplete:
        return "partial"
    if analyzer_status == "complete" or reconstruction_status == "complete":
        return "complete"
    return "not-run"


class _InventoryAccumulator:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        capture_id: int,
        inventory_run_id: int,
        max_frames: int,
        max_protocol_labels: int,
        max_conversations: int,
    ) -> None:
        self.connection = connection
        self.capture_id = capture_id
        self.inventory_run_id = inventory_run_id
        self.max_frames = max_frames
        self.max_protocol_labels = max_protocol_labels
        self.max_conversations = max_conversations
        self.processed_frames = 0
        self.skipped_frames = 0
        self.skipped_protocol_labels = 0
        self.protocol_counts: Counter[str] = Counter()
        self.protocol_ranges: dict[str, tuple[int, int]] = {}
        self.conversations: dict[tuple[str, int], _ConversationAggregate] = {}
        self.rejected_conversations: set[tuple[str, int]] = set()

    @property
    def skipped_conversations(self) -> int:
        return len(self.rejected_conversations)

    def _skip(
        self,
        scope: str,
        reason: str,
        *,
        frame_number: Optional[int] = None,
        protocol: Optional[str] = None,
        stream_index: Optional[int] = None,
        detail: Optional[dict[str, object]] = None,
    ) -> None:
        row = self.connection.execute(
            "SELECT id,count FROM inventory_skip "
            "WHERE inventory_run_id=? AND scope=? AND frame_number IS ? "
            "AND protocol IS ? AND stream_index IS ? AND reason=?",
            (
                self.inventory_run_id,
                scope,
                frame_number,
                protocol,
                stream_index,
                reason,
            ),
        ).fetchone()
        detail_json = json.dumps(detail or {}, sort_keys=True)
        if row is None:
            self.connection.execute(
                "INSERT INTO inventory_skip "
                "(inventory_run_id,scope,frame_number,protocol,stream_index,reason,"
                "count,detail_json) VALUES(?,?,?,?,?,?,1,?)",
                (
                    self.inventory_run_id,
                    scope,
                    frame_number,
                    protocol,
                    stream_index,
                    reason,
                    detail_json,
                ),
            )
        else:
            self.connection.execute(
                "UPDATE inventory_skip SET count=count+1,detail_json=? WHERE id=?",
                (detail_json, int(row["id"])),
            )

    def record_frame_limit(self) -> None:
        self.skipped_frames += 1
        self._skip(
            "frame",
            "frame-limit",
            detail={"max_frames": self.max_frames},
        )

    def add(self, row: InventoryRow) -> None:
        if self.processed_frames >= self.max_frames:
            raise _FrameLimitReached("inventory frame limit reached")
        self.processed_frames += 1
        self.connection.execute(
            "INSERT OR IGNORE INTO frame "
            "(capture_id,frame_number,time_epoch,captured_length,original_length) "
            "VALUES(?,?,?,?,?)",
            (
                self.capture_id,
                row.frame_number,
                row.time_epoch,
                row.captured_length,
                row.frame_length,
            ),
        )
        for label in row.protocols:
            if label not in self.protocol_counts and len(self.protocol_counts) >= (
                self.max_protocol_labels
            ):
                self.skipped_protocol_labels += 1
                self._skip(
                    "protocol-label",
                    "label-limit",
                    protocol=label,
                    detail={"max_protocol_labels": self.max_protocol_labels},
                )
                continue
            self.protocol_counts[label] += 1
            first, _ = self.protocol_ranges.get(label, (row.frame_number, row.frame_number))
            self.protocol_ranges[label] = (first, row.frame_number)

        if row.transport is None:
            return
        if (
            row.stream_index is None
            or not row.source
            or not row.destination
            or row.source_port is None
            or row.destination_port is None
        ):
            self.skipped_frames += 1
            self._skip(
                "frame",
                "missing-conversation-fields",
                frame_number=row.frame_number,
                protocol=row.transport,
                stream_index=row.stream_index,
            )
            return
        key = (row.transport, row.stream_index)
        aggregate = self.conversations.get(key)
        if aggregate is None:
            if key in self.rejected_conversations:
                self._skip(
                    "conversation",
                    "conversation-limit",
                    protocol=row.transport,
                    stream_index=row.stream_index,
                    detail={"max_conversations": self.max_conversations},
                )
                return
            if len(self.conversations) >= self.max_conversations:
                self.rejected_conversations.add(key)
                self._skip(
                    "conversation",
                    "conversation-limit",
                    protocol=row.transport,
                    stream_index=row.stream_index,
                    detail={"max_conversations": self.max_conversations},
                )
                return
            aggregate = _ConversationAggregate(
                transport=row.transport,
                stream_index=row.stream_index,
                endpoint_a=_endpoint(row.source, row.source_port),
                endpoint_b=_endpoint(row.destination, row.destination_port),
                first_frame=row.frame_number,
                last_frame=row.frame_number,
                first_time=row.time_epoch,
                last_time=row.time_epoch,
            )
            self.conversations[key] = aggregate
        aggregate.add(row)


def _persist_inventory(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    capture_sha256: str,
    inventory_run_id: int,
    accumulator: _InventoryAccumulator,
) -> None:
    updated_at = _now()
    for label, count in accumulator.protocol_counts.items():
        first_frame, last_frame = accumulator.protocol_ranges[label]
        public_id = stable_id(
            "protocol-observation",
            {"capture_sha256": capture_sha256, "protocol_label": label},
        )
        connection.execute(
            "INSERT INTO protocol_observation "
            "(observation_id,capture_id,protocol_label,frame_count,first_frame,last_frame,"
            "inventory_run_id,updated_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(capture_id,protocol_label) DO UPDATE SET "
            "frame_count=excluded.frame_count,first_frame=excluded.first_frame,"
            "last_frame=excluded.last_frame,inventory_run_id=excluded.inventory_run_id,"
            "updated_at=excluded.updated_at",
            (
                public_id,
                capture_id,
                label,
                count,
                first_frame,
                last_frame,
                inventory_run_id,
                updated_at,
            ),
        )

    for aggregate in accumulator.conversations.values():
        public_id = stable_id(
            "conversation-profile",
            {
                "capture_sha256": capture_sha256,
                "protocol": aggregate.transport,
                "stream_index": aggregate.stream_index,
            },
        )
        values = (
            public_id,
            capture_id,
            aggregate.transport,
            aggregate.stream_index,
            aggregate.endpoint_a,
            aggregate.endpoint_b,
            aggregate.initiator,
            aggregate.responder,
            aggregate.first_frame,
            aggregate.last_frame,
            aggregate.first_time,
            aggregate.last_time,
            aggregate.frame_count,
            aggregate.captured_bytes,
            aggregate.wire_bytes,
            aggregate.payload_bytes,
            json.dumps(sorted(aggregate.labels)),
            updated_at,
        )
        connection.execute(
            "INSERT INTO conversation_profile "
            "(profile_id,capture_id,protocol,stream_index,endpoint_a,endpoint_b,"
            "initiator_endpoint,responder_endpoint,first_frame,last_frame,first_time,"
            "last_time,frame_count,captured_bytes,wire_bytes,payload_bytes,"
            "protocol_labels_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(capture_id,protocol,stream_index) DO UPDATE SET "
            "endpoint_a=excluded.endpoint_a,endpoint_b=excluded.endpoint_b,"
            "initiator_endpoint=excluded.initiator_endpoint,"
            "responder_endpoint=excluded.responder_endpoint,"
            "first_frame=excluded.first_frame,last_frame=excluded.last_frame,"
            "first_time=excluded.first_time,last_time=excluded.last_time,"
            "frame_count=excluded.frame_count,captured_bytes=excluded.captured_bytes,"
            "wire_bytes=excluded.wire_bytes,payload_bytes=excluded.payload_bytes,"
            "protocol_labels_json=excluded.protocol_labels_json,"
            "updated_at=excluded.updated_at",
            values,
        )
        profile_id = int(
            connection.execute(
                "SELECT id FROM conversation_profile WHERE profile_id=?",
                (public_id,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO conversation_profile_run "
            "(profile_id,inventory_run_id) VALUES(?,?)",
            (profile_id, inventory_run_id),
        )


def _protocol_analyzer_status(
    connection: sqlite3.Connection, capture_id: int, label: str
) -> Optional[str]:
    if label == "telnet":
        rows = connection.execute(
            "SELECT status FROM telnet_dialogue WHERE capture_id=?",
            (capture_id,),
        ).fetchall()
    elif label in {"ftp", "ftp-data"}:
        rows = connection.execute(
            "SELECT status FROM ftp_transfer WHERE capture_id=?",
            (capture_id,),
        ).fetchall()
    elif label == "http":
        count = int(
            connection.execute(
                "SELECT count(*) FROM protocol_message WHERE capture_id=? AND protocol='http'",
                (capture_id,),
            ).fetchone()[0]
        )
        return "complete" if count else None
    else:
        return None
    states = {str(row["status"]) for row in rows}
    if not states:
        return None
    if "failed" in states:
        return "failed"
    if states & {"partial", "truncated", "conflicting", "skipped-budget"}:
        return "partial"
    return "complete" if states <= {"complete"} else None


def _capability_available(capabilities: TsharkCapabilities, label: str) -> bool:
    feature = {"ftp-data": "ftp", "mime_multipart": "multipart"}.get(label, label)
    if label in {"frame", "eth", "ethertype", "ip", "ipv6", "tcp", "udp"}:
        return True
    return bool(capabilities.features.get(feature, False))


def _write_coverage(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    capture_sha256: str,
    inventory_run_public_id: str,
    capabilities: TsharkCapabilities,
    inventory_status: str,
) -> Counter[str]:
    counts: Counter[str] = Counter()
    budget_limited = inventory_status == "budget-limited"
    observations = connection.execute(
        "SELECT observation_id,protocol_label FROM protocol_observation WHERE capture_id=?",
        (capture_id,),
    ).fetchall()
    for row in observations:
        label = str(row["protocol_label"])
        analyzer_status = _protocol_analyzer_status(connection, capture_id, label)
        available = _capability_available(capabilities, label)
        status = derive_coverage_status(
            capability_available=available,
            analyzer_status=analyzer_status,
            budget_limited=budget_limited,
        )
        _upsert_coverage(
            connection,
            capture_id=capture_id,
            capture_sha256=capture_sha256,
            subject_kind="protocol",
            subject_id=str(row["observation_id"]),
            status=status,
            detail={
                "analyzer_status": analyzer_status,
                "capability_available": available,
                "inventory_run_id": inventory_run_public_id,
                "protocol_label": label,
            },
        )
        counts[status] += 1

    profiles = connection.execute(
        "SELECT profile_id,protocol,stream_index FROM conversation_profile "
        "WHERE capture_id=?",
        (capture_id,),
    ).fetchall()
    for row in profiles:
        reconstruction_status = None
        if row["protocol"] == "tcp":
            states = {
                str(item["status"])
                for item in connection.execute(
                    "SELECT tr.status FROM tcp_reconstruction tr "
                    "JOIN conversation c ON c.id=tr.conversation_id "
                    "WHERE c.capture_id=? AND c.protocol='tcp' AND c.stream_index=?",
                    (capture_id, row["stream_index"]),
                )
            }
            if states:
                reconstruction_status = (
                    "partial"
                    if states & {"partial", "truncated", "conflicting"}
                    else "complete"
                    if states <= {"complete", "empty"}
                    else None
                )
        status = derive_coverage_status(
            capability_available=True,
            reconstruction_status=reconstruction_status,
            budget_limited=budget_limited,
        )
        _upsert_coverage(
            connection,
            capture_id=capture_id,
            capture_sha256=capture_sha256,
            subject_kind="conversation",
            subject_id=str(row["profile_id"]),
            status=status,
            detail={
                "inventory_run_id": inventory_run_public_id,
                "protocol": str(row["protocol"]),
                "reconstruction_status": reconstruction_status,
                "stream_index": int(row["stream_index"]),
            },
        )
        counts[status] += 1
    return counts


def _upsert_coverage(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    capture_sha256: str,
    subject_kind: str,
    subject_id: str,
    status: str,
    detail: dict[str, object],
) -> None:
    public_id = stable_id(
        "analysis-coverage",
        {
            "capture_sha256": capture_sha256,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
        },
    )
    connection.execute(
        "INSERT INTO analysis_coverage "
        "(coverage_id,capture_id,subject_kind,subject_id,status,detail_json,updated_at) "
        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(capture_id,subject_kind,subject_id) "
        "DO UPDATE SET status=excluded.status,detail_json=excluded.detail_json,"
        "updated_at=excluded.updated_at",
        (
            public_id,
            capture_id,
            subject_kind,
            subject_id,
            status,
            json.dumps(detail, sort_keys=True),
            _now(),
        ),
    )


def index_summary(
    project_path: Path,
    tshark: Path,
    *,
    max_frames: int = 100_000,
    max_protocol_labels: int = 256,
    max_conversations: int = 10_000,
    max_parts: int = 10_000,
    max_body_scan_bytes: int = 4 * 1024 * 1024,
    max_tasks: int = 10_000,
    max_signals: int = 50_000,
    max_evidence_links: int = 100_000,
    max_unsupported_tasks: int = 25,
) -> InventorySummary:
    if min(
        max_frames,
        max_protocol_labels,
        max_conversations,
        max_parts,
        max_body_scan_bytes,
        max_tasks,
        max_signals,
        max_evidence_links,
        max_unsupported_tasks,
    ) <= 0:
        raise ValueError("inventory limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    capabilities = probe_tshark(tshark)
    missing = INVENTORY_REQUIRED_FIELDS - set(capabilities.fields)
    if not capabilities.usable or missing:
        detail = ", ".join(sorted(missing))
        raise ValueError(f"TShark lacks required inventory fields: {detail}")
    selected_fields = selected_inventory_fields(set(capabilities.fields))
    argv = tshark_inventory_arguments(
        str(tshark),
        str(project.capture_path),
        selected_fields,
    )
    inventory_run_public_id = uuid4().hex
    tool_run_public_id = uuid4().hex
    started_at = _now()
    policy = {
        "max_conversations": max_conversations,
        "max_frames": max_frames,
        "max_protocol_labels": max_protocol_labels,
    }
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?",
                (project.capture_sha256,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO tool_run "
            "(run_id,tool_name,tool_version,argv_json,capability_json,started_at,status) "
            "VALUES(?,?,?,?,?,?,'running')",
            (
                tool_run_public_id,
                "tshark",
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_provenance_json(),
                started_at,
            ),
        )
        tool_run_id = int(
            connection.execute(
                "SELECT id FROM tool_run WHERE run_id=?",
                (tool_run_public_id,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO capture_inventory_run "
            "(inventory_run_id,capture_id,tool_run_id,policy_json,status,"
            "processed_frames,skipped_frames,skipped_conversations,"
            "skipped_protocol_labels,started_at) "
            "VALUES(?,?,?,?,'partial',0,0,0,0,?)",
            (
                inventory_run_public_id,
                capture_id,
                tool_run_id,
                json.dumps(policy, sort_keys=True),
                started_at,
            ),
        )
        inventory_run_id = int(
            connection.execute(
                "SELECT id FROM capture_inventory_run WHERE inventory_run_id=?",
                (inventory_run_public_id,),
            ).fetchone()[0]
        )

    result: Optional[StreamProcessResult] = None
    inventory_status = "completed"
    error_text = ""
    with database.connect() as connection:
        accumulator = _InventoryAccumulator(
            connection,
            capture_id=capture_id,
            inventory_run_id=inventory_run_id,
            max_frames=max_frames,
            max_protocol_labels=max_protocol_labels,
            max_conversations=max_conversations,
        )
        try:
            result = run_streaming_lines(
                argv,
                lambda line: accumulator.add(parse_inventory_line(line, selected_fields)),
                timeout_seconds=300,
                max_line_bytes=1024 * 1024,
                stderr_limit=512 * 1024,
            )
            if result.timed_out:
                inventory_status = "failed"
                error_text = "TShark inventory timed out"
            elif result.output_limit_exceeded:
                inventory_status = "budget-limited"
                error_text = "TShark inventory line limit exceeded"
            elif result.returncode != 0:
                inventory_status = "failed"
                error_text = f"TShark inventory exited {result.returncode}"
        except _FrameLimitReached as error:
            accumulator.record_frame_limit()
            inventory_status = "budget-limited"
            error_text = str(error)

        _persist_inventory(
            connection,
            capture_id=capture_id,
            capture_sha256=project.capture_sha256,
            inventory_run_id=inventory_run_id,
            accumulator=accumulator,
        )
        coverage = _write_coverage(
            connection,
            capture_id=capture_id,
            capture_sha256=project.capture_sha256,
            inventory_run_public_id=inventory_run_public_id,
            capabilities=capabilities,
            inventory_status=inventory_status,
        )
        ended_at = _now()
        connection.execute(
            "UPDATE capture_inventory_run SET status=?,processed_frames=?,"
            "skipped_frames=?,skipped_conversations=?,skipped_protocol_labels=?,"
            "ended_at=? WHERE id=?",
            (
                inventory_status,
                accumulator.processed_frames,
                accumulator.skipped_frames,
                accumulator.skipped_conversations,
                accumulator.skipped_protocol_labels,
                ended_at,
                inventory_run_id,
            ),
        )
        stderr = result.stderr.decode("utf-8", errors="replace") if result else error_text
        connection.execute(
            "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
            "stderr_truncated=? WHERE id=?",
            (
                ended_at,
                "completed" if inventory_status == "completed" else inventory_status,
                result.returncode if result else None,
                stderr,
                int(result.stderr_truncated) if result else 0,
                tool_run_id,
            ),
        )
        observation_count = int(
            connection.execute(
                "SELECT count(*) FROM protocol_observation WHERE capture_id=?",
                (capture_id,),
            ).fetchone()[0]
        )
        profile_count = int(
            connection.execute(
                "SELECT count(*) FROM conversation_profile WHERE capture_id=?",
                (capture_id,),
            ).fetchone()[0]
        )
    multipart_parts = findings = manual_tasks = manual_signals = 0
    if inventory_status == "completed":
        from .findings import index_multipart_findings
        from .manual_queue import rebuild_manual_queue

        finding_summary = index_multipart_findings(
            project.root,
            tshark,
            max_parts=max_parts,
            max_body_scan_bytes=max_body_scan_bytes,
        )
        multipart_parts = finding_summary.multipart_parts
        findings = (
            finding_summary.type_mismatch_findings
            + finding_summary.contradiction_findings
        )
        rebuild_manual_queue(
            project.root,
            max_tasks=max_tasks,
            max_signals=max_signals,
            max_evidence_links=max_evidence_links,
            max_unsupported_tasks=max_unsupported_tasks,
        )
        with Database(project.root / "project.sqlite").connect() as summary_connection:
            manual_tasks = int(
                summary_connection.execute(
                    "SELECT count(*) FROM manual_task WHERE capture_id=?", (capture_id,)
                ).fetchone()[0]
            )
            manual_signals = int(
                summary_connection.execute(
                    "SELECT count(*) FROM manual_task_signal mts "
                    "JOIN manual_task mt ON mt.id=mts.task_id WHERE mt.capture_id=?",
                    (capture_id,),
                ).fetchone()[0]
            )
            findings = int(
                summary_connection.execute(
                    "SELECT count(DISTINCT f.id) FROM finding f "
                    "JOIN finding_evidence fe ON fe.finding_id=f.id "
                    "JOIN evidence e ON e.id=fe.evidence_id WHERE e.capture_id=?",
                    (capture_id,),
                ).fetchone()[0]
            )
            multipart_parts = int(
                summary_connection.execute(
                    "SELECT count(*) FROM multipart_part mp "
                    "JOIN protocol_message pm ON pm.id=mp.protocol_message_id "
                    "WHERE pm.capture_id=?",
                    (capture_id,),
                ).fetchone()[0]
            )
    return InventorySummary(
        project=str(project.root),
        schema_version="auto-shark.summary/v1",
        inventory_run_id=inventory_run_public_id,
        status=inventory_status,
        processed_frames=accumulator.processed_frames,
        skipped_frames=accumulator.skipped_frames,
        skipped_conversations=accumulator.skipped_conversations,
        skipped_protocol_labels=accumulator.skipped_protocol_labels,
        protocol_observations=observation_count,
        conversation_profiles=profile_count,
        coverage=dict(sorted(coverage.items())),
        multipart_parts=multipart_parts,
        findings=findings,
        manual_tasks=manual_tasks,
        manual_signals=manual_signals,
    )
