"""Bounded reconstruction and triage of generic TCP data streams."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .core.ids import stable_id
from .engines.tshark import probe_tshark
from .inventory import index_summary
from .manual_queue import rebuild_manual_queue
from .project import inspect_project
from .storage import Database
from .tcp import reconstruct_tcp_stream
from .triage import triage_project

GENERIC_TCP_LABELS = frozenset(
    {
        "data",
        "eth",
        "ethertype",
        "ip",
        "ipv6",
        "linux-sll",
        "null",
        "sll",
        "sll2",
        "tcp",
        "tcp.segments",
        "vlan",
    }
)


@dataclass(frozen=True)
class TcpTextStreamResult:
    stream_index: int
    estimated_payload_bytes: int
    status: str
    output_bytes: int
    directions: int
    error: str = ""


@dataclass(frozen=True)
class TcpTextTriageSummary:
    schema_version: str
    project: str
    inventory_refreshed: bool
    profiles_discovered: int
    eligible_streams: int
    excluded_streams: int
    selected_streams: int
    reconstructed_streams: int
    partial_streams: int
    truncated_streams: int
    skipped_budget: int
    skipped_limit: int
    failed_streams: int
    coverage_status: str
    estimated_payload_bytes: int
    output_bytes: int
    known_matches: int
    candidate_values: tuple[str, ...]
    streams: tuple[TcpTextStreamResult, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


def _profiles(database: Database) -> list[dict[str, object]]:
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        rows = connection.execute(
            "SELECT stream_index,payload_bytes,protocol_labels_json "
            "FROM conversation_profile WHERE capture_id=? AND protocol='tcp' "
            "AND payload_bytes>0 ORDER BY payload_bytes,stream_index",
            (capture_id,),
        ).fetchall()
    return [
        {
            "stream_index": int(row["stream_index"]),
            "payload_bytes": int(row["payload_bytes"]),
            "labels": frozenset(
                str(item).lower() for item in json.loads(row["protocol_labels_json"])
            ),
        }
        for row in rows
    ]


def _is_generic_data_profile(profile: dict[str, object]) -> bool:
    labels = profile["labels"]
    return isinstance(labels, frozenset) and "data" in labels and labels <= GENERIC_TCP_LABELS


def _update_data_coverage(
    database: Database,
    capture_sha256: str,
    *,
    status: str,
    eligible_streams: int,
    reconstructed_streams: int,
    partial_streams: int,
    truncated_streams: int,
    skipped_budget: int,
    skipped_limit: int,
    failed_streams: int,
) -> None:
    with database.connect() as connection:
        row = connection.execute(
            "SELECT po.observation_id,po.capture_id FROM protocol_observation po "
            "WHERE po.protocol_label='data'"
        ).fetchone()
        if row is None:
            return
        subject_id = str(row["observation_id"])
        coverage_id = stable_id(
            "analysis-coverage",
            {
                "capture_sha256": capture_sha256,
                "subject_kind": "protocol",
                "subject_id": subject_id,
            },
        )
        detail = {
            "analyzer": "tcp-text",
            "eligible_streams": eligible_streams,
            "failed_streams": failed_streams,
            "partial_streams": partial_streams,
            "protocol_label": "data",
            "reconstructed_streams": reconstructed_streams,
            "skipped_budget": skipped_budget,
            "skipped_limit": skipped_limit,
            "truncated_streams": truncated_streams,
        }
        connection.execute(
            "INSERT INTO analysis_coverage "
            "(coverage_id,capture_id,subject_kind,subject_id,status,detail_json,updated_at) "
            "VALUES(?,?,'protocol',?,?,?,?) "
            "ON CONFLICT(capture_id,subject_kind,subject_id) DO UPDATE SET "
            "status=excluded.status,detail_json=excluded.detail_json,updated_at=excluded.updated_at",
            (
                coverage_id,
                int(row["capture_id"]),
                subject_id,
                status,
                json.dumps(detail, sort_keys=True),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def triage_tcp_text(
    project_path: Path,
    tshark: Path,
    *,
    max_streams: int = 32,
    max_segments_per_stream: int = 100_000,
    max_stream_bytes: int = 16 * 1024 * 1024,
    max_total_bytes: int = 64 * 1024 * 1024,
) -> TcpTextTriageSummary:
    """Reconstruct bounded raw-data TCP streams and run the shared candidate triage."""

    if min(max_streams, max_segments_per_stream, max_stream_bytes, max_total_bytes) <= 0:
        raise ValueError("TCP text triage limits must be positive")
    project = inspect_project(project_path)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    profiles = _profiles(database)
    inventory_refreshed = False
    if not profiles:
        index_summary(project.root, tshark)
        profiles = _profiles(database)
        inventory_refreshed = True

    eligible = [profile for profile in profiles if _is_generic_data_profile(profile)]
    results: list[TcpTextStreamResult] = []
    selected = reconstructed = partial = truncated = skipped_budget = skipped_limit = failed = 0
    estimated_total = output_total = 0
    remaining = max_total_bytes
    capabilities = probe_tshark(tshark) if eligible else None

    for profile in eligible:
        stream_index = int(profile["stream_index"])
        payload_bytes = int(profile["payload_bytes"])
        if payload_bytes > max_stream_bytes or payload_bytes > remaining:
            skipped_budget += 1
            results.append(
                TcpTextStreamResult(
                    stream_index,
                    payload_bytes,
                    "skipped-budget",
                    0,
                    0,
                )
            )
            continue
        if selected >= max_streams:
            skipped_limit += 1
            results.append(TcpTextStreamResult(stream_index, payload_bytes, "skipped-limit", 0, 0))
            continue
        selected += 1
        estimated_total += payload_bytes
        remaining -= payload_bytes
        try:
            summary = reconstruct_tcp_stream(
                project.root,
                stream_index,
                tshark,
                max_segments=max_segments_per_stream,
                max_index_payload_bytes=max_stream_bytes,
                max_direction_bytes=max_stream_bytes,
                max_total_output_bytes=max_stream_bytes,
                capabilities=capabilities,
            )
            output_bytes = sum(item.output_bytes for item in summary.directions)
            direction_statuses = {item.status for item in summary.directions}
            is_truncated = summary.index_truncated or "truncated" in direction_statuses
            is_partial = bool(direction_statuses & {"partial", "conflicting"})
            if is_truncated:
                truncated += 1
            if is_partial:
                partial += 1
            stream_status = (
                "truncated"
                if is_truncated
                else "conflicting"
                if "conflicting" in direction_statuses
                else "partial"
                if is_partial
                else "reconstructed"
            )
            reconstructed += 1
            output_total += output_bytes
            results.append(
                TcpTextStreamResult(
                    stream_index,
                    payload_bytes,
                    stream_status,
                    output_bytes,
                    len(summary.directions),
                )
            )
        except (OSError, TimeoutError, ValueError) as error:
            failed += 1
            results.append(
                TcpTextStreamResult(
                    stream_index,
                    payload_bytes,
                    "failed",
                    0,
                    0,
                    str(error)[:500],
                )
            )

    triage = triage_project(
        project.root,
        max_evidence_bytes=max_stream_bytes,
        max_total_bytes=max_total_bytes,
    )
    coverage_status = (
        "partial"
        if failed or partial
        else "budget-limited"
        if skipped_budget or skipped_limit or truncated
        else "complete"
        if eligible
        else "not-run"
    )
    if eligible:
        _update_data_coverage(
            database,
            project.capture_sha256,
            status=coverage_status,
            eligible_streams=len(eligible),
            reconstructed_streams=reconstructed,
            partial_streams=partial,
            truncated_streams=truncated,
            skipped_budget=skipped_budget,
            skipped_limit=skipped_limit,
            failed_streams=failed,
        )
    rebuild_manual_queue(project.root)
    return TcpTextTriageSummary(
        schema_version="auto-shark.tcp-text-triage/v1",
        project=str(project.root),
        inventory_refreshed=inventory_refreshed,
        profiles_discovered=len(profiles),
        eligible_streams=len(eligible),
        excluded_streams=len(profiles) - len(eligible),
        selected_streams=selected,
        reconstructed_streams=reconstructed,
        partial_streams=partial,
        truncated_streams=truncated,
        skipped_budget=skipped_budget,
        skipped_limit=skipped_limit,
        failed_streams=failed,
        coverage_status=coverage_status,
        estimated_payload_bytes=estimated_total,
        output_bytes=output_total,
        known_matches=triage.known_matches,
        candidate_values=tuple(item.value for item in triage.candidates),
        streams=tuple(results),
    )
