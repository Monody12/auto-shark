"""Auto-Shark command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .analysis import analyze_http
from .body import extract_http_body
from .config import Settings
from .detectors import detect_project
from .engines.tshark import find_tshark, probe_tshark
from .exporting import ExportLimits, export_bundle
from .files.carve import carve_project
from .ftp import index_ftp
from .inventory import index_summary
from .investigation import add_note, query_notes, set_review_mark, update_note
from .m4_queries import query_findings, query_timeline
from .manual_queue import rebuild_manual_queue, update_manual_task_state
from .pipeline import scan_project
from .project import create_project, inspect_project
from .queries import (
    query_manual_queue,
    query_streams,
    query_summary,
    query_telnet_dialogues,
    query_transactions,
)
from .reporting import ReportLimits, collect_report
from .tcp import reconstruct_tcp_stream
from .telnet import index_telnet
from .triage import triage_project
from .version import __version__
from .workflow import analyze_with_bodies


def _add_report_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-protocols", type=int, default=256)
    parser.add_argument("--max-conversations", type=int, default=1000)
    parser.add_argument("--max-candidates", type=int, default=1000)
    parser.add_argument("--max-findings", type=int, default=1000)
    parser.add_argument("--max-events", type=int, default=1000)
    parser.add_argument("--max-artifacts", type=int, default=1000)
    parser.add_argument("--max-manual-tasks", type=int, default=1000)
    parser.add_argument("--max-review-marks", type=int, default=1000)
    parser.add_argument("--max-notes", type=int, default=1000)
    parser.add_argument("--max-evidence", type=int, default=10_000)
    parser.add_argument("--max-tool-runs", type=int, default=1000)
    parser.add_argument("--max-detector-runs", type=int, default=1000)
    parser.add_argument("--max-signals", type=int, default=10_000)
    parser.add_argument("--max-evidence-links", type=int, default=50_000)
    parser.add_argument("--max-detail-bytes", type=int, default=4096)
    parser.add_argument("--max-note-bytes", type=int, default=64 * 1024)


def _report_limits(args: argparse.Namespace) -> ReportLimits:
    return ReportLimits(
        protocols=args.max_protocols,
        conversations=args.max_conversations,
        candidates=args.max_candidates,
        findings=args.max_findings,
        events=args.max_events,
        artifacts=args.max_artifacts,
        manual_tasks=args.max_manual_tasks,
        review_marks=args.max_review_marks,
        notes=args.max_notes,
        evidence=args.max_evidence,
        tool_runs=args.max_tool_runs,
        detector_runs=args.max_detector_runs,
        signals=args.max_signals,
        evidence_links=args.max_evidence_links,
        detail_bytes=args.max_detail_bytes,
        note_bytes=args.max_note_bytes,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto-shark",
        description="Offline, evidence-preserving CTF packet analysis workbench",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    commands = parser.add_subparsers(dest="command")

    analyze = commands.add_parser("analyze", help="create and analyze a capture project")
    analyze.add_argument("capture", type=Path)
    analyze.add_argument("--project", required=True, type=Path)
    analyze.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    analyze.add_argument("--uri", help="also count transactions with this exact request URI")
    analyze.add_argument("--with-bodies", action="store_true")
    analyze.add_argument("--scan", action="store_true", help="scan bodies after extraction")
    analyze.add_argument("--max-body-bytes", type=int, default=16 * 1024 * 1024)
    analyze.add_argument("--max-body-total", type=int, default=64 * 1024 * 1024)
    analyze.add_argument("--verbose-bodies", action="store_true")

    extract = commands.add_parser("extract-body", help="extract one indexed HTTP body")
    extract.add_argument("project", type=Path)
    extract.add_argument("frame", type=int)
    extract.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    extract.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)

    scan = commands.add_parser("scan", help="scan extracted evidence and apply bounded transforms")
    scan.add_argument("project", type=Path)
    scan.add_argument("--max-transform-bytes", type=int, default=16 * 1024 * 1024)
    scan.add_argument("--max-transform-total", type=int, default=64 * 1024 * 1024)
    scan.add_argument("--max-form-bytes", type=int, default=16 * 1024 * 1024)
    scan.add_argument("--with-files", action="store_true", help="also carve static files")
    scan.add_argument("--max-file-scan-bytes", type=int, default=64 * 1024 * 1024)
    scan.add_argument("--max-file-artifact-bytes", type=int, default=64 * 1024 * 1024)

    carve = commands.add_parser("carve", help="identify and persist static file artifacts")
    carve.add_argument("project", type=Path)
    carve.add_argument("--max-scan-bytes", type=int, default=64 * 1024 * 1024)
    carve.add_argument("--max-artifact-bytes", type=int, default=64 * 1024 * 1024)
    carve.add_argument("--max-candidates", type=int, default=128)
    carve.add_argument("--window-bytes", type=int, default=1024 * 1024)

    reconstruct = commands.add_parser(
        "reconstruct-stream", help="index and reconstruct one bidirectional TCP stream"
    )
    reconstruct.add_argument("project", type=Path)
    reconstruct.add_argument("stream", type=int)
    reconstruct.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    reconstruct.add_argument("--max-segments", type=int, default=100_000)
    reconstruct.add_argument("--max-index-bytes", type=int, default=512 * 1024 * 1024)
    reconstruct.add_argument("--max-direction-bytes", type=int, default=256 * 1024 * 1024)
    reconstruct.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)

    transactions = commands.add_parser("transactions", help="query indexed HTTP transactions")
    transactions.add_argument("project", type=Path)
    transactions.add_argument("--uri", help="filter by exact request URI")
    transactions.add_argument("--offset", type=int, default=0)
    transactions.add_argument("--limit", type=int, default=100)

    streams = commands.add_parser("streams", help="query current TCP reconstructions")
    streams.add_argument("project", type=Path)
    streams.add_argument("--offset", type=int, default=0)
    streams.add_argument("--limit", type=int, default=100)

    triage = commands.add_parser("triage", help="rank bounded current evidence")
    triage.add_argument("project", type=Path)
    triage.add_argument("--max-evidence", type=int, default=10_000)
    triage.add_argument("--max-evidence-bytes", type=int, default=64 * 1024 * 1024)
    triage.add_argument("--max-total-bytes", type=int, default=256 * 1024 * 1024)
    triage.add_argument("--max-matches", type=int, default=128)
    triage.add_argument("--max-candidates", type=int, default=1024)
    triage.add_argument("--max-field-bytes", type=int, default=4096)
    triage.add_argument("--window-bytes", type=int, default=1024 * 1024)

    detect = commands.add_parser("detect", help="run bounded explainable CTF detectors")
    detect.add_argument("project", type=Path)
    detect.add_argument("--max-evidence", type=int, default=10_000)
    detect.add_argument("--max-evidence-bytes", type=int, default=64 * 1024 * 1024)
    detect.add_argument("--max-total-bytes", type=int, default=256 * 1024 * 1024)
    detect.add_argument("--max-matches", type=int, default=128)
    detect.add_argument("--max-candidates", type=int, default=1024)
    detect.add_argument("--chunk-size", type=int, default=1024 * 1024)
    detect.add_argument("--max-transactions", type=int, default=10_000)
    detect.add_argument("--max-parameters", type=int, default=1024)
    detect.add_argument("--max-parameter-bytes", type=int, default=4096)
    detect.add_argument("--max-events", type=int, default=10_000)
    detect.add_argument("--max-findings", type=int, default=1000)
    detect.add_argument("--max-preview-bytes", type=int, default=256)
    detect.add_argument("--max-webshell-fields", type=int, default=100_000)
    detect.add_argument("--max-webshell-value-bytes", type=int, default=64 * 1024)

    ftp = commands.add_parser("index-ftp", help="correlate and export bounded FTP transfers")
    ftp.add_argument("project", type=Path)
    ftp.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    ftp.add_argument("--max-messages", type=int, default=100_000)
    ftp.add_argument("--max-transfers", type=int, default=10_000)
    ftp.add_argument("--max-index-bytes", type=int, default=512 * 1024 * 1024)
    ftp.add_argument("--max-transfer-bytes", type=int, default=256 * 1024 * 1024)
    ftp.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)

    telnet = commands.add_parser("index-telnet", help="index bounded directional Telnet dialogues")
    telnet.add_argument("project", type=Path)
    telnet.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    telnet.add_argument("--max-metadata-frames", type=int, default=100_000)
    telnet.add_argument("--max-streams", type=int, default=10_000)
    telnet.add_argument("--max-records", type=int, default=100_000)
    telnet.add_argument("--max-record-bytes", type=int, default=1024 * 1024)
    telnet.add_argument("--max-index-bytes", type=int, default=512 * 1024 * 1024)
    telnet.add_argument("--max-direction-bytes", type=int, default=256 * 1024 * 1024)
    telnet.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)

    dialogues = commands.add_parser(
        "telnet-dialogues", help="query current bounded Telnet dialogue records"
    )
    dialogues.add_argument("project", type=Path)
    dialogues.add_argument("--stream", type=int)
    dialogues.add_argument("--offset", type=int, default=0)
    dialogues.add_argument("--limit", type=int, default=100)
    dialogues.add_argument("--max-records", type=int, default=1000)
    dialogues.add_argument("--max-preview-bytes", type=int, default=256)
    dialogues.add_argument("--max-total-preview-bytes", type=int, default=64 * 1024)
    dialogues.add_argument("--max-source-mappings", type=int, default=10_000)
    dialogues.add_argument("--max-relations", type=int, default=10_000)
    dialogues.add_argument("--max-candidates", type=int, default=10_000)

    inventory = commands.add_parser(
        "index-summary", help="index bounded capture and conversation summaries"
    )
    inventory.add_argument("project", type=Path)
    inventory.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    inventory.add_argument("--max-frames", type=int, default=100_000)
    inventory.add_argument("--max-protocol-labels", type=int, default=256)
    inventory.add_argument("--max-conversations", type=int, default=10_000)
    inventory.add_argument("--max-parts", type=int, default=10_000)
    inventory.add_argument("--max-body-scan-bytes", type=int, default=4 * 1024 * 1024)
    inventory.add_argument("--max-tasks", type=int, default=10_000)
    inventory.add_argument("--max-signals", type=int, default=50_000)
    inventory.add_argument("--max-evidence-links", type=int, default=100_000)
    inventory.add_argument("--max-unsupported-tasks", type=int, default=25)

    summary = commands.add_parser("summary", help="query bounded capture summaries")
    summary.add_argument("project", type=Path)
    summary.add_argument("--protocol-offset", type=int, default=0)
    summary.add_argument("--protocol-limit", type=int, default=100)
    summary.add_argument("--conversation-offset", type=int, default=0)
    summary.add_argument("--conversation-limit", type=int, default=100)

    queue = commands.add_parser("manual-queue", help="query persistent manual-analysis tasks")
    queue.add_argument("project", type=Path)
    queue.add_argument("--rebuild", action="store_true")
    queue.add_argument("--state")
    queue.add_argument("--kind")
    queue.add_argument("--min-priority", type=int, default=0)
    queue.add_argument("--subject-kind")
    queue.add_argument("--subject-id")
    queue.add_argument("--offset", type=int, default=0)
    queue.add_argument("--limit", type=int, default=100)
    queue.add_argument("--max-signals", type=int, default=1000)
    queue.add_argument("--max-evidence-links", type=int, default=1000)
    queue.add_argument("--max-detail-bytes", type=int, default=4096)
    queue.add_argument("--max-tasks", type=int, default=10_000)
    queue.add_argument("--max-unsupported-tasks", type=int, default=25)

    findings = commands.add_parser("findings", help="query bounded candidates and findings")
    findings.add_argument("project", type=Path)
    findings.add_argument("--candidate-offset", type=int, default=0)
    findings.add_argument("--candidate-limit", type=int, default=100)
    findings.add_argument("--finding-offset", type=int, default=0)
    findings.add_argument("--finding-limit", type=int, default=100)
    findings.add_argument("--max-signals", type=int, default=1000)
    findings.add_argument("--max-evidence-links", type=int, default=10_000)
    findings.add_argument("--max-detail-bytes", type=int, default=4096)

    timeline = commands.add_parser("timeline", help="query the static WebShell timeline")
    timeline.add_argument("project", type=Path)
    timeline.add_argument("--event-kind")
    timeline.add_argument("--status")
    timeline.add_argument("--frame-start", type=int)
    timeline.add_argument("--frame-end", type=int)
    timeline.add_argument("--include-duplicates", action="store_true")
    timeline.add_argument("--offset", type=int, default=0)
    timeline.add_argument("--limit", type=int, default=100)
    timeline.add_argument("--max-evidence-links", type=int, default=10_000)
    timeline.add_argument("--max-detail-bytes", type=int, default=4096)

    task = commands.add_parser("manual-task", help="update one manual-analysis task state")
    task.add_argument("project", type=Path)
    task.add_argument("task_id")
    task.add_argument(
        "--state",
        required=True,
        choices=("open", "in-progress", "resolved", "dismissed"),
    )

    review = commands.add_parser("review-mark", help="set one human investigation mark")
    review.add_argument("project", type=Path)
    review.add_argument("subject_kind")
    review.add_argument("subject_id")
    review.add_argument(
        "--state",
        required=True,
        choices=("unreviewed", "needs_review", "excluded", "key_evidence"),
    )

    note_add = commands.add_parser("note-add", help="add a bounded investigation note")
    note_add.add_argument("project", type=Path)
    note_add.add_argument("subject_kind")
    note_add.add_argument("subject_id")
    note_add.add_argument("--body", required=True)
    note_add.add_argument("--max-note-bytes", type=int, default=64 * 1024)

    note_update = commands.add_parser("note-update", help="update one investigation note")
    note_update.add_argument("project", type=Path)
    note_update.add_argument("note_id")
    note_update.add_argument("--body", required=True)
    note_update.add_argument("--max-note-bytes", type=int, default=64 * 1024)

    notes = commands.add_parser("notes", help="query bounded investigation notes")
    notes.add_argument("project", type=Path)
    notes.add_argument("--subject-kind")
    notes.add_argument("--subject-id")
    notes.add_argument("--offset", type=int, default=0)
    notes.add_argument("--limit", type=int, default=100)
    notes.add_argument("--max-body-bytes", type=int, default=64 * 1024)

    report = commands.add_parser("report", help="emit a deterministic bounded report")
    report.add_argument("project", type=Path)
    _add_report_limits(report)

    export = commands.add_parser("export", help="write an offline report bundle")
    export.add_argument("project", type=Path)
    export.add_argument("output_directory", type=Path)
    export.add_argument("--no-evidence", action="store_true")
    export.add_argument("--max-evidence-items", type=int, default=1000)
    export.add_argument("--max-evidence-item-bytes", type=int, default=16 * 1024 * 1024)
    export.add_argument("--max-evidence-total-bytes", type=int, default=64 * 1024 * 1024)
    _add_report_limits(export)

    probe = commands.add_parser("probe", help="probe TShark capabilities")
    probe.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    probe.add_argument("--json", action="store_true", help="emit the complete JSON profile")

    project = commands.add_parser("project", help="manage an analysis project")
    project_commands = project.add_subparsers(dest="project_command", required=True)
    create = project_commands.add_parser("create", help="create a machine-local project")
    create.add_argument("capture", type=Path)
    create.add_argument("directory", type=Path)
    create.add_argument(
        "--allow-synced",
        action="store_true",
        help="allow a live SQLite project in OneDrive or another synced root",
    )
    status = project_commands.add_parser("status", help="inspect an existing project")
    status.add_argument("directory", type=Path)

    return parser


def _print_project(info: object) -> None:
    payload = asdict(info)
    for key, value in payload.items():
        if isinstance(value, Path):
            payload[key] = str(value)
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "report":
            print(collect_report(args.project, limits=_report_limits(args)).to_json(), end="")
            return 0
        if args.command == "export":
            print(
                export_bundle(
                    args.project,
                    args.output_directory,
                    report_limits=_report_limits(args),
                    export_limits=ExportLimits(
                        include_evidence=not args.no_evidence,
                        max_evidence_items=args.max_evidence_items,
                        max_evidence_item_bytes=args.max_evidence_item_bytes,
                        max_evidence_total_bytes=args.max_evidence_total_bytes,
                    ),
                ).to_json(),
                end="",
            )
            return 0
        if args.command == "review-mark":
            print(
                json.dumps(
                    set_review_mark(
                        args.project, args.subject_kind, args.subject_id, args.state
                    ),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        if args.command == "note-add":
            print(
                json.dumps(
                    add_note(
                        args.project,
                        args.subject_kind,
                        args.subject_id,
                        args.body,
                        max_note_bytes=args.max_note_bytes,
                    ),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        if args.command == "note-update":
            print(
                json.dumps(
                    update_note(
                        args.project,
                        args.note_id,
                        args.body,
                        max_note_bytes=args.max_note_bytes,
                    ),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        if args.command == "notes":
            print(
                query_notes(
                    args.project,
                    subject_kind=args.subject_kind,
                    subject_id=args.subject_id,
                    offset=args.offset,
                    limit=args.limit,
                    max_body_bytes=args.max_body_bytes,
                ).to_json()
            )
            return 0
        if args.command == "manual-task":
            print(
                json.dumps(
                    update_manual_task_state(args.project, args.task_id, args.state),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        if args.command == "manual-queue":
            if args.rebuild:
                rebuild_manual_queue(
                    args.project,
                    max_tasks=args.max_tasks,
                    max_signals=args.max_signals,
                    max_evidence_links=args.max_evidence_links,
                    max_unsupported_tasks=args.max_unsupported_tasks,
                )
            print(
                query_manual_queue(
                    args.project,
                    state=args.state,
                    kind=args.kind,
                    min_priority=args.min_priority,
                    subject_kind=args.subject_kind,
                    subject_id=args.subject_id,
                    offset=args.offset,
                    limit=args.limit,
                    max_signals=args.max_signals,
                    max_evidence_links=args.max_evidence_links,
                    max_detail_bytes=args.max_detail_bytes,
                ).to_json()
            )
            return 0
        if args.command == "findings":
            print(
                query_findings(
                    args.project,
                    candidate_offset=args.candidate_offset,
                    candidate_limit=args.candidate_limit,
                    finding_offset=args.finding_offset,
                    finding_limit=args.finding_limit,
                    max_signals=args.max_signals,
                    max_evidence_links=args.max_evidence_links,
                    max_detail_bytes=args.max_detail_bytes,
                ).to_json()
            )
            return 0
        if args.command == "timeline":
            print(
                query_timeline(
                    args.project,
                    event_kind=args.event_kind,
                    status=args.status,
                    frame_start=args.frame_start,
                    frame_end=args.frame_end,
                    include_duplicates=args.include_duplicates,
                    offset=args.offset,
                    limit=args.limit,
                    max_evidence_links=args.max_evidence_links,
                    max_detail_bytes=args.max_detail_bytes,
                ).to_json()
            )
            return 0
        if args.command == "summary":
            print(
                query_summary(
                    args.project,
                    protocol_offset=args.protocol_offset,
                    protocol_limit=args.protocol_limit,
                    conversation_offset=args.conversation_offset,
                    conversation_limit=args.conversation_limit,
                ).to_json()
            )
            return 0
        if args.command == "index-summary":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            print(
                index_summary(
                    args.project,
                    executable,
                    max_frames=args.max_frames,
                    max_protocol_labels=args.max_protocol_labels,
                    max_conversations=args.max_conversations,
                    max_parts=args.max_parts,
                    max_body_scan_bytes=args.max_body_scan_bytes,
                    max_tasks=args.max_tasks,
                    max_signals=args.max_signals,
                    max_evidence_links=args.max_evidence_links,
                    max_unsupported_tasks=args.max_unsupported_tasks,
                ).to_json()
            )
            return 0
        if args.command == "index-telnet":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            print(
                index_telnet(
                    args.project,
                    executable,
                    max_metadata_frames=args.max_metadata_frames,
                    max_streams=args.max_streams,
                    max_records=args.max_records,
                    max_record_bytes=args.max_record_bytes,
                    max_index_payload_bytes=args.max_index_bytes,
                    max_direction_bytes=args.max_direction_bytes,
                    max_total_bytes=args.max_total_bytes,
                ).to_json()
            )
            return 0
        if args.command == "telnet-dialogues":
            print(
                query_telnet_dialogues(
                    args.project,
                    stream=args.stream,
                    offset=args.offset,
                    limit=args.limit,
                    max_records_per_dialogue=args.max_records,
                    max_preview_bytes=args.max_preview_bytes,
                    max_total_preview_bytes=args.max_total_preview_bytes,
                    max_source_mappings=args.max_source_mappings,
                    max_relations=args.max_relations,
                    max_candidates=args.max_candidates,
                ).to_json()
            )
            return 0
        if args.command == "index-ftp":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            print(
                index_ftp(
                    args.project,
                    executable,
                    max_messages=args.max_messages,
                    max_transfers=args.max_transfers,
                    max_index_payload_bytes=args.max_index_bytes,
                    max_transfer_bytes=args.max_transfer_bytes,
                    max_total_output_bytes=args.max_total_bytes,
                ).to_json()
            )
            return 0
        if args.command == "triage":
            print(
                triage_project(
                    args.project,
                    max_evidence=args.max_evidence,
                    max_evidence_bytes=args.max_evidence_bytes,
                    max_total_bytes=args.max_total_bytes,
                    max_matches_per_evidence=args.max_matches,
                    max_candidates=args.max_candidates,
                    max_field_bytes=args.max_field_bytes,
                    window_bytes=args.window_bytes,
                ).to_json()
            )
            return 0
        if args.command == "detect":
            print(
                detect_project(
                    args.project,
                    max_evidence=args.max_evidence,
                    max_evidence_bytes=args.max_evidence_bytes,
                    max_total_bytes=args.max_total_bytes,
                    max_matches=args.max_matches,
                    max_candidates=args.max_candidates,
                    chunk_size=args.chunk_size,
                    max_transactions=args.max_transactions,
                    max_parameters=args.max_parameters,
                    max_parameter_bytes=args.max_parameter_bytes,
                    max_events=args.max_events,
                    max_findings=args.max_findings,
                    max_preview_bytes=args.max_preview_bytes,
                    max_webshell_fields=args.max_webshell_fields,
                    max_webshell_value_bytes=args.max_webshell_value_bytes,
                ).to_json()
            )
            return 0
        if args.command == "transactions":
            print(
                query_transactions(
                    args.project,
                    uri=args.uri,
                    offset=args.offset,
                    limit=args.limit,
                ).to_json()
            )
            return 0
        if args.command == "streams":
            print(query_streams(args.project, offset=args.offset, limit=args.limit).to_json())
            return 0
        if args.command == "reconstruct-stream":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            print(
                reconstruct_tcp_stream(
                    args.project,
                    args.stream,
                    executable,
                    max_segments=args.max_segments,
                    max_index_payload_bytes=args.max_index_bytes,
                    max_direction_bytes=args.max_direction_bytes,
                    max_total_output_bytes=args.max_total_bytes,
                ).to_json()
            )
            return 0
        if args.command == "carve":
            print(
                carve_project(
                    args.project,
                    max_scan_bytes=args.max_scan_bytes,
                    max_artifact_bytes=args.max_artifact_bytes,
                    max_candidates_per_evidence=args.max_candidates,
                    window_bytes=args.window_bytes,
                ).to_json()
            )
            return 0
        if args.command == "scan":
            print(
                scan_project(
                    args.project,
                    max_transform_output_bytes=args.max_transform_bytes,
                    max_transform_total_bytes=args.max_transform_total,
                    max_form_input_bytes=args.max_form_bytes,
                    with_files=args.with_files,
                    max_file_scan_bytes=args.max_file_scan_bytes,
                    max_file_artifact_bytes=args.max_file_artifact_bytes,
                ).to_json()
            )
            return 0
        if args.command == "extract-body":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            print(
                extract_http_body(
                    args.project,
                    args.frame,
                    executable,
                    max_body_bytes=args.max_bytes,
                ).to_json()
            )
            return 0
        if args.command == "analyze":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            if args.scan and not args.with_bodies:
                raise ValueError("--scan requires --with-bodies")
            if args.with_bodies:
                result = analyze_with_bodies(
                    args.capture,
                    args.project,
                    executable,
                    uri=args.uri,
                    max_body_bytes=args.max_body_bytes,
                    max_total_bytes=args.max_body_total,
                    run_scan=args.scan,
                )
            else:
                result = analyze_http(
                    args.capture,
                    args.project,
                    executable,
                    matching_uri=args.uri,
                )
            if args.with_bodies:
                print(result.to_json(verbose_bodies=args.verbose_bodies))
            else:
                print(result.to_json())
            return 0
        if args.command == "probe":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            result = probe_tshark(executable)
            if args.json:
                print(result.to_json())
            else:
                print(result.version_line or result.executable)
                print("usable: %s" % ("yes" if result.usable else "no"))
                for feature, available in sorted(result.features.items()):
                    print(f"{feature}: {'yes' if available else 'no'}")
                for error in result.errors:
                    print(f"error: {error}", file=sys.stderr)
            return 0 if result.usable else 3
        if args.command == "project" and args.project_command == "create":
            _print_project(
                create_project(args.capture, args.directory, allow_synced=args.allow_synced)
            )
            return 0
        if args.command == "project" and args.project_command == "status":
            _print_project(inspect_project(args.directory))
            return 0
    except (FileNotFoundError, FileExistsError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2
