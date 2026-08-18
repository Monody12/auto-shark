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
from .dns import triage_dns_tunnels
from .engines.tshark import find_tshark, load_tls_rsa_key, probe_tshark
from .exporting import ExportLimits, export_bundle
from .files.carve import carve_project
from .ftp import index_ftp
from .icmp import triage_icmp
from .image_analysis import analyze_project_images
from .inventory import index_summary
from .investigation import add_note, query_notes, set_review_mark, update_note
from .m4_queries import query_findings, query_timeline
from .manual_queue import rebuild_manual_queue, update_manual_task_state
from .pipeline import scan_project
from .plugins import probe_plugin, run_plugin
from .project import create_project, inspect_project
from .queries import (
    query_manual_queue,
    query_streams,
    query_summary,
    query_telnet_dialogues,
    query_transactions,
)
from .remote import (
    RemoteNodeConfig,
    SshTransport,
    find_ssh_tools,
    probe_remote_node,
    run_remote_job,
    setup_remote_adapter,
)
from .reporting import ReportLimits, collect_report
from .tcp import reconstruct_tcp_stream
from .tcp_text import triage_tcp_text
from .tcp_urgent import triage_tcp_urgent
from .telnet import index_telnet
from .tftp import extract_tftp_transfers
from .triage import triage_project
from .usb_hid import triage_usb_hid
from .version import __version__
from .voip import extract_voip_audio
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
    analyze.add_argument(
        "--tls-rsa-key",
        type=Path,
        help="challenge-provided private key for compatible legacy RSA TLS sessions",
    )
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
    extract.add_argument(
        "--tls-rsa-key",
        type=Path,
        help="challenge-provided private key for compatible legacy RSA TLS sessions",
    )
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

    tcp_text = commands.add_parser(
        "tcp-text", help="reconstruct and triage bounded generic TCP data streams"
    )
    tcp_text.add_argument("project", type=Path)
    tcp_text.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    tcp_text.add_argument("--max-streams", type=int, default=32)
    tcp_text.add_argument("--max-segments-per-stream", type=int, default=100_000)
    tcp_text.add_argument("--max-stream-bytes", type=int, default=16 * 1024 * 1024)
    tcp_text.add_argument("--max-total-bytes", type=int, default=64 * 1024 * 1024)

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
    detect.add_argument("--max-ognl-fields", type=int, default=100_000)
    detect.add_argument("--max-ognl-body-bytes", type=int, default=1024 * 1024)

    ftp = commands.add_parser("index-ftp", help="correlate and export bounded FTP transfers")
    ftp.add_argument("project", type=Path)
    ftp.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    ftp.add_argument("--max-messages", type=int, default=100_000)
    ftp.add_argument("--max-transfers", type=int, default=10_000)
    ftp.add_argument("--max-index-bytes", type=int, default=512 * 1024 * 1024)
    ftp.add_argument("--max-transfer-bytes", type=int, default=256 * 1024 * 1024)
    ftp.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)

    tftp = commands.add_parser(
        "tftp-extract", help="reconstruct bounded TFTP uploads and downloads"
    )
    tftp.add_argument("project", type=Path)
    tftp.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    tftp.add_argument("--max-discovery-packets", type=int, default=100_000)
    tftp.add_argument("--max-data-packets", type=int, default=500_000)
    tftp.add_argument("--max-transfers", type=int, default=256)
    tftp.add_argument("--max-transfer-bytes", type=int, default=64 * 1024 * 1024)
    tftp.add_argument("--max-total-bytes", type=int, default=256 * 1024 * 1024)

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

    voip = commands.add_parser(
        "voip-extract", help="reconstruct bounded G.711 RTP streams as WAV artifacts"
    )
    voip.add_argument("project", type=Path)
    voip.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    voip.add_argument("--max-packets", type=int, default=100_000)
    voip.add_argument("--max-streams", type=int, default=128)
    voip.add_argument("--max-payload-bytes", type=int, default=64 * 1024 * 1024)

    dns = commands.add_parser(
        "dns-triage", help="triage encoded DNS labels and recover validated files"
    )
    dns.add_argument("project", type=Path)
    dns.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    dns.add_argument("--max-queries", type=int, default=100_000)
    dns.add_argument("--max-groups", type=int, default=256)
    dns.add_argument("--max-decoded-bytes", type=int, default=64 * 1024 * 1024)
    dns.add_argument("--max-preview-bytes", type=int, default=4096)
    dns.add_argument("--max-stream-bytes", type=int, default=16 * 1024 * 1024)
    dns.add_argument("--max-artifact-bytes", type=int, default=16 * 1024 * 1024)

    icmp = commands.add_parser(
        "icmp-triage", help="detect printable TTL echo oracles and ICMP side channels"
    )
    icmp.add_argument("project", type=Path)
    icmp.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    icmp.add_argument("--max-packets", type=int, default=100_000)
    icmp.add_argument("--max-routes", type=int, default=256)
    icmp.add_argument("--max-preview-attempts", type=int, default=256)

    urgent = commands.add_parser(
        "tcp-urgent", help="detect printable data concealed in TCP urgent pointers"
    )
    urgent.add_argument("project", type=Path)
    urgent.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    urgent.add_argument("--max-frames", type=int, default=100_000)
    urgent.add_argument("--max-groups", type=int, default=256)

    usb_hid = commands.add_parser(
        "usb-hid", help="triage USB keyboard and absolute-pointer report series"
    )
    usb_hid.add_argument("project", type=Path)
    usb_hid.add_argument("--tshark", type=Path, help="explicit path to tshark executable")
    usb_hid.add_argument("--max-reports", type=int, default=100_000)
    usb_hid.add_argument("--max-endpoints", type=int, default=256)

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

    timeline = commands.add_parser("timeline", help="query a detector behavior timeline")
    timeline.add_argument("project", type=Path)
    timeline.add_argument("--detector", default="static-webshell-activity")
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

    gui = commands.add_parser("gui", help="launch the investigation UI (optional gui extra)")
    gui.add_argument("--project", type=Path, help="open this project directory at startup")

    plugin_probe = commands.add_parser(
        "plugin-probe", help="validate one external analyzer manifest"
    )
    plugin_probe.add_argument("manifest", type=Path)

    plugin_run = commands.add_parser("plugin-run", help="run one declared analyzer on one artifact")
    plugin_run.add_argument("project", type=Path)
    plugin_run.add_argument("manifest", type=Path)
    plugin_run.add_argument("--artifact", required=True)

    remote_probe = commands.add_parser(
        "remote-probe", help="probe a Linux analysis node over constrained SSH"
    )
    remote_probe.add_argument("--host", required=True)
    remote_probe.add_argument(
        "--path", action="append", required=True, help="absolute remote executable path"
    )
    remote_probe.add_argument("--ssh", type=Path)
    remote_probe.add_argument("--sftp", type=Path)
    remote_probe.add_argument("--connect-timeout", type=int, default=15)

    remote_run = commands.add_parser("remote-run", help="run one declared analyzer on a Linux node")
    remote_run.add_argument("project", type=Path)
    remote_run.add_argument("manifest", type=Path)
    remote_run.add_argument("--artifact", required=True)
    remote_run.add_argument("--host", required=True)
    remote_run.add_argument("--ssh", type=Path)
    remote_run.add_argument("--sftp", type=Path)
    remote_run.add_argument("--remote-root", default=".auto-shark-jobs")

    remote_setup = commands.add_parser(
        "remote-setup", help="upload the cwd adapter to a Linux node once"
    )
    remote_setup.add_argument("--host", required=True)
    remote_setup.add_argument("--ssh", type=Path)
    remote_setup.add_argument("--sftp", type=Path)
    remote_setup.add_argument("--remote-root", default=".auto-shark-jobs")

    image_analyze = commands.add_parser(
        "image-analyze", help="run a declared image analyzer over image artifacts"
    )
    image_analyze.add_argument("project", type=Path)
    image_analyze.add_argument("manifest", type=Path)
    image_analyze.add_argument("--max-artifacts", type=int, default=32)
    image_analyze.add_argument("--remote", action="store_true", help="run on the Linux node")
    image_analyze.add_argument("--host")
    image_analyze.add_argument("--ssh", type=Path)
    image_analyze.add_argument("--sftp", type=Path)
    image_analyze.add_argument("--remote-root", default=".auto-shark-jobs")

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
        if args.command == "plugin-probe":
            probe = probe_plugin(args.manifest)
            print(json.dumps(probe, ensure_ascii=False, sort_keys=True, indent=2))
            return 0 if probe["available"] else 2
        if args.command == "plugin-run":
            print(
                json.dumps(
                    run_plugin(args.project, args.manifest, args.artifact),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        if args.command == "remote-probe":
            ssh, sftp = find_ssh_tools(args.ssh, args.sftp)
            if ssh is None or sftp is None:
                print("error: ssh and sftp clients are required", file=sys.stderr)
                return 2
            probe = probe_remote_node(
                RemoteNodeConfig(
                    host=args.host,
                    ssh_executable=ssh,
                    sftp_executable=sftp,
                    connect_timeout_seconds=args.connect_timeout,
                ),
                args.path,
            )
            print(json.dumps(probe, ensure_ascii=False, sort_keys=True, indent=2))
            return 0 if probe["available"] else 2
        if args.command == "remote-run":
            ssh, sftp = find_ssh_tools(args.ssh, args.sftp)
            if ssh is None or sftp is None:
                print("error: ssh and sftp clients are required", file=sys.stderr)
                return 2
            print(
                json.dumps(
                    run_remote_job(
                        args.project,
                        SshTransport(
                            RemoteNodeConfig(
                                host=args.host,
                                ssh_executable=ssh,
                                sftp_executable=sftp,
                                remote_root=args.remote_root,
                            )
                        ),
                        args.manifest,
                        args.artifact,
                        node_name=args.host,
                        remote_root=args.remote_root,
                    ),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        if args.command == "remote-setup":
            ssh, sftp = find_ssh_tools(args.ssh, args.sftp)
            if ssh is None or sftp is None:
                print("error: ssh and sftp clients are required", file=sys.stderr)
                return 2
            result = setup_remote_adapter(
                RemoteNodeConfig(
                    host=args.host,
                    ssh_executable=ssh,
                    sftp_executable=sftp,
                    remote_root=args.remote_root,
                )
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
            return 0 if result["ok"] else 2
        if args.command == "image-analyze":
            if args.remote and not args.host:
                raise ValueError("--remote requires --host")
            print(
                analyze_project_images(
                    args.project,
                    args.manifest,
                    remote_host=args.host if args.remote else None,
                    ssh_executable=args.ssh,
                    sftp_executable=args.sftp,
                    remote_root=args.remote_root,
                    max_artifacts=args.max_artifacts,
                ).to_json(),
                end="",
            )
            return 0
        if args.command == "gui":
            from .gui import run_gui

            return run_gui(args.project)
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
                    set_review_mark(args.project, args.subject_kind, args.subject_id, args.state),
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
                    detector=args.detector,
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
        if args.command == "voip-extract":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            summary = extract_voip_audio(
                args.project,
                executable,
                max_packets=args.max_packets,
                max_streams=args.max_streams,
                max_payload_bytes=args.max_payload_bytes,
            )
            rebuild_manual_queue(args.project)
            print(summary.to_json(), end="")
            return 0
        if args.command == "dns-triage":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            summary = triage_dns_tunnels(
                args.project,
                executable,
                max_queries=args.max_queries,
                max_groups=args.max_groups,
                max_decoded_bytes=args.max_decoded_bytes,
                max_preview_bytes=args.max_preview_bytes,
                max_stream_bytes=args.max_stream_bytes,
                max_artifact_bytes=args.max_artifact_bytes,
            )
            rebuild_manual_queue(args.project)
            print(summary.to_json(), end="")
            return 0
        if args.command == "icmp-triage":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            summary = triage_icmp(
                args.project,
                executable,
                max_packets=args.max_packets,
                max_routes=args.max_routes,
                max_preview_attempts=args.max_preview_attempts,
            )
            rebuild_manual_queue(args.project)
            print(summary.to_json(), end="")
            return 0
        if args.command == "tcp-urgent":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            summary = triage_tcp_urgent(
                args.project,
                executable,
                max_frames=args.max_frames,
                max_groups=args.max_groups,
            )
            rebuild_manual_queue(args.project)
            print(summary.to_json(), end="")
            return 0
        if args.command == "usb-hid":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            summary = triage_usb_hid(
                args.project,
                executable,
                max_reports=args.max_reports,
                max_endpoints=args.max_endpoints,
            )
            rebuild_manual_queue(args.project)
            print(summary.to_json(), end="")
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
        if args.command == "tftp-extract":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            summary = extract_tftp_transfers(
                args.project,
                executable,
                max_discovery_packets=args.max_discovery_packets,
                max_data_packets=args.max_data_packets,
                max_transfers=args.max_transfers,
                max_transfer_bytes=args.max_transfer_bytes,
                max_total_bytes=args.max_total_bytes,
            )
            rebuild_manual_queue(args.project)
            print(summary.to_json(), end="")
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
                    max_ognl_fields=args.max_ognl_fields,
                    max_ognl_body_bytes=args.max_ognl_body_bytes,
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
        if args.command == "tcp-text":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            print(
                triage_tcp_text(
                    args.project,
                    executable,
                    max_streams=args.max_streams,
                    max_segments_per_stream=args.max_segments_per_stream,
                    max_stream_bytes=args.max_stream_bytes,
                    max_total_bytes=args.max_total_bytes,
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
                    tls_rsa_key=(
                        load_tls_rsa_key(args.tls_rsa_key) if args.tls_rsa_key else None
                    ),
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
            tls_rsa_key = load_tls_rsa_key(args.tls_rsa_key) if args.tls_rsa_key else None
            if args.with_bodies:
                result = analyze_with_bodies(
                    args.capture,
                    args.project,
                    executable,
                    uri=args.uri,
                    max_body_bytes=args.max_body_bytes,
                    max_total_bytes=args.max_body_total,
                    run_scan=args.scan,
                    tls_rsa_key=tls_rsa_key,
                )
            else:
                result = analyze_http(
                    args.capture,
                    args.project,
                    executable,
                    matching_uri=args.uri,
                    tls_rsa_key=tls_rsa_key,
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
    except (FileNotFoundError, FileExistsError, ValueError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2
