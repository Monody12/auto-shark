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
from .engines.tshark import find_tshark, probe_tshark
from .pipeline import scan_project
from .project import create_project, inspect_project
from .version import __version__
from .workflow import analyze_with_bodies


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
        if args.command == "scan":
            print(
                scan_project(
                    args.project,
                    max_transform_output_bytes=args.max_transform_bytes,
                    max_transform_total_bytes=args.max_transform_total,
                    max_form_input_bytes=args.max_form_bytes,
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
