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
from .config import Settings
from .engines.tshark import find_tshark, probe_tshark
from .project import create_project, inspect_project
from .version import __version__


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
        if args.command == "analyze":
            settings = Settings.from_environment()
            executable = find_tshark(args.tshark or settings.tshark_path)
            if executable is None:
                print(
                    "TShark was not found. Use --tshark or AUTO_SHARK_TSHARK.",
                    file=sys.stderr,
                )
                return 2
            print(
                analyze_http(
                    args.capture,
                    args.project,
                    executable,
                    matching_uri=args.uri,
                ).to_json()
            )
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
