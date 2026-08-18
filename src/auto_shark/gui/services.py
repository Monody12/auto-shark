"""Headless service facade for the investigation UI.

Every method wraps one existing bounded query, mutation, or analysis surface
and returns its parsed JSON payload (or the summary object for stages). This
module imports no Qt dependency so it stays testable on Python 3.9 and
minimal installs.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import Settings
from ..detectors import detect_project
from ..dns import triage_dns_tunnels
from ..engines.tshark import TlsRsaKey, find_tshark, probe_tshark
from ..exporting import ExportLimits, export_bundle
from ..ftp import index_ftp
from ..icmp import triage_icmp
from ..inventory import index_summary
from ..investigation import add_note, query_notes, set_review_mark, update_note
from ..m4_queries import query_findings, query_timeline
from ..manual_queue import rebuild_manual_queue, update_manual_task_state
from ..pipeline import scan_project
from ..project import ProjectInfo, create_project, inspect_project
from ..queries import (
    query_manual_queue,
    query_streams,
    query_summary,
    query_telnet_dialogues,
    query_transaction_detail,
    query_transactions,
)
from ..reporting import collect_report
from ..smtp import extract_smtp_messages
from ..tcp_text import triage_tcp_text
from ..tcp_urgent import triage_tcp_urgent
from ..tftp import extract_tftp_transfers
from ..triage import triage_project
from ..usb_hid import triage_usb_hid
from ..voip import extract_voip_audio
from ..workflow import analyze_with_bodies

PAGE_LIMIT = 100


@dataclass(frozen=True)
class AnalysisStage:
    """One bounded, durably-idempotent pipeline step exposed to the UI."""

    key: str
    title: str
    run: Callable[[], object]


def resolve_tshark(explicit: Optional[Path] = None) -> Optional[Path]:
    settings = Settings.from_environment()
    return find_tshark(explicit or settings.tshark_path)


def create_new_project(capture: Path, directory: Path) -> ProjectInfo:
    return create_project(capture, directory)


def _payload(result: object) -> dict:
    if isinstance(result, dict):
        return result
    return json.loads(result.to_json())  # type: ignore[attr-defined]


class ProjectServices:
    """Bound read/mutation facade over one Auto-Shark project."""

    def __init__(self, project_path: Path) -> None:
        self.root = Path(project_path)

    def info(self) -> ProjectInfo:
        return inspect_project(self.root)

    # ------------------------------------------------------------------ reads

    def overview(self) -> dict:
        return _payload(collect_report(self.root))

    def summary(self, *, protocol_offset: int = 0, conversation_offset: int = 0) -> dict:
        return _payload(
            query_summary(
                self.root,
                protocol_offset=protocol_offset,
                protocol_limit=PAGE_LIMIT,
                conversation_offset=conversation_offset,
                conversation_limit=PAGE_LIMIT,
            )
        )

    def transactions(self, *, uri: Optional[str] = None, offset: int = 0) -> dict:
        return _payload(query_transactions(self.root, uri=uri, offset=offset, limit=PAGE_LIMIT))

    def transaction_detail(self, transaction_id: str) -> dict:
        return query_transaction_detail(self.root, transaction_id)

    def streams(self, *, offset: int = 0) -> dict:
        return _payload(query_streams(self.root, offset=offset, limit=PAGE_LIMIT))

    def telnet_dialogues(self, *, stream: Optional[int] = None, offset: int = 0) -> dict:
        return _payload(
            query_telnet_dialogues(self.root, stream=stream, offset=offset, limit=PAGE_LIMIT)
        )

    def findings(self, *, candidate_offset: int = 0, finding_offset: int = 0) -> dict:
        return _payload(
            query_findings(
                self.root,
                candidate_offset=candidate_offset,
                candidate_limit=PAGE_LIMIT,
                finding_offset=finding_offset,
                finding_limit=PAGE_LIMIT,
            )
        )

    def timeline(
        self,
        *,
        event_kind: Optional[str] = None,
        status: Optional[str] = None,
        include_duplicates: bool = False,
        offset: int = 0,
    ) -> dict:
        return _payload(
            query_timeline(
                self.root,
                event_kind=event_kind,
                status=status,
                include_duplicates=include_duplicates,
                offset=offset,
                limit=PAGE_LIMIT,
            )
        )

    def manual_queue(
        self,
        *,
        state: Optional[str] = None,
        kind: Optional[str] = None,
        min_priority: int = 0,
        offset: int = 0,
    ) -> dict:
        return _payload(
            query_manual_queue(
                self.root,
                state=state,
                kind=kind,
                min_priority=min_priority,
                offset=offset,
                limit=PAGE_LIMIT,
            )
        )

    def notes(
        self,
        *,
        subject_kind: Optional[str] = None,
        subject_id: Optional[str] = None,
        offset: int = 0,
    ) -> dict:
        return _payload(
            query_notes(
                self.root,
                subject_kind=subject_kind,
                subject_id=subject_id,
                offset=offset,
                limit=PAGE_LIMIT,
            )
        )

    # --------------------------------------------------------------- mutations

    def set_review_mark(self, subject_kind: str, subject_id: str, state: str) -> dict:
        return _payload(set_review_mark(self.root, subject_kind, subject_id, state))

    def add_note(self, subject_kind: str, subject_id: str, body: str) -> dict:
        return _payload(add_note(self.root, subject_kind, subject_id, body))

    def update_note(self, note_id: str, body: str) -> dict:
        return _payload(update_note(self.root, note_id, body))

    def update_manual_task_state(self, task_id: str, state: str) -> dict:
        return _payload(update_manual_task_state(self.root, task_id, state))

    def export_bundle_to(
        self,
        output_directory: Path,
        *,
        include_evidence: bool = True,
    ) -> dict:
        return _payload(
            export_bundle(
                self.root,
                output_directory,
                export_limits=ExportLimits(include_evidence=include_evidence),
            )
        )

    # ---------------------------------------------------------------- analysis

    def analysis_stages(
        self,
        tshark: Path,
        *,
        capture: Optional[Path] = None,
        tls_rsa_key: Optional[TlsRsaKey] = None,
    ) -> list[AnalysisStage]:
        """Return the ordered bounded analysis pipeline for this project.

        ``capture`` prefixes the metadata/body extraction stage that creates
        the project database; it is used once for newly created projects.
        """
        stages: list[AnalysisStage] = []
        if capture is not None:
            stages.append(
                AnalysisStage(
                    "analyze",
                    "Extract HTTP metadata, bodies, and transforms",
                    lambda: analyze_with_bodies(
                        capture,
                        self.root,
                        tshark,
                        uri=None,
                        max_body_bytes=16 * 1024 * 1024,
                        max_total_bytes=64 * 1024 * 1024,
                        run_scan=True,
                        tls_rsa_key=tls_rsa_key,
                    ),
                )
            )

        def voip_stage() -> object:
            protocol_labels = {
                str(item.get("protocol_label"))
                for item in _payload(
                    query_summary(
                        self.root,
                        protocol_limit=PAGE_LIMIT,
                        conversation_limit=1,
                    )
                ).get("protocols", [])
            }
            if "rtp" not in protocol_labels:
                return {"status": "not-applicable", "reason": "no RTP protocol observed"}
            summary = extract_voip_audio(self.root, tshark)
            rebuild_manual_queue(self.root)
            return summary

        def ftp_stage() -> object:
            capabilities = probe_tshark(tshark)
            if not capabilities.features.get("ftp", False):
                return {
                    "status": "unavailable",
                    "reason": "TShark lacks the required FTP/FTP-DATA fields",
                }
            return index_ftp(self.root, tshark, capabilities=capabilities)

        def tftp_stage() -> object:
            summary = extract_tftp_transfers(self.root, tshark)
            rebuild_manual_queue(self.root)
            return summary

        def smtp_stage() -> object:
            capabilities = probe_tshark(tshark)
            if not capabilities.features.get("smtp", False):
                return {
                    "status": "unavailable",
                    "reason": "TShark lacks the required SMTP fields",
                }
            summary = extract_smtp_messages(self.root, tshark, capabilities=capabilities)
            rebuild_manual_queue(self.root)
            return summary

        def dns_stage() -> object:
            protocol_labels = {
                str(item.get("protocol_label"))
                for item in _payload(
                    query_summary(
                        self.root,
                        protocol_limit=PAGE_LIMIT,
                        conversation_limit=1,
                    )
                ).get("protocols", [])
            }
            if "dns" not in protocol_labels:
                return {"status": "not-applicable", "reason": "no DNS protocol observed"}
            summary = triage_dns_tunnels(self.root, tshark)
            rebuild_manual_queue(self.root)
            return summary

        def tcp_urgent_stage() -> object:
            summary = triage_tcp_urgent(self.root, tshark)
            rebuild_manual_queue(self.root)
            return summary

        def icmp_stage() -> object:
            summary = triage_icmp(self.root, tshark)
            rebuild_manual_queue(self.root)
            return summary

        def usb_hid_stage() -> object:
            summary = triage_usb_hid(self.root, tshark)
            rebuild_manual_queue(self.root)
            return summary

        stages.extend(
            [
                AnalysisStage(
                    "ftp",
                    "Correlate FTP control and data transfers",
                    ftp_stage,
                ),
                AnalysisStage(
                    "tftp",
                    "Reconstruct TFTP uploads and downloads",
                    tftp_stage,
                ),
                AnalysisStage(
                    "smtp",
                    "Recover SMTP messages and MIME attachments",
                    smtp_stage,
                ),
                AnalysisStage(
                    "scan",
                    "Apply transforms and carve static files",
                    lambda: scan_project(self.root, with_files=True),
                ),
                AnalysisStage(
                    "triage",
                    "Rank known-format and sensitive-field candidates",
                    lambda: triage_project(self.root),
                ),
                AnalysisStage(
                    "detect",
                    "Run unknown-candidate, SQL-injection, and WebShell detectors",
                    lambda: detect_project(self.root),
                ),
                AnalysisStage(
                    "inventory",
                    "Build capture summary and manual queue",
                    lambda: index_summary(self.root, tshark),
                ),
                AnalysisStage(
                    "tcp-text",
                    "Reconstruct and inspect generic TCP data streams",
                    lambda: triage_tcp_text(self.root, tshark),
                ),
                AnalysisStage(
                    "dns",
                    "Triage encoded DNS labels and recover validated files",
                    dns_stage,
                ),
                AnalysisStage(
                    "icmp",
                    "Inspect ICMP echo side channels and printable TTL oracles",
                    icmp_stage,
                ),
                AnalysisStage(
                    "tcp-urgent",
                    "Inspect TCP urgent-pointer side channels",
                    tcp_urgent_stage,
                ),
                AnalysisStage(
                    "usb-hid",
                    "Triage USB HID input report series",
                    usb_hid_stage,
                ),
                AnalysisStage(
                    "voip",
                    "Reconstruct supported RTP audio and preserve VoIP hints",
                    voip_stage,
                ),
            ]
        )
        return stages
