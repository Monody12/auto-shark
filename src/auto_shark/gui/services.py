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
from ..engines.process import run_bounded
from ..engines.tshark import TlsKeylog, TlsRsaKey, find_tshark, probe_tshark
from ..exporting import ExportLimits, export_bundle
from ..frames import extract_frame_columns
from ..ftp import index_ftp
from ..grep import grep_project
from ..icmp import triage_icmp, triage_icmp_data
from ..inventory import index_summary
from ..investigation import add_note, query_notes, set_review_mark, update_note
from ..m4_queries import query_findings, query_timeline
from ..manual_queue import rebuild_manual_queue, update_manual_task_state
from ..pipeline import scan_project
from ..project import ProjectInfo, create_project, inspect_project, write_flag_format
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
from ..snmp_strings import triage_snmp_strings
from ..storage import Database
from ..suggestions import build_wizard
from ..tcp_text import triage_tcp_text
from ..tcp_urgent import triage_tcp_urgent
from ..telnet import index_telnet
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
    return find_tshark(explicit or settings.tshark_path, settings.extra_tshark_dirs)


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

    # --------------------------------------------------------- statistics page

    def statistics(self) -> dict:
        """Protocol hierarchy, conversations, and HTTP aggregates (SQL only)."""

        project = inspect_project(self.root)
        database = Database(project.root / "project.sqlite")
        with database.connect() as connection:
            capture_id = int(
                connection.execute(
                    "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
                ).fetchone()[0]
            )
            protocols = [
                dict(row)
                for row in connection.execute(
                    "SELECT protocol_label, frame_count, first_frame, last_frame "
                    "FROM protocol_observation WHERE capture_id=? "
                    "ORDER BY frame_count DESC LIMIT 200",
                    (capture_id,),
                )
            ]
            conversations = [
                dict(row)
                for row in connection.execute(
                    "SELECT protocol, stream_index, endpoint_a, endpoint_b, "
                    "frame_count, captured_bytes, first_time, last_time "
                    "FROM conversation_profile WHERE capture_id=? "
                    "ORDER BY captured_bytes DESC LIMIT 500",
                    (capture_id,),
                )
            ]
            status_codes = [
                {"code": row["code"], "count": row["c"]}
                for row in connection.execute(
                    "SELECT hm.response_code code, count(*) c FROM http_message hm "
                    "JOIN protocol_message pm ON pm.id=hm.protocol_message_id "
                    "WHERE pm.capture_id=? AND hm.response_code IS NOT NULL "
                    "GROUP BY code ORDER BY c DESC LIMIT 30",
                    (capture_id,),
                )
            ]
            top_uris = [
                {"uri": row["uri"], "count": row["c"]}
                for row in connection.execute(
                    "SELECT COALESCE(hm.host,'') || hm.uri uri, count(*) c "
                    "FROM http_message hm "
                    "JOIN protocol_message pm ON pm.id=hm.protocol_message_id "
                    "WHERE pm.capture_id=? AND hm.method IS NOT NULL "
                    "GROUP BY uri ORDER BY c DESC LIMIT 100",
                    (capture_id,),
                )
            ]
        return {
            "schema_version": "auto-shark.statistics/v1",
            "protocols": protocols,
            "conversations": conversations,
            "status_codes": status_codes,
            "top_uris": top_uris,
        }

    _DNS_NAME_CAP = 5000

    def dns_names(self) -> list:
        """First-seen unique DNS query names (manual exfil review)."""

        project = inspect_project(self.root)
        tshark = resolve_tshark(None)
        if tshark is None:
            raise ValueError("TShark was not found for DNS listing")
        result = run_bounded(
            [
                str(tshark),
                "-r",
                str(project.capture_path),
                "-Y",
                "dns.flags.response == 0",
                "-T",
                "fields",
                "-E",
                "separator=/t",
                "-e",
                "frame.number",
                "-e",
                "dns.qry.name",
            ],
            timeout_seconds=120,
            stdout_limit=8 * 1024 * 1024,
            stderr_limit=64 * 1024,
        )
        if result.returncode != 0:
            raise ValueError("DNS query listing failed")
        seen: dict = {}
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) < 2 or not parts[1].strip():
                continue
            frame = int(parts[0]) if parts[0].strip().isdigit() else None
            for name in parts[1].split(","):
                name = name.strip()
                if name and name not in seen:
                    seen[name] = frame
                    if len(seen) >= self._DNS_NAME_CAP:
                        return [
                            {"name": key, "first_frame": value}
                            for key, value in seen.items()
                        ]
        return [{"name": key, "first_frame": value} for key, value in seen.items()]

    # ------------------------------------------------------------ frames page

    _FILTER_FRAME_CAP = 20_000

    def frames_stage(self, tshark: Path):
        """Stage wrapper: populate the packet-list columns."""

        return extract_frame_columns(self.root, tshark)

    def frames(
        self, *, offset: int = 0, limit: int = PAGE_LIMIT, filter_text: str = ""
    ) -> dict:
        """Page of packet rows; an optional tshark display filter narrows first."""

        project = inspect_project(self.root)
        tshark = resolve_tshark(None)
        numbers: Optional[list] = None
        if filter_text.strip():
            if tshark is None:
                raise ValueError("TShark was not found for display filtering")
            result = run_bounded(
                [
                    str(tshark),
                    "-r",
                    str(project.capture_path),
                    "-Y",
                    filter_text.strip(),
                    "-T",
                    "fields",
                    "-e",
                    "frame.number",
                ],
                timeout_seconds=120,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=64 * 1024,
            )
            if result.returncode != 0:
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                raise ValueError(detail.splitlines()[-1] if detail else "filter failed")
            numbers = []
            for line in result.stdout.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.isdigit():
                    numbers.append(int(line))
                    if len(numbers) >= self._FILTER_FRAME_CAP:
                        break
        database = Database(project.root / "project.sqlite")
        with database.connect() as connection:
            capture_id = int(
                connection.execute(
                    "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
                ).fetchone()[0]
            )
            where = "WHERE capture_id=?"
            params: list = [capture_id]
            if numbers is not None:
                if not numbers:
                    return {"items": [], "total": 0, "offset": offset, "filter": filter_text}
                where += f" AND frame_number IN ({','.join('?' for _ in numbers)})"
                params += numbers
            total = int(
                connection.execute(
                    f"SELECT count(*) FROM frame_column {where}", params
                ).fetchone()[0]
            )
            time_base = connection.execute(
                f"SELECT MIN(time_epoch) FROM frame_column {where}", params
            ).fetchone()[0]
            has_tcp = (
                connection.execute(
                    "SELECT 1 FROM frame_column WHERE capture_id=? AND tcp_stream "
                    "IS NOT NULL LIMIT 1",
                    (capture_id,),
                ).fetchone()
                is not None
            )
            has_udp = (
                connection.execute(
                    "SELECT 1 FROM frame_column WHERE capture_id=? AND udp_stream "
                    "IS NOT NULL LIMIT 1",
                    (capture_id,),
                ).fetchone()
                is not None
            )
            rows = connection.execute(
                f"SELECT frame_number,time_epoch,src,dst,protocol,info,frame_len,"
                f"tcp_stream,udp_stream FROM frame_column {where} "
                f"ORDER BY frame_number LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        items = [
            {
                "frame": row["frame_number"],
                "time": round(row["time_epoch"], 6),
                "src": row["src"],
                "dst": row["dst"],
                "protocol": row["protocol"],
                "info": row["info"],
                "length": row["frame_len"],
                "tcp_stream": row["tcp_stream"],
                "udp_stream": row["udp_stream"],
            }
            for row in rows
        ]
        return {
            "items": items,
            "total": total,
            "offset": offset,
            "filter": filter_text,
            "time_base": time_base,
            "has_tcp": has_tcp,
            "has_udp": has_udp,
        }

    def follow_stream(self, proto: str, stream_index: int) -> dict:
        """Reconstruct one TCP/UDP stream on demand, split by direction.

        ``proto="http"`` follows the same TCP stream (Wireshark's Follow
        HTTP Stream carries the identical bytes).
        """

        project = inspect_project(self.root)
        tshark = resolve_tshark(None)
        if tshark is None:
            raise ValueError("TShark was not found for stream following")
        wire_proto = "tcp" if proto in ("tcp", "http") else "udp"
        field = f"{wire_proto}.stream"
        result = run_bounded(
            [
                str(tshark),
                "-r",
                str(project.capture_path),
                "-Y",
                f"{field} == {int(stream_index)}",
                "-T",
                "fields",
                "-E",
                "separator=/t",
                "-E",
                "occurrence=f",
                "-e",
                "frame.number",
                "-e",
                "ip.src",
                "-e",
                f"{wire_proto}.srcport",
                "-e",
                f"{wire_proto}.payload",
            ],
            timeout_seconds=120,
            stdout_limit=32 * 1024 * 1024,
            stderr_limit=64 * 1024,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(detail.splitlines()[-1] if detail else "follow failed")
        client_key = None
        directions: dict = {}
        first_frame = last_frame = None
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            frame_text, src, payload = parts[0], parts[1], parts[3]
            if frame_text.isdigit():
                frame = int(frame_text)
                first_frame = frame if first_frame is None else min(first_frame, frame)
                last_frame = frame if last_frame is None else max(last_frame, frame)
            key = src
            if client_key is None and payload.strip():
                client_key = key
            bucket = directions.setdefault(key, bytearray())
            for chunk in payload.replace(":", "").split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                try:
                    bucket += bytes.fromhex(chunk)
                except ValueError:
                    continue
        client = bytes(directions.pop(client_key, bytearray())) if client_key else b""
        server = b"".join(bytes(value) for value in directions.values())
        return {
            "client": client,
            "server": server,
            "frames": [first_frame, last_frame],
            "stream": stream_index,
            "proto": proto,
        }

    def frame_detail(self, frame_number: int) -> str:
        """Verbose dissection text for one frame (single-frame tshark -V)."""

        project = inspect_project(self.root)
        tshark = resolve_tshark(None)
        if tshark is None:
            raise ValueError("TShark was not found for frame detail")
        result = run_bounded(
            [
                str(tshark),
                "-r",
                str(project.capture_path),
                "-Y",
                f"frame.number == {int(frame_number)}",
                "-V",
            ],
            timeout_seconds=60,
            stdout_limit=2 * 1024 * 1024,
            stderr_limit=64 * 1024,
        )
        if result.returncode != 0:
            raise ValueError("frame dissection failed")
        return result.stdout.decode("utf-8", errors="replace")

    # ------------------------------------------------------------- wizard/files

    def wizard(self) -> dict:
        """Challenge-type wizard payload (see auto_shark.suggestions)."""

        return build_wizard(self.root)

    def grep(self, needle: str) -> dict:
        """Global raw/hex/base64 search across every stored blob."""

        return grep_project(self.root, needle)

    def files(self) -> dict:
        """Bounded listing of carved/exported artifacts with blob locations."""

        project = inspect_project(self.root)
        database = Database(project.root / "project.sqlite")
        with database.connect() as connection:
            rows = connection.execute(
                "SELECT a.artifact_id, a.suggested_name, a.declared_media_type, "
                "a.detected_media_type, b.sha256, b.byte_length, b.media_type, "
                "b.magic_description, b.relative_path, b.complete "
                "FROM artifact a JOIN blob b ON b.id=a.blob_id "
                "ORDER BY b.byte_length DESC LIMIT 500"
            ).fetchall()
        items = [
            {
                "artifact_id": row["artifact_id"],
                "name": row["suggested_name"] or row["relative_path"].split("/")[-1],
                "media_type": row["detected_media_type"] or row["media_type"],
                "magic": row["magic_description"],
                "byte_length": row["byte_length"],
                "sha256": row["sha256"],
                "relative_path": row["relative_path"],
                "complete": bool(row["complete"]),
            }
            for row in rows
        ]
        return {"schema_version": "auto-shark.files/v1", "items": items, "total": len(items)}

    def blob_path(self, sha256: str) -> Optional[Path]:
        """Locate one stored blob file by content hash for content viewing."""

        project = inspect_project(self.root)
        database = Database(project.root / "project.sqlite")
        with database.connect() as connection:
            row = connection.execute(
                "SELECT relative_path FROM blob WHERE sha256 = ?", (sha256,)
            ).fetchone()
        if row is None:
            return None
        return self.root / Path(str(row["relative_path"]))

    def set_flag_format(self, pattern: str) -> None:
        write_flag_format(self.root, pattern)

    def http_body_path(self, message_public_id: str) -> Optional[Path]:
        """Locate the stored body bytes for one HTTP message."""

        if not message_public_id or message_public_id == "None":
            return None
        project = inspect_project(self.root)
        database = Database(project.root / "project.sqlite")
        with database.connect() as connection:
            row = connection.execute(
                "SELECT b.relative_path FROM protocol_message pm "
                "JOIN http_body hb ON hb.protocol_message_id = pm.id "
                "JOIN evidence e ON e.id = hb.evidence_id "
                "JOIN blob b ON b.id = e.blob_id "
                "WHERE pm.message_id = ?",
                (message_public_id,),
            ).fetchone()
        if row is None:
            return None
        return self.root / Path(str(row["relative_path"]))

    def rescan_stages(self) -> list[AnalysisStage]:
        """Cheap re-scan after a flag-format change (no tshark re-runs)."""

        def guarded(key: str, runner):
            def run_guarded():
                try:
                    return runner()
                except Exception as error:  # noqa: BLE001 - degraded, not fatal
                    return {"status": "failed", "stage": key, "reason": str(error)}

            return run_guarded

        return [
            AnalysisStage(
                "triage",
                "Re-rank candidates with the new flag format",
                guarded("triage", lambda: triage_project(self.root)),
            ),
            AnalysisStage(
                "detect",
                "Re-run detectors",
                guarded("detect", lambda: detect_project(self.root)),
            ),
        ]

    # ---------------------------------------------------------------- analysis

    def _observed_protocol_labels(self) -> set[str]:
        return {
            str(item.get("protocol_label"))
            for item in _payload(
                query_summary(
                    self.root,
                    protocol_limit=PAGE_LIMIT,
                    conversation_limit=1,
                )
            ).get("protocols", [])
        }

    def _capture_for_rerun(self, capture: Optional[Path]) -> Optional[Path]:
        """Re-run the base analysis when an opened project has no HTTP facts.

        Re-opening an existing project or using the menu action passes
        ``capture=None``; without this fallback the HTTP page stays empty
        forever because only the ``analyze`` stage writes transactions.
        """

        if capture is not None:
            return capture
        try:
            transactions = _payload(query_transactions(self.root, offset=0, limit=1))
            if int(transactions.get("total", 0)) > 0:
                return None
            stored = inspect_project(self.root).capture_path
        except (OSError, ValueError, KeyError):
            return None
        return stored if stored.is_file() else None

    def analysis_stages(
        self,
        tshark: Path,
        *,
        capture: Optional[Path] = None,
        tls_rsa_key: Optional[TlsRsaKey] = None,
        tls_keylog: Optional[TlsKeylog] = None,
    ) -> list[AnalysisStage]:
        """Return the ordered bounded analysis pipeline for this project.

        ``capture`` prefixes the metadata/body extraction stage; when omitted
        but the project has no indexed transactions yet, the stored capture
        path is used so a re-opened project still gets a full first analysis.
        """

        from ..pcap_repair import ensure_working_capture

        ensure_working_capture(self.root)

        def guarded(key: str, runner: Callable[[], object]) -> Callable[[], object]:
            """Degrade one stage's failure into a recorded skip.

            A stage that cannot run (missing optional capability, partial
            probe, unexpected data) must not abort the remaining pipeline:
            it returns a status payload the UI can surface instead. The base
            analysis stage is exempt — if HTTP extraction fails nothing
            downstream can work, so the failure must stay loud.
            """

            if key == "analyze":
                return runner

            def run_guarded() -> object:
                try:
                    return runner()
                except Exception as error:  # noqa: BLE001 - degraded, not fatal
                    return {
                        "status": "failed",
                        "stage": key,
                        "reason": str(error),
                    }

            return run_guarded

        stages: list[AnalysisStage] = []
        rerun_capture = self._capture_for_rerun(capture)
        if rerun_capture is not None:
            stages.append(
                AnalysisStage(
                    "analyze",
                    "Extract HTTP metadata, bodies, and transforms",
                    guarded(
                        "analyze",
                        lambda: analyze_with_bodies(
                            rerun_capture,
                            self.root,
                            tshark,
                            uri=None,
                            max_body_bytes=16 * 1024 * 1024,
                            max_total_bytes=64 * 1024 * 1024,
                            run_scan=True,
                            tls_rsa_key=tls_rsa_key,
                            tls_keylog=tls_keylog,
                        ),
                    ),
                )
            )

        def voip_stage() -> object:
            if "rtp" not in self._observed_protocol_labels():
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
            try:
                return index_ftp(self.root, tshark, capabilities=capabilities)
            except ValueError as error:
                # Partial capability probes must skip FTP, not abort the run.
                return {"status": "unavailable", "reason": str(error)}

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
            try:
                summary = extract_smtp_messages(self.root, tshark, capabilities=capabilities)
            except ValueError as error:
                return {"status": "unavailable", "reason": str(error)}
            rebuild_manual_queue(self.root)
            return summary

        def telnet_stage() -> object:
            if "telnet" not in self._observed_protocol_labels():
                return {"status": "not-applicable", "reason": "no Telnet protocol observed"}
            summary = index_telnet(self.root, tshark)
            rebuild_manual_queue(self.root)
            return summary

        def dns_stage() -> object:
            if "dns" not in self._observed_protocol_labels():
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
            data_summary = triage_icmp_data(self.root, tshark)
            snmp_summary = triage_snmp_strings(self.root, tshark)
            rebuild_manual_queue(self.root)
            if isinstance(summary, dict) or not hasattr(summary, "to_json"):
                return summary
            payload = json.loads(summary.to_json())
            payload["data_payloads"] = {
                "status": data_summary.status,
                "frames": data_summary.frames,
                "payload_bytes": data_summary.payload_bytes,
            }
            payload["snmp_strings"] = {
                "status": snmp_summary.status,
                "frames": snmp_summary.frames,
                "value_bytes": snmp_summary.value_bytes,
            }
            return payload

        def usb_hid_stage() -> object:
            summary = triage_usb_hid(self.root, tshark)
            rebuild_manual_queue(self.root)
            return summary

        stages.extend(
            [
                AnalysisStage(
                    "ftp",
                    "Correlate FTP control and data transfers",
                    guarded("ftp", ftp_stage),
                ),
                AnalysisStage(
                    "tftp",
                    "Reconstruct TFTP uploads and downloads",
                    guarded("tftp", tftp_stage),
                ),
                AnalysisStage(
                    "smtp",
                    "Recover SMTP messages and MIME attachments",
                    guarded("smtp", smtp_stage),
                ),
                AnalysisStage(
                    "scan",
                    "Apply transforms and carve static files",
                    guarded("scan", lambda: scan_project(self.root, with_files=True)),
                ),
                AnalysisStage(
                    "inventory",
                    "Build capture summary and manual queue",
                    guarded("inventory", lambda: index_summary(self.root, tshark)),
                ),
                AnalysisStage(
                    "frames",
                    "Index packet list columns for the traffic page",
                    guarded("frames", lambda: extract_frame_columns(self.root, tshark)),
                ),
                AnalysisStage(
                    "tcp-text",
                    "Reconstruct and inspect generic TCP data streams",
                    guarded("tcp-text", lambda: triage_tcp_text(self.root, tshark)),
                ),
                AnalysisStage(
                    "telnet",
                    "Index directional Telnet dialogues",
                    guarded("telnet", telnet_stage),
                ),
                AnalysisStage(
                    "dns",
                    "Triage encoded DNS labels and recover validated files",
                    guarded("dns", dns_stage),
                ),
                AnalysisStage(
                    "icmp",
                    "Inspect ICMP echo side channels and printable TTL oracles",
                    guarded("icmp", icmp_stage),
                ),
                AnalysisStage(
                    "tcp-urgent",
                    "Inspect TCP urgent-pointer side channels",
                    guarded("tcp-urgent", tcp_urgent_stage),
                ),
                AnalysisStage(
                    "usb-hid",
                    "Triage USB HID input report series",
                    guarded("usb-hid", usb_hid_stage),
                ),
                AnalysisStage(
                    "voip",
                    "Reconstruct supported RTP audio and preserve VoIP hints",
                    guarded("voip", voip_stage),
                ),
                AnalysisStage(
                    "triage",
                    "Rank known-format and sensitive-field candidates",
                    guarded("triage", lambda: triage_project(self.root)),
                ),
                AnalysisStage(
                    "detect",
                    "Run unknown-candidate, SQL-injection, and WebShell detectors",
                    guarded("detect", lambda: detect_project(self.root)),
                ),
            ]
        )
        return stages
