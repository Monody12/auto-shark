import json
from types import SimpleNamespace

from auto_shark import cli
from auto_shark.detectors import ProjectDetectionSummary
from auto_shark.exporting import ExportLimits, ExportSummary
from auto_shark.ftp import FtpIndexSummary
from auto_shark.inventory import InventorySummary
from auto_shark.investigation import NotesPage
from auto_shark.m4_queries import FindingsPage, TimelinePage
from auto_shark.queries import TelnetQueryPage
from auto_shark.reporting import ReportDocument, ReportLimits
from auto_shark.telnet import TelnetIndexSummary
from auto_shark.triage import TriageSummary


def test_triage_cli_forwards_limits_and_emits_schema(monkeypatch, capsys, tmp_path) -> None:
    received = {}

    def fake_triage(project, **limits):
        received["project"] = project
        received.update(limits)
        return TriageSummary(
            schema_version="auto-shark.triage/v1",
            project=str(project),
            evidence_selected=0,
            evidence_scanned=0,
            scanned_bytes=0,
            complete=0,
            input_truncated=0,
            candidate_limited=0,
            skipped_budget=0,
            skipped_limit=0,
            failed=0,
            known_matches=0,
            field_candidates=0,
            candidates=(),
        )

    monkeypatch.setattr(cli, "triage_project", fake_triage)
    project = tmp_path / "sample.auto-shark"

    result = cli.main(
        [
            "triage",
            str(project),
            "--max-evidence",
            "7",
            "--max-evidence-bytes",
            "11",
            "--max-total-bytes",
            "13",
            "--max-matches",
            "17",
            "--max-candidates",
            "19",
            "--max-field-bytes",
            "23",
            "--window-bytes",
            "29",
        ]
    )

    assert result == 0
    assert received == {
        "project": project,
        "max_evidence": 7,
        "max_evidence_bytes": 11,
        "max_total_bytes": 13,
        "max_matches_per_evidence": 17,
        "max_candidates": 19,
        "max_field_bytes": 23,
        "window_bytes": 29,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "auto-shark.triage/v1"


def test_triage_cli_reports_invalid_limits(capsys, tmp_path) -> None:
    result = cli.main(["triage", str(tmp_path), "--max-total-bytes", "0"])
    assert result == 2
    assert "triage limits must be positive" in capsys.readouterr().err


def test_cli_reports_runtime_tool_failures_without_a_traceback(
    monkeypatch, capsys, tmp_path
) -> None:
    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic external tool failure")

    monkeypatch.setattr(cli, "triage_project", fail)

    assert cli.main(["triage", str(tmp_path)]) == 2
    assert capsys.readouterr().err == "error: synthetic external tool failure\n"


def test_analyze_cli_forwards_loaded_tls_rsa_key(monkeypatch, capsys, tmp_path) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")
    key_path = tmp_path / "challenge.pem"
    key_path.write_bytes(b"synthetic key")
    received = {}

    def fake_analyze(capture_path, project, tshark, **options):
        received.update(
            capture=capture_path,
            project=project,
            tshark=tshark,
            **options,
        )
        return SimpleNamespace(to_json=lambda: '{"status":"ok"}')

    monkeypatch.setattr(cli, "find_tshark", lambda _path: executable)
    monkeypatch.setattr(cli, "analyze_http", fake_analyze)
    project = tmp_path / "case.auto-shark"

    result = cli.main(
        [
            "analyze",
            str(capture),
            "--project",
            str(project),
            "--tshark",
            str(executable),
            "--tls-rsa-key",
            str(key_path),
        ]
    )

    assert result == 0
    assert received["capture"] == capture
    assert received["project"] == project
    assert received["tshark"] == executable
    assert received["tls_rsa_key"].path == key_path.resolve()
    assert len(received["tls_rsa_key"].sha256) == 64
    assert json.loads(capsys.readouterr().out) == {"status": "ok"}


def test_specialized_cli_stages_refresh_manual_queue(monkeypatch, capsys, tmp_path) -> None:
    project = tmp_path / "sample.auto-shark"
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")
    events = []
    monkeypatch.setattr(cli, "find_tshark", lambda _path: executable)
    monkeypatch.setattr(
        cli,
        "rebuild_manual_queue",
        lambda value: events.append(("queue", value)),
    )

    for command, function_name in (
        ("voip-extract", "extract_voip_audio"),
        ("tcp-urgent", "triage_tcp_urgent"),
        ("usb-hid", "triage_usb_hid"),
    ):

        def fake_stage(value, tshark, _name=function_name, **_limits):
            events.append((_name, value, tshark))
            return SimpleNamespace(to_json=lambda: json.dumps({"stage": _name}) + "\n")

        monkeypatch.setattr(cli, function_name, fake_stage)
        assert cli.main([command, str(project), "--tshark", str(executable)]) == 0

    assert events == [
        ("extract_voip_audio", project, executable),
        ("queue", project),
        ("triage_tcp_urgent", project, executable),
        ("queue", project),
        ("triage_usb_hid", project, executable),
        ("queue", project),
    ]
    assert capsys.readouterr().out.count('"stage"') == 3


def test_investigation_cli_commands_forward_values(monkeypatch, capsys, tmp_path) -> None:
    calls = []
    project = tmp_path / "sample.auto-shark"

    def fake_review(value, subject_kind, subject_id, state):
        calls.append(("review", value, subject_kind, subject_id, state))
        return {"schema_version": "auto-shark.review-mark/v1"}

    def fake_add(value, subject_kind, subject_id, body, **limits):
        calls.append(("add", value, subject_kind, subject_id, body, limits))
        return {"schema_version": "auto-shark.note/v1"}

    def fake_update(value, note_id, body, **limits):
        calls.append(("update", value, note_id, body, limits))
        return {"schema_version": "auto-shark.note/v1"}

    def fake_query(value, **limits):
        calls.append(("query", value, limits))
        return NotesPage(
            "auto-shark.notes/v1",
            limits["offset"],
            limits["limit"],
            0,
            0,
            limits["max_body_bytes"],
            limits["subject_kind"],
            limits["subject_id"],
            (),
        )

    monkeypatch.setattr(cli, "set_review_mark", fake_review)
    monkeypatch.setattr(cli, "add_note", fake_add)
    monkeypatch.setattr(cli, "update_note", fake_update)
    monkeypatch.setattr(cli, "query_notes", fake_query)

    assert (
        cli.main(
            ["review-mark", str(project), "candidate", "candidate-1", "--state", "key_evidence"]
        )
        == 0
    )
    assert (
        cli.main(
            [
                "note-add",
                str(project),
                "candidate",
                "candidate-1",
                "--body",
                "first",
                "--max-note-bytes",
                "7",
            ]
        )
        == 0
    )
    assert (
        cli.main(
            ["note-update", str(project), "note-1", "--body", "second", "--max-note-bytes", "11"]
        )
        == 0
    )
    assert (
        cli.main(
            [
                "notes",
                str(project),
                "--subject-kind",
                "candidate",
                "--subject-id",
                "candidate-1",
                "--offset",
                "1",
                "--limit",
                "2",
                "--max-body-bytes",
                "13",
            ]
        )
        == 0
    )

    assert calls == [
        ("review", project, "candidate", "candidate-1", "key_evidence"),
        ("add", project, "candidate", "candidate-1", "first", {"max_note_bytes": 7}),
        ("update", project, "note-1", "second", {"max_note_bytes": 11}),
        (
            "query",
            project,
            {
                "subject_kind": "candidate",
                "subject_id": "candidate-1",
                "offset": 1,
                "limit": 2,
                "max_body_bytes": 13,
            },
        ),
    ]
    assert capsys.readouterr().out.count('"schema_version"') == 4


def test_report_cli_forwards_independent_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}
    project = tmp_path / "sample.auto-shark"

    def fake_report(value, *, limits):
        received["project"] = value
        received["limits"] = limits
        return ReportDocument({"schema_version": "auto-shark.report/v1"})

    monkeypatch.setattr(cli, "collect_report", fake_report)
    values = tuple(range(1, 17))
    result = cli.main(
        [
            "report",
            str(project),
            "--max-protocols",
            "1",
            "--max-conversations",
            "2",
            "--max-candidates",
            "3",
            "--max-findings",
            "4",
            "--max-events",
            "5",
            "--max-artifacts",
            "6",
            "--max-manual-tasks",
            "7",
            "--max-review-marks",
            "8",
            "--max-notes",
            "9",
            "--max-evidence",
            "10",
            "--max-tool-runs",
            "11",
            "--max-detector-runs",
            "12",
            "--max-signals",
            "13",
            "--max-evidence-links",
            "14",
            "--max-detail-bytes",
            "15",
            "--max-note-bytes",
            "16",
        ]
    )

    assert result == 0
    assert received == {
        "project": project,
        "limits": ReportLimits(*values),
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "auto-shark.report/v1"


def test_export_cli_forwards_report_and_evidence_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}
    project = tmp_path / "sample.auto-shark"
    destination = tmp_path / "out"

    def fake_export(value, output, *, report_limits, export_limits):
        received.update(
            {
                "project": value,
                "output": output,
                "report_limits": report_limits,
                "export_limits": export_limits,
            }
        )
        return ExportSummary("auto-shark.export/v1", str(output), "r", "h", 0, 0, 0, ())

    monkeypatch.setattr(cli, "export_bundle", fake_export)
    assert (
        cli.main(
            [
                "export",
                str(project),
                str(destination),
                "--no-evidence",
                "--max-evidence-items",
                "7",
                "--max-evidence-item-bytes",
                "11",
                "--max-evidence-total-bytes",
                "13",
                "--max-events",
                "17",
                "--max-detail-bytes",
                "19",
            ]
        )
        == 0
    )
    assert received == {
        "project": project,
        "output": destination,
        "report_limits": ReportLimits(events=17, detail_bytes=19),
        "export_limits": ExportLimits(
            include_evidence=False,
            max_evidence_items=7,
            max_evidence_item_bytes=11,
            max_evidence_total_bytes=13,
        ),
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "auto-shark.export/v1"


def test_detect_cli_forwards_unknown_candidate_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}

    def fake_detect(project, **limits):
        received["project"] = project
        received.update(limits)
        return ProjectDetectionSummary(
            schema_version="auto-shark.detect/v1",
            project=str(project),
            status="completed",
            detector_runs=("unknown", "sql"),
            inputs_processed=0,
            inputs_skipped=0,
            candidates=0,
            findings=0,
            events=0,
        )

    monkeypatch.setattr(cli, "detect_project", fake_detect)
    project = tmp_path / "sample.auto-shark"
    result = cli.main(
        [
            "detect",
            str(project),
            "--max-evidence",
            "7",
            "--max-evidence-bytes",
            "11",
            "--max-total-bytes",
            "13",
            "--max-matches",
            "17",
            "--max-candidates",
            "19",
            "--chunk-size",
            "23",
            "--max-transactions",
            "29",
            "--max-parameters",
            "31",
            "--max-parameter-bytes",
            "37",
            "--max-events",
            "41",
            "--max-findings",
            "43",
            "--max-preview-bytes",
            "47",
            "--max-webshell-fields",
            "53",
            "--max-webshell-value-bytes",
            "59",
            "--max-ognl-fields",
            "61",
            "--max-ognl-body-bytes",
            "67",
        ]
    )

    assert result == 0
    assert received == {
        "project": project,
        "max_evidence": 7,
        "max_evidence_bytes": 11,
        "max_total_bytes": 13,
        "max_matches": 17,
        "max_candidates": 19,
        "chunk_size": 23,
        "max_transactions": 29,
        "max_parameters": 31,
        "max_parameter_bytes": 37,
        "max_events": 41,
        "max_findings": 43,
        "max_preview_bytes": 47,
        "max_webshell_fields": 53,
        "max_webshell_value_bytes": 59,
        "max_ognl_fields": 61,
        "max_ognl_body_bytes": 67,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "auto-shark.detect/v1"


def test_findings_cli_forwards_independent_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}
    project = tmp_path / "sample.auto-shark"

    def fake_query(value, **limits):
        received["project"] = value
        received.update(limits)
        return FindingsPage(
            "auto-shark.findings/v1",
            str(value),
            limits["candidate_offset"],
            limits["candidate_limit"],
            0,
            limits["finding_offset"],
            limits["finding_limit"],
            0,
            limits["max_signals"],
            limits["max_evidence_links"],
            limits["max_detail_bytes"],
            0,
            0,
            (),
            (),
        )

    monkeypatch.setattr(cli, "query_findings", fake_query)
    result = cli.main(
        [
            "findings",
            str(project),
            "--candidate-offset",
            "1",
            "--candidate-limit",
            "2",
            "--finding-offset",
            "3",
            "--finding-limit",
            "4",
            "--max-signals",
            "5",
            "--max-evidence-links",
            "6",
            "--max-detail-bytes",
            "7",
        ]
    )
    assert result == 0
    assert received == {
        "project": project,
        "candidate_offset": 1,
        "candidate_limit": 2,
        "finding_offset": 3,
        "finding_limit": 4,
        "max_signals": 5,
        "max_evidence_links": 6,
        "max_detail_bytes": 7,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "auto-shark.findings/v1"


def test_timeline_cli_forwards_filters_and_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}
    project = tmp_path / "sample.auto-shark"

    def fake_query(value, **limits):
        received["project"] = value
        received.update(limits)
        return TimelinePage(
            "auto-shark.timeline/v1",
            str(value),
            limits["offset"],
            limits["limit"],
            0,
            0,
            limits["include_duplicates"],
            limits["max_evidence_links"],
            limits["max_detail_bytes"],
            0,
            (),
        )

    monkeypatch.setattr(cli, "query_timeline", fake_query)
    result = cli.main(
        [
            "timeline",
            str(project),
            "--event-kind",
            "file-read",
            "--status",
            "complete",
            "--frame-start",
            "10",
            "--frame-end",
            "20",
            "--include-duplicates",
            "--offset",
            "1",
            "--limit",
            "2",
            "--max-evidence-links",
            "3",
            "--max-detail-bytes",
            "4",
        ]
    )
    assert result == 0
    assert received == {
        "project": project,
        "detector": "static-webshell-activity",
        "event_kind": "file-read",
        "status": "complete",
        "frame_start": 10,
        "frame_end": 20,
        "include_duplicates": True,
        "offset": 1,
        "limit": 2,
        "max_evidence_links": 3,
        "max_detail_bytes": 4,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "auto-shark.timeline/v1"


def test_index_ftp_cli_forwards_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"tool")

    def fake_index(project, tshark, **limits):
        received.update({"project": project, "tshark": tshark, **limits})
        return FtpIndexSummary(
            schema_version="auto-shark.ftp-index/v1",
            project=str(project),
            messages=0,
            skipped_messages=0,
            transfers=0,
            complete=0,
            unresolved=0,
            skipped_limit=0,
            skipped_budget=0,
            partial=0,
            conflicting=0,
            truncated=0,
            empty=0,
            failed=0,
            output_bytes=0,
            artifacts=0,
        )

    monkeypatch.setattr(cli, "index_ftp", fake_index)
    project = tmp_path / "sample.auto-shark"
    result = cli.main(
        [
            "index-ftp",
            str(project),
            "--tshark",
            str(executable),
            "--max-messages",
            "7",
            "--max-transfers",
            "11",
            "--max-index-bytes",
            "13",
            "--max-transfer-bytes",
            "17",
            "--max-total-bytes",
            "19",
        ]
    )
    assert result == 0
    assert received == {
        "project": project,
        "tshark": executable.resolve(),
        "max_messages": 7,
        "max_transfers": 11,
        "max_index_payload_bytes": 13,
        "max_transfer_bytes": 17,
        "max_total_output_bytes": 19,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "auto-shark.ftp-index/v1"


def test_smtp_extract_cli_forwards_limits_and_refreshes_queue(
    monkeypatch, capsys, tmp_path
) -> None:
    received = {}
    events = []
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"tool")
    project = tmp_path / "mail.auto-shark"

    def fake_extract(project_path, tshark_path, **limits):
        received.update(project=project_path, tshark=tshark_path, **limits)
        return SimpleNamespace(
            to_json=lambda: json.dumps({"schema_version": "auto-shark.smtp-mime/v1"}) + "\n"
        )

    monkeypatch.setattr(cli, "find_tshark", lambda _path: executable)
    monkeypatch.setattr(cli, "extract_smtp_messages", fake_extract)
    monkeypatch.setattr(cli, "rebuild_manual_queue", lambda value: events.append(value))

    result = cli.main(
        [
            "smtp-extract",
            str(project),
            "--tshark",
            str(executable),
            "--max-streams",
            "3",
            "--max-messages",
            "5",
            "--max-stream-bytes",
            "7",
            "--max-message-bytes",
            "11",
            "--max-message-total",
            "13",
            "--max-attachments",
            "17",
            "--max-attachment-bytes",
            "19",
            "--max-attachment-total",
            "23",
        ]
    )

    assert result == 0
    assert received == {
        "project": project,
        "tshark": executable,
        "max_streams": 3,
        "max_messages": 5,
        "max_stream_bytes": 7,
        "max_message_bytes": 11,
        "max_total_message_bytes": 13,
        "max_attachments": 17,
        "max_attachment_bytes": 19,
        "max_total_attachment_bytes": 23,
    }
    assert events == [project]
    assert json.loads(capsys.readouterr().out)["schema_version"] == ("auto-shark.smtp-mime/v1")


def test_index_telnet_cli_forwards_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"tool")

    def fake_index(project, tshark, **limits):
        received.update({"project": project, "tshark": tshark, **limits})
        return TelnetIndexSummary(
            schema_version="auto-shark.telnet-index/v1",
            project=str(project),
            metadata_frames=0,
            skipped_metadata_frames=0,
            streams=0,
            complete=0,
            partial=0,
            conflicting=0,
            truncated=0,
            unresolved_role=0,
            failed=0,
            records=0,
            parsed_bytes=0,
            skipped_bytes=0,
        )

    monkeypatch.setattr(cli, "index_telnet", fake_index)
    project = tmp_path / "sample.auto-shark"
    result = cli.main(
        [
            "index-telnet",
            str(project),
            "--tshark",
            str(executable),
            "--max-metadata-frames",
            "3",
            "--max-streams",
            "5",
            "--max-records",
            "7",
            "--max-record-bytes",
            "11",
            "--max-index-bytes",
            "13",
            "--max-direction-bytes",
            "17",
            "--max-total-bytes",
            "19",
        ]
    )

    assert result == 0
    assert received == {
        "project": project,
        "tshark": executable.resolve(),
        "max_metadata_frames": 3,
        "max_streams": 5,
        "max_records": 7,
        "max_record_bytes": 11,
        "max_index_payload_bytes": 13,
        "max_direction_bytes": 17,
        "max_total_bytes": 19,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == ("auto-shark.telnet-index/v1")


def test_telnet_dialogues_cli_forwards_query_limits(monkeypatch, capsys, tmp_path) -> None:
    received = {}

    def fake_query(project, **limits):
        received.update({"project": project, **limits})
        return TelnetQueryPage(
            schema_version="auto-shark.telnet-dialogues/v1",
            project=str(project),
            offset=limits["offset"],
            limit=limits["limit"],
            total=0,
            count=0,
            max_records_per_dialogue=limits["max_records_per_dialogue"],
            max_preview_bytes=limits["max_preview_bytes"],
            max_total_preview_bytes=limits["max_total_preview_bytes"],
            max_source_mappings=limits["max_source_mappings"],
            max_relations=limits["max_relations"],
            max_candidates=limits["max_candidates"],
            preview_bytes=0,
            items=(),
        )

    monkeypatch.setattr(cli, "query_telnet_dialogues", fake_query)
    project = tmp_path / "sample.auto-shark"
    result = cli.main(
        [
            "telnet-dialogues",
            str(project),
            "--stream",
            "2",
            "--offset",
            "3",
            "--limit",
            "5",
            "--max-records",
            "7",
            "--max-preview-bytes",
            "11",
            "--max-total-preview-bytes",
            "13",
            "--max-source-mappings",
            "17",
            "--max-relations",
            "19",
            "--max-candidates",
            "23",
        ]
    )

    assert result == 0
    assert received == {
        "project": project,
        "stream": 2,
        "offset": 3,
        "limit": 5,
        "max_records_per_dialogue": 7,
        "max_preview_bytes": 11,
        "max_total_preview_bytes": 13,
        "max_source_mappings": 17,
        "max_relations": 19,
        "max_candidates": 23,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == (
        "auto-shark.telnet-dialogues/v1"
    )


def test_index_summary_cli_forwards_inventory_limits(monkeypatch, capsys, tmp_path) -> None:
    project = tmp_path / "case.auto-shark"
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")
    observed = {}
    monkeypatch.setattr(cli, "find_tshark", lambda _: executable)

    def fake_index(project_path, tshark_path, **limits):
        observed.update(limits)
        assert project_path == project
        assert tshark_path == executable
        return InventorySummary(
            project=str(project),
            schema_version="auto-shark.summary/v1",
            inventory_run_id="run",
            status="completed",
            processed_frames=3,
            skipped_frames=0,
            skipped_conversations=0,
            skipped_protocol_labels=0,
            protocol_observations=4,
            conversation_profiles=2,
            coverage={"not-run": 6},
        )

    monkeypatch.setattr(cli, "index_summary", fake_index)
    result = cli.main(
        [
            "index-summary",
            str(project),
            "--tshark",
            str(executable),
            "--max-frames",
            "11",
            "--max-protocol-labels",
            "12",
            "--max-conversations",
            "13",
        ]
    )
    assert result == 0
    assert observed == {
        "max_frames": 11,
        "max_protocol_labels": 12,
        "max_conversations": 13,
        "max_parts": 10_000,
        "max_body_scan_bytes": 4 * 1024 * 1024,
        "max_tasks": 10_000,
        "max_signals": 50_000,
        "max_evidence_links": 100_000,
        "max_unsupported_tasks": 25,
    }
    assert json.loads(capsys.readouterr().out)["schema_version"] == "auto-shark.summary/v1"
