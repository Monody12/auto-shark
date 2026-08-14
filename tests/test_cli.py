import json

from auto_shark import cli
from auto_shark.ftp import FtpIndexSummary
from auto_shark.queries import TelnetQueryPage
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
    assert json.loads(capsys.readouterr().out)["schema_version"] == (
        "auto-shark.telnet-index/v1"
    )


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
