import json

from auto_shark import cli
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
