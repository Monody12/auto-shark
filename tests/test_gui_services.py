import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from auto_shark import cli
from auto_shark.engines.tshark import TlsRsaKey
from auto_shark.gui.services import (
    AnalysisStage,
    ProjectServices,
    create_new_project,
    resolve_tshark,
)
from auto_shark.project import create_project
from auto_shark.storage import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _services_project(tmp_path: Path):
    capture = tmp_path / "source.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "gui.auto-shark"
    create_project(capture, root, allow_synced=True)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
        connection.execute(
            "INSERT INTO evidence"
            "(evidence_id,capture_id,source_kind,frame_start,frame_end,byte_offset,"
            "byte_length,text_value,blob_id,locator_json) "
            "VALUES('evidence-1',?, 'test',1,1,0,4,'flag{gui}',NULL,?)",
            (capture_id, json.dumps({"local": str(root)})),
        )
        evidence_id = int(
            connection.execute("SELECT id FROM evidence WHERE evidence_id='evidence-1'").fetchone()[
                0
            ]
        )
        connection.execute(
            "INSERT INTO candidate"
            "(candidate_id,kind,raw_value,normalized_value,confidence,rank_score,created_at) "
            "VALUES('candidate-1','known-flag','flag{gui}','flag{gui}',1,100,?)",
            (_now(),),
        )
        candidate_id = int(connection.execute("SELECT id FROM candidate").fetchone()[0])
        connection.execute(
            "INSERT INTO candidate_evidence(candidate_id,evidence_id,role) VALUES(?,?,'match')",
            (candidate_id, evidence_id),
        )
        connection.execute(
            "INSERT INTO candidate_signal"
            "(signal_id,candidate_id,evidence_id,detector,detector_version,signal_name,"
            "contribution,detail_json) VALUES('signal-1',?,?,'test','1','match',100,?)",
            (candidate_id, evidence_id, "{}"),
        )
        connection.execute(
            "INSERT INTO finding"
            "(finding_id,detector,detector_version,title,description,severity,confidence,"
            "recommended_action,created_at) VALUES('finding-1','test','1','title','desc',"
            "'medium',0.5,NULL,?)",
            (_now(),),
        )
        finding_id = int(connection.execute("SELECT id FROM finding").fetchone()[0])
        connection.execute(
            "INSERT INTO finding_evidence(finding_id,evidence_id,role) VALUES(?,?,'support')",
            (finding_id, evidence_id),
        )
    return root


def test_services_read_payloads_and_info(tmp_path) -> None:
    root = _services_project(tmp_path)
    services = ProjectServices(root)

    info = services.info()
    assert info.root == root.resolve()
    assert info.database_schema >= 14

    overview = services.overview()
    assert overview["schema_version"] == "auto-shark.report/v1"
    assert overview["overview"]["candidates"] == 1
    assert overview["overview"]["findings"] == 1

    findings = services.findings()
    assert findings["schema_version"] == "auto-shark.findings/v1"
    assert findings["candidate_total"] == 1
    assert findings["finding_total"] == 1
    assert findings["candidates"][0]["candidate_id"] == "candidate-1"
    assert findings["findings"][0]["finding_id"] == "finding-1"

    for payload, key in (
        (services.summary(), "protocols"),
        (services.transactions(), "items"),
        (services.streams(), "items"),
        (services.telnet_dialogues(), "items"),
        (services.timeline(), "items"),
        (services.manual_queue(), "items"),
        (services.notes(), "items"),
    ):
        assert key in payload


def test_services_mutations_round_trip(tmp_path) -> None:
    root = _services_project(tmp_path)
    services = ProjectServices(root)

    mark = services.set_review_mark("candidate", "candidate-1", "key_evidence")
    assert mark["state"] == "key_evidence"
    note = services.add_note("candidate", "candidate-1", "first body")
    note_id = note["note_id"]
    updated = services.update_note(note_id, "second body")
    assert updated["note_id"] == note_id
    page = services.notes(subject_kind="candidate", subject_id="candidate-1")
    assert page["total"] == 1
    assert page["items"][0]["body"] == "second body"
    assert page["items"][0]["subject_id"] == "candidate-1"


def test_services_export_and_stages(tmp_path) -> None:
    root = _services_project(tmp_path)
    services = ProjectServices(root)

    export = services.export_bundle_to(tmp_path / "bundle")
    assert export["schema_version"] == "auto-shark.export/v1"
    assert (tmp_path / "bundle" / "manifest.json").is_file()

    stages = services.analysis_stages(Path("tshark.exe"))
    assert [stage.key for stage in stages] == [
        "ftp",
        "tftp",
        "smtp",
        "scan",
        "triage",
        "detect",
        "inventory",
        "tcp-text",
        "dns",
        "icmp",
        "tcp-urgent",
        "usb-hid",
        "voip",
    ]
    with_capture = services.analysis_stages(Path("tshark.exe"), capture=Path("cap.pcap"))
    assert [stage.key for stage in with_capture] == [
        "analyze",
        "ftp",
        "tftp",
        "smtp",
        "scan",
        "triage",
        "detect",
        "inventory",
        "tcp-text",
        "dns",
        "icmp",
        "tcp-urgent",
        "usb-hid",
        "voip",
    ]
    scan_summary = with_capture[4].run()
    assert hasattr(scan_summary, "to_json")


def test_gui_analysis_stage_forwards_tls_rsa_key(tmp_path, monkeypatch) -> None:
    root = _services_project(tmp_path)
    key_path = tmp_path / "challenge.pem"
    key_path.write_bytes(b"key")
    key = TlsRsaKey(key_path, 3, hashlib.sha256(b"key").hexdigest())
    received = {}

    def fake_analyze(capture, project, tshark, **options):
        received.update(capture=capture, project=project, tshark=tshark, **options)
        return "analyzed"

    monkeypatch.setattr("auto_shark.gui.services.analyze_with_bodies", fake_analyze)
    stage = ProjectServices(root).analysis_stages(
        Path("tshark.exe"), capture=Path("capture.pcap"), tls_rsa_key=key
    )[0]

    assert stage.run() == "analyzed"
    assert received["tls_rsa_key"] is key


def test_stage_dataclass_and_tshark_resolution(tmp_path) -> None:
    stage = AnalysisStage("key", "title", lambda: "done")
    assert stage.run() == "done"
    assert resolve_tshark(Path("Z:/definitely-missing-tshark.exe")) is None
    root = tmp_path / "fresh.auto-shark"
    capture = tmp_path / "cap.pcap"
    capture.write_bytes(b"pcap")
    info = create_new_project(capture, root)
    assert (info.root / "project.sqlite").is_file()


def test_gui_ftp_stage_skips_tshark_without_required_fields(tmp_path, monkeypatch) -> None:
    root = _services_project(tmp_path)
    monkeypatch.setattr(
        "auto_shark.gui.services.probe_tshark",
        lambda _path: SimpleNamespace(features={"ftp": False}),
    )

    result = ProjectServices(root).analysis_stages(Path("tshark.exe"))[0].run()

    assert result == {
        "status": "unavailable",
        "reason": "TShark lacks the required FTP/FTP-DATA fields",
    }


def test_gui_specialized_stages_refresh_manual_queue(tmp_path, monkeypatch) -> None:
    root = _services_project(tmp_path)
    events = []
    monkeypatch.setattr(
        "auto_shark.gui.services.query_summary",
        lambda *_args, **_kwargs: {"protocols": [{"protocol_label": "rtp"}]},
    )
    monkeypatch.setattr(
        "auto_shark.gui.services.rebuild_manual_queue",
        lambda value: events.append(("queue", value)),
    )
    monkeypatch.setattr(
        "auto_shark.gui.services.probe_tshark",
        lambda _path: SimpleNamespace(features={"smtp": True}),
    )

    def fake_stage(name):
        def run(value, tshark, **_options):
            events.append((name, value, tshark))
            return name

        return run

    monkeypatch.setattr("auto_shark.gui.services.triage_tcp_urgent", fake_stage("tcp-urgent"))
    monkeypatch.setattr("auto_shark.gui.services.triage_usb_hid", fake_stage("usb-hid"))
    monkeypatch.setattr("auto_shark.gui.services.extract_voip_audio", fake_stage("voip"))
    monkeypatch.setattr("auto_shark.gui.services.extract_smtp_messages", fake_stage("smtp"))
    stages = {
        stage.key: stage for stage in ProjectServices(root).analysis_stages(Path("tshark.exe"))
    }

    assert stages["tcp-urgent"].run() == "tcp-urgent"
    assert stages["usb-hid"].run() == "usb-hid"
    assert stages["voip"].run() == "voip"
    assert stages["smtp"].run() == "smtp"
    assert events == [
        ("tcp-urgent", root, Path("tshark.exe")),
        ("queue", root),
        ("usb-hid", root, Path("tshark.exe")),
        ("queue", root),
        ("voip", root, Path("tshark.exe")),
        ("queue", root),
        ("smtp", root, Path("tshark.exe")),
        ("queue", root),
    ]


def test_gui_cli_forwards_project_without_importing_widgets(monkeypatch, tmp_path) -> None:
    received = {}

    def fake_run_gui(project=None):
        received["project"] = project
        return 0

    monkeypatch.setattr("auto_shark.gui.run_gui", fake_run_gui)
    assert cli.main(["gui", "--project", str(tmp_path)]) == 0
    assert received["project"] == tmp_path


def test_cli_import_stays_free_of_qt_and_widget_modules() -> None:
    code = (
        "import sys; import auto_shark.cli; "
        "print(any(m == 'PySide6' or m.startswith('PySide6.') "
        "or m == 'auto_shark.gui.main_window' for m in sys.modules))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_gui_display_autodetection_platform_aware(monkeypatch) -> None:
    from auto_shark.gui.app import display_available

    monkeypatch.setattr("sys.platform", "win32", raising=False)
    assert display_available() == (True, "")

    monkeypatch.setattr("sys.platform", "linux", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("XDG_SESSION_TYPE", raising=False)
    available, reason = display_available()
    assert available is False and "DISPLAY" in reason

    monkeypatch.setenv("XDG_SESSION_TYPE", "x11")
    assert display_available() == (True, "")
