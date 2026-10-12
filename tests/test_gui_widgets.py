import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

pytest.importorskip("PySide6", reason="GUI widget tests need the optional gui extra")

from PySide6.QtCore import QEventLoop, Qt, QTimer  # noqa: E402
from PySide6.QtGui import QAction  # noqa: E402
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QWidget,
)  # noqa: E402

from auto_shark.gui.main_window import PAGE_NAMES, MainWindow  # noqa: E402
from auto_shark.gui.services import AnalysisStage  # noqa: E402
from auto_shark.gui.workers import StageWorker  # noqa: E402
from auto_shark.project import create_project  # noqa: E402
from auto_shark.storage import Database  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def qapp():
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture(autouse=True)
def english_gui_locale(monkeypatch):
    """Keep legacy English assertions deterministic on Chinese Windows hosts."""
    monkeypatch.setenv("AUTO_SHARK_LANGUAGE", "en-US")


def _widget_project(tmp_path: Path) -> Path:
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
    return root


def test_window_builds_all_pages_with_no_project_state(qapp) -> None:
    window = MainWindow()
    assert window._nav.count() == len(PAGE_NAMES)
    assert [
        window._nav.item(index).data(Qt.ItemDataRole.UserRole)
        for index in range(window._nav.count())
    ] == list(PAGE_NAMES)
    for name in PAGE_NAMES:
        assert window._banners[name].text() == ""
        window._refresh_page(name)()
        assert "No project open" in window._banners[name].text()
    nav_labels = [window._nav.item(index).text() for index in range(window._nav.count())]
    assert "Timeline" not in nav_labels
    assert "Manual queue" not in nav_labels
    assert "Notes" not in nav_labels
    assert "Export" not in nav_labels
    assert window._help_button.text() == "?"
    assert window.services is None


def test_window_uses_simplified_chinese_for_chinese_locale(qapp, monkeypatch) -> None:
    monkeypatch.setenv("AUTO_SHARK_LANGUAGE", "zh-CN")
    window = MainWindow()

    assert window._language == "zh"
    assert window._nav.item(0).text() == "解题向导"
    assert window._nav.item(1).text() == "文件"
    assert window._nav.item(2).text() == "流量"
    assert window._nav.item(3).text() == "统计"
    assert window._nav.item(6).text() == "发现"
    assert window._overview_table.horizontalHeaderItem(0).text() == "指标"
    assert window._suggestions_table.horizontalHeaderItem(0).text() == "题型"
    assert window._suggestions_table.horizontalHeaderItem(2).text() == "建议"
    assert window._candidates_table.horizontalHeaderItem(1).text() == "考点"
    assert window._uri_edit.placeholderText() == "精确 URI，留空表示不过滤"


def test_open_project_populates_views_and_details(qapp, tmp_path) -> None:
    root = _widget_project(tmp_path)
    window = MainWindow()
    window.open_project(root)
    assert window.services is not None
    assert "schema" in window.statusBar().currentMessage()

    window._refresh_page("Overview")()
    assert window._overview_table.rowCount() >= 4
    assert '"auto-shark.report/v1"' in window._overview_json.toPlainText()

    window._refresh_page("HTTP")()
    assert "Showing 0 of 0" in window._banners["HTTP"].text()
    assert window._http_table.rowCount() == 0

    window._refresh_page("Findings")()
    assert window._candidates_table.rowCount() == 1
    assert window._candidates_table.item(0, 0).text() == "flag{gui}"
    window._candidates_table.selectRow(0)
    detail = window._details["Findings"].toPlainText()
    assert '"candidate_id": "candidate-1"' in detail
    assert '"signals"' in detail


def test_findings_table_shows_usb_key_sequence(qapp, tmp_path) -> None:
    root = _widget_project(tmp_path)
    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        evidence_id = int(
            connection.execute("SELECT id FROM evidence WHERE evidence_id='evidence-1'").fetchone()[
                0
            ]
        )
        connection.execute(
            "INSERT INTO finding(finding_id,detector,detector_version,title,description,"
            "severity,confidence,recommended_action,created_at) "
            "VALUES('finding-usb','usb-hid-triage','auto-shark.usb-hid-triage/v1',"
            "'USB HID boot-keyboard-like endpoint',"
            "'USB source 2.1.1 has 66 keyboard-like 8-byte reports. "
            "Key-down sequence preview: f, l, a, g, [, p, r, 3.',"
            "'medium',0.88,"
            "'Review key-down/release edges and correlate held keys with other USB devices.',?)",
            (_now(),),
        )
        finding_id = int(connection.execute("SELECT id FROM finding").fetchone()[0])
        connection.execute(
            "INSERT INTO finding_evidence(finding_id,evidence_id,role) "
            "VALUES(?,?,'usb-report-series')",
            (finding_id, evidence_id),
        )
    window = MainWindow()
    window.open_project(root)
    window._refresh_page("Findings")()
    assert window._findings_table.rowCount() == 1
    assert window._findings_table.item(0, 0).text() == "USB keyboard"
    look_at = window._findings_table.item(0, 1).text()
    assert look_at.startswith("Typed keys:")
    assert "flag[pr3" in look_at
    qapp.processEvents()
    assert window._findings_table.columnWidth(1) >= 160
    assert "flag[pr3" in window._findings_table.item(0, 1).toolTip()


def test_edit_menu_has_settings_and_omits_notes(qapp) -> None:
    window = MainWindow()
    texts = [action.text() for action in window.findChildren(QAction)]
    assert "&Settings…" in texts
    assert "Notes…" not in texts
    assert "Notes" not in window._pages


def test_help_button_shows_usage_card(qapp, monkeypatch) -> None:
    shown = []
    monkeypatch.setattr(
        QMessageBox, "information", lambda *args, **kwargs: shown.append(args) or 0
    )
    window = MainWindow()
    window._show_help()
    assert shown
    assert "Drag a .pcap" in str(shown[0][2])


def test_open_invalid_project_shows_error_and_keeps_state(qapp, tmp_path, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: calls.append(args))
    window = MainWindow()
    window.open_project(tmp_path / "missing.auto-shark")
    assert calls and window.services is None
    assert "No project open" in window.statusBar().currentMessage()


def _run_worker(worker: StageWorker) -> list:
    events: list = []
    loop = QEventLoop()

    def record(kind, *args):
        events.append((kind, *args))

    worker.stage_started.connect(lambda title: record("started", title))
    worker.stage_finished.connect(lambda key, summary: record("finished", key, summary))
    worker.stage_failed.connect(lambda key, error: record("failed", key, error))
    worker.finished_run.connect(
        lambda completed, message: (record("done", completed, message), loop.quit())
    )
    worker.start()
    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(loop.quit)
    timer.start(30_000)
    loop.exec()
    timer.stop()
    return events


def test_stage_worker_reports_each_stage(qapp) -> None:
    order = []

    def make(key):
        return AnalysisStage(key, f"title-{key}", lambda key=key: order.append(key) or key)

    worker = StageWorker([make("one"), make("two")])
    events = _run_worker(worker)
    assert order == ["one", "two"]
    kinds = [event[0] for event in events]
    assert kinds == ["started", "finished", "started", "finished", "done"]
    assert events[-1][1] is True
    assert "one" in events[-1][2] and "two" in events[-1][2]


def test_stage_worker_continues_after_failure(qapp) -> None:
    def boom():
        raise ValueError("boom")

    worker = StageWorker(
        [
            AnalysisStage("ok", "OK", lambda: "fine"),
            AnalysisStage("bad", "Bad", boom),
            AnalysisStage("never", "Never", lambda: "not reached"),
        ]
    )
    events = _run_worker(worker)
    kinds = [event[0] for event in events]
    # The failing stage is reported but the remaining stages still run so a
    # single degraded analyzer cannot leave every later page empty.
    assert kinds == [
        "started",
        "finished",
        "started",
        "failed",
        "started",
        "finished",
        "done",
    ]
    assert events[-1][1] is False
    assert "bad: boom" in events[-1][2]
    assert "ok" in events[-1][2] and "never" in events[-1][2]


def test_stage_worker_cancel_skips_remaining_stages(qapp) -> None:
    ran = []

    def slow_first():
        ran.append("first")
        worker.cancel()
        return "first"

    worker = StageWorker(
        [
            AnalysisStage("first", "First", slow_first),
            AnalysisStage("second", "Second", lambda: ran.append("second")),
        ]
    )
    events = _run_worker(worker)
    assert ran == ["first"]
    assert events[-1][1] is False
    assert "cancelled" in events[-1][2]


def test_settings_round_trip_and_tshark_resolution(qapp, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from auto_shark.gui.settings import GuiSettings, load_settings, save_settings

    save_settings(
        GuiSettings(
            tshark_path=str(tmp_path / "tshark.exe"),
            remote_host="ctf@192.168.1.10",
            remote_port=2222,
            ssh_identity=str(tmp_path / "id_ed25519"),
        )
    )
    loaded = load_settings()
    assert loaded.tshark_path == str(tmp_path / "tshark.exe")
    assert loaded.remote_host == "ctf@192.168.1.10"
    assert loaded.remote_port == 2222
    assert loaded.ssh_identity == str(tmp_path / "id_ed25519")

    (tmp_path / "tshark.exe").write_bytes(b"")
    window = MainWindow()
    assert window._settings.tshark_path == str(tmp_path / "tshark.exe")
    assert window._tshark_path() == tmp_path / "tshark.exe"

    save_settings(GuiSettings(tshark_path=None))
    window2 = MainWindow()
    assert window2._tshark_path() is None or window2._tshark_path().is_file()


def test_open_capture_creates_machine_local_project(qapp, tmp_path, monkeypatch) -> None:
    from PySide6.QtWidgets import QFileDialog

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    capture = tmp_path / "evidence.pcapng"
    capture.write_bytes(b"pcap-data")

    triggered = {}

    def fake_run_analysis(*_args, **_kwargs):
        triggered["ran"] = True

    (tmp_path / "tshark.exe").write_bytes(b"")
    monkeypatch.setattr(MainWindow, "run_analysis", fake_run_analysis)
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        staticmethod(lambda *args, **kwargs: (str(capture), "")),
    )
    window = MainWindow()
    window._settings = type(window._settings)(tshark_path=str(tmp_path / "tshark.exe"))
    window._open_capture_dialog()

    expected_root = tmp_path / "AutoShark" / "projects" / "evidence.auto-shark"
    assert (expected_root / "project.json").is_file()
    assert window.services is not None
    # A brand-new capture is analyzed automatically, in one interaction.
    assert triggered == {"ran": True}

    triggered.clear()
    # A project that was already analyzed opens without re-running.
    monkeypatch.setattr(MainWindow, "_project_needs_analysis", lambda self: False)
    window._open_capture_dialog()
    assert triggered == {}
    assert (expected_root / "project.json").is_file()


def test_new_project_dialog_forwards_ephemeral_tls_rsa_key(qapp, tmp_path, monkeypatch) -> None:
    capture = tmp_path / "mail.pcap"
    capture.write_bytes(b"pcap")
    project = tmp_path / "mail.auto-shark"
    tshark = tmp_path / "tshark.exe"
    tshark.write_bytes(b"tool")
    key_path = tmp_path / "challenge.pem"
    key_path.write_bytes(b"challenge key")
    received = {}

    def fake_exec(dialog):
        values = {
            "capturePath": capture,
            "projectPath": project,
            "tsharkPath": tshark,
            "tlsRsaKeyPath": key_path,
        }
        for object_name, value in values.items():
            dialog.findChild(QLineEdit, object_name).setText(str(value))
        return QDialog.DialogCode.Accepted

    def fake_run_analysis(self, **options):
        received.update(options)

    monkeypatch.setattr(QDialog, "exec", fake_exec)
    monkeypatch.setattr(MainWindow, "run_analysis", fake_run_analysis)
    window = MainWindow()
    window._new_project_dialog()

    assert received["capture"] == capture
    assert received["tshark"] == tshark
    assert received["tls_rsa_key"].path == key_path.resolve()
    assert received["tls_rsa_key"].sha256 == hashlib.sha256(b"challenge key").hexdigest()
    assert not hasattr(window._settings, "tls_rsa_key")


def test_settings_dialog_hides_remote_fields_and_uses_translated_labels(
    qapp, monkeypatch
) -> None:
    monkeypatch.setenv("AUTO_SHARK_LANGUAGE", "zh-CN")
    captured: dict = {}

    def fake_exec(self):
        captured["title"] = self.windowTitle()
        captured["labels"] = [widget.text() for widget in self.findChildren(QLabel)]
        captured["buttons"] = [widget.text() for widget in self.findChildren(QPushButton)]
        captured["checks"] = [widget.text() for widget in self.findChildren(QCheckBox)]
        advanced = self.findChild(QWidget, "settingsAdvanced")
        captured["advanced_hidden"] = bool(advanced is None or advanced.isHidden())
        host = self.findChild(QLineEdit, "settingsRemoteHost")
        port = self.findChild(QSpinBox, "settingsRemotePort")
        identity = self.findChild(QLineEdit, "settingsSshIdentity")
        captured["host_placeholder"] = host.placeholderText() if host is not None else ""
        captured["port"] = port.value() if port is not None else None
        captured["identity_present"] = identity is not None
        return QDialog.DialogCode.Rejected

    monkeypatch.setattr(QDialog, "exec", fake_exec)
    window = MainWindow()
    assert window._language == "zh"
    window._settings_dialog()
    assert "设置" in captured["title"]
    assert any("检测" in text for text in captured["buttons"])
    assert any("浏览" in text for text in captured["buttons"])
    assert any("远程 Linux" in text for text in captured["checks"])
    assert captured["advanced_hidden"] is True
    assert any("本地做流量题" in text for text in captured["labels"])
    assert any("SSH + SFTP" in text for text in captured["labels"])
    assert captured["host_placeholder"] == "ctf@192.168.1.10"
    assert captured["port"] == 22
    assert captured["identity_present"] is True


def test_tshark_too_old_blocks_analysis(qapp, monkeypatch) -> None:
    shown = []
    monkeypatch.setattr(
        QMessageBox, "warning", lambda *args, **kwargs: shown.append(args) or 0
    )
    window = MainWindow()
    monkeypatch.setattr(window, "_tshark_path", lambda: Path("C:/old/tshark.exe"))
    monkeypatch.setattr(
        "auto_shark.gui.main_window._tshark_version", lambda _path: (2, 2, 1)
    )
    window.services = object()  # type: ignore[assignment]
    window.run_analysis()
    assert shown
    assert "2.2.1" in str(shown[0][2])
    assert "4.0" in str(shown[0][2])
