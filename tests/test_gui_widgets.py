import json
import os
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

pytest.importorskip("PySide6", reason="GUI widget tests need the optional gui extra")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

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
            connection.execute("SELECT id FROM evidence WHERE evidence_id='evidence-1'")
            .fetchone()[0]
        )
        connection.execute(
            "INSERT INTO candidate"
            "(candidate_id,kind,raw_value,normalized_value,confidence,rank_score,created_at) "
            "VALUES('candidate-1','known-flag','flag{gui}','flag{gui}',1,100,?)",
            (_now(),),
        )
        candidate_id = int(connection.execute("SELECT id FROM candidate").fetchone()[0])
        connection.execute(
            "INSERT INTO candidate_evidence(candidate_id,evidence_id,role) "
            "VALUES(?,?,'match')",
            (candidate_id, evidence_id),
        )
    return root


def test_window_builds_all_pages_with_no_project_state(qapp) -> None:
    window = MainWindow()
    assert window._nav.count() == len(PAGE_NAMES)
    for name in PAGE_NAMES:
        assert window._banners[name].text() == ""
        window._refresh_page(name)()
        assert "No project open" in window._banners[name].text()
    assert window.services is None


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
    window._candidates_table.selectRow(0)
    detail = window._details["Findings"].toPlainText()
    assert '"candidate_id": "candidate-1"' in detail
    assert '"signals"' in detail


def test_notes_and_review_mark_round_trip(qapp, tmp_path) -> None:
    root = _widget_project(tmp_path)
    window = MainWindow()
    window.open_project(root)
    window._note_kind.setCurrentText("candidate")
    window._note_subject.setText("candidate-1")
    window._note_body.setPlainText("widget note")
    window._add_note()
    assert window._notes_table.rowCount() == 1
    assert window._note_items[0]["body"] == "widget note"

    window._note_body.setPlainText("updated note")
    window._notes_table.selectRow(0)
    window._update_selected_note()
    refreshed = window.services.notes()
    assert refreshed["items"][0]["body"] == "updated note"

    window._mark_state.setCurrentText("key_evidence")
    window._apply_review_mark()
    overview = window.services.overview()
    assert overview["overview"]["review_marks"] == 1


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


def test_stage_worker_stops_on_failure(qapp) -> None:
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
    assert kinds == ["started", "finished", "started", "failed", "done"]
    assert events[-1][1] is False
    assert "'bad' failed" in events[-1][2]


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

    save_settings(GuiSettings(tshark_path=str(tmp_path / "tshark.exe")))
    loaded = load_settings()
    assert loaded.tshark_path == str(tmp_path / "tshark.exe")

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

    def fake_run_analysis(self, *, capture=None, tshark=None):
        triggered["capture"] = capture
        triggered["tshark"] = tshark

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
    assert triggered["capture"] == capture
    assert triggered["tshark"] == tmp_path / "tshark.exe"

    triggered.clear()
    window._open_capture_dialog()
    assert triggered["capture"] is None  # existing project: refresh stages only
    assert (expected_root / "project.json").is_file()
