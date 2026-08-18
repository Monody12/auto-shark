"""Main investigation window over the bounded read models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..config import Settings
from ..project import ProjectInfo, create_project
from .i18n import apply_widget_translations, detect_language, translate
from .services import PAGE_LIMIT, ProjectServices, resolve_tshark
from .settings import GuiSettings, load_settings, save_settings
from .workers import SingleRunWorker, StageWorker

PAGE_NAMES = (
    "Overview",
    "HTTP",
    "Streams",
    "Telnet",
    "Findings",
    "Timeline",
    "Manual queue",
    "Notes",
    "Export",
)
REVIEW_STATES = ("unreviewed", "needs_review", "excluded", "key_evidence")
SUBJECT_KINDS = (
    "candidate",
    "finding",
    "artifact",
    "behavior-event",
    "manual-task",
    "evidence",
)
TASK_STATES = ("open", "in-progress", "resolved", "dismissed")


def _cell(value: Any) -> QTableWidgetItem:
    return QTableWidgetItem("" if value is None else str(value))


def _table(headers: tuple[str, ...]) -> QTableWidget:
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    widget.horizontalHeader().setStretchLastSection(True)
    return widget


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.services: Optional[ProjectServices] = None
        self._worker: Optional[StageWorker] = None
        self._single_worker: Optional[SingleRunWorker] = None
        self._settings = load_settings()
        self._offsets: dict[str, int] = {}
        self._pages: dict[str, QWidget] = {}
        self._banners: dict[str, QLabel] = {}
        self._refreshers: dict[str, Callable[[], None]] = {}
        self._details: dict[str, QPlainTextEdit] = {}
        self._uri_filter = ""
        self._http_items: list = []
        self._streams_items: list = []
        self._telnet_items: list = []
        self._candidate_items: list = []
        self._finding_items: list = []
        self._timeline_items: list = []
        self._queue_items: list = []
        self._note_items: list = []
        self._language = detect_language()
        self.setWindowTitle("Auto-Shark")
        self.resize(1280, 820)
        self._build_menu()
        self._build_body()
        apply_widget_translations(self, self._language)

    def _t(self, text: str) -> str:
        return translate(text, self._language)

    # ------------------------------------------------------------------ setup

    def _build_menu(self) -> None:
        menu = self.menuBar()
        file_menu = menu.addMenu("&File")
        action = file_menu.addAction("&Open capture…")
        action.triggered.connect(self._open_capture_dialog)
        action = file_menu.addAction("Open &project…")
        action.triggered.connect(self._open_project_dialog)
        action = file_menu.addAction("&New project from capture…")
        action.triggered.connect(self._new_project_dialog)
        file_menu.addSeparator()
        action = file_menu.addAction("E&xit")
        action.triggered.connect(self.close)
        edit_menu = menu.addMenu("&Edit")
        action = edit_menu.addAction("&Settings…")
        action.triggered.connect(self._settings_dialog)
        analysis_menu = menu.addMenu("&Analysis")
        action = analysis_menu.addAction("&Run full analysis")
        action.triggered.connect(self.run_analysis)
        self._cancel_action = analysis_menu.addAction("&Cancel running analysis")
        self._cancel_action.triggered.connect(self.cancel_analysis)
        self._cancel_action.setEnabled(False)
        analysis_menu.addSeparator()
        action = analysis_menu.addAction("&Refresh page")
        action.triggered.connect(self.refresh_current_page)

    def _build_body(self) -> None:
        splitter = QSplitter()
        self._nav = QListWidget()
        for name in PAGE_NAMES:
            self._nav.addItem(name)
        self._nav.setCurrentRow(0)
        self._nav.currentRowChanged.connect(self._nav_changed)
        splitter.addWidget(self._nav)
        self._stack = QStackedWidget()
        builders: dict[str, Callable[[], QWidget]] = {
            "Overview": self._build_overview_page,
            "HTTP": self._build_http_page,
            "Streams": self._build_streams_page,
            "Telnet": self._build_telnet_page,
            "Findings": self._build_findings_page,
            "Timeline": self._build_timeline_page,
            "Manual queue": self._build_queue_page,
            "Notes": self._build_notes_page,
            "Export": self._build_export_page,
        }
        for name in PAGE_NAMES:
            page = builders[name]()
            self._pages[name] = page
            self._stack.addWidget(page)
        splitter.addWidget(self._stack)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([220, 1060])
        self.setCentralWidget(splitter)
        self._register_refreshers()
        self.statusBar().showMessage(self._t("No project open"))

    def _page_scaffold(self, name: str, body: QWidget) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        banner = QLabel("")
        banner.setWordWrap(True)
        layout.addWidget(banner)
        layout.addWidget(body, 1)
        self._banners[name] = banner
        return container

    def _detail_pane(self, name: str) -> QPlainTextEdit:
        detail = QPlainTextEdit()
        detail.setReadOnly(True)
        detail.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._details[name] = detail
        return detail

    # ------------------------------------------------------------- page build

    def _build_overview_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        self._overview_table = _table(("Metric", "Value"))
        layout.addWidget(self._overview_table)
        layout.addWidget(QLabel("Report JSON (bounded preview of report/v1):"))
        self._overview_json = QPlainTextEdit()
        self._overview_json.setReadOnly(True)
        layout.addWidget(self._overview_json, 1)
        return self._page_scaffold("Overview", body)

    def _build_http_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("URI filter:"))
        self._uri_edit = QLineEdit()
        self._uri_edit.setPlaceholderText("exact URI or empty")
        filter_row.addWidget(self._uri_edit, 1)
        apply_button = QPushButton("Apply")
        apply_button.clicked.connect(self._apply_uri_filter)
        filter_row.addWidget(apply_button)
        layout.addLayout(filter_row)
        self._http_table = _table(
            ("Frame", "Method", "Host", "URI", "Status", "Code")
        )
        self._http_table.itemSelectionChanged.connect(self._show_http_detail)
        layout.addWidget(self._http_table, 1)
        self._params_table = _table(("Parameter", "Source", "Value"))
        layout.addWidget(self._params_table, 1)
        nav = QHBoxLayout()
        prev = QPushButton("Previous")
        prev.clicked.connect(lambda: self._page_step("HTTP", -1))
        next_ = QPushButton("Next")
        next_.clicked.connect(lambda: self._page_step("HTTP", 1))
        nav.addWidget(prev)
        nav.addWidget(next_)
        nav.addStretch(1)
        layout.addLayout(nav)
        self._http_detail = self._detail_pane("HTTP")
        layout.addWidget(self._http_detail, 1)
        return self._page_scaffold("HTTP", body)

    def _build_streams_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        self._streams_table = _table(
            ("Stream", "Conversation", "Endpoints", "Direction", "Status", "Output bytes")
        )
        self._streams_table.itemSelectionChanged.connect(
            lambda: self._show_selected_json(
                "Streams", self._streams_table, self._streams_items
            )
        )
        layout.addWidget(self._streams_table, 1)
        nav = QHBoxLayout()
        prev = QPushButton("Previous")
        prev.clicked.connect(lambda: self._page_step("Streams", -1))
        next_ = QPushButton("Next")
        next_.clicked.connect(lambda: self._page_step("Streams", 1))
        nav.addWidget(prev)
        nav.addWidget(next_)
        nav.addStretch(1)
        layout.addLayout(nav)
        self._streams_detail = self._detail_pane("Streams")
        layout.addWidget(self._streams_detail, 1)
        return self._page_scaffold("Streams", body)

    def _build_telnet_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        self._telnet_table = _table(
            ("Conversation", "Status", "Current", "Client bytes", "Server bytes", "Records")
        )
        self._telnet_table.itemSelectionChanged.connect(
            lambda: self._show_selected_json(
                "Telnet", self._telnet_table, self._telnet_items
            )
        )
        layout.addWidget(self._telnet_table, 1)
        nav = QHBoxLayout()
        prev = QPushButton("Previous")
        prev.clicked.connect(lambda: self._page_step("Telnet", -1))
        next_ = QPushButton("Next")
        next_.clicked.connect(lambda: self._page_step("Telnet", 1))
        nav.addWidget(prev)
        nav.addWidget(next_)
        nav.addStretch(1)
        layout.addLayout(nav)
        self._telnet_detail = self._detail_pane("Telnet")
        layout.addWidget(self._telnet_detail, 1)
        return self._page_scaffold("Telnet", body)

    def _build_findings_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.addWidget(QLabel("Candidates:"))
        self._candidates_table = _table(
            ("Rank", "Kind", "Value", "Confidence")
        )
        self._candidates_table.itemSelectionChanged.connect(
            lambda: self._show_selected_json(
                "Findings", self._candidates_table, self._candidate_items
            )
        )
        layout.addWidget(self._candidates_table, 1)
        layout.addWidget(QLabel("Findings:"))
        self._findings_table = _table(("Kind", "Subject kind", "Subject", "Status"))
        self._findings_table.itemSelectionChanged.connect(
            lambda: self._show_selected_json(
                "Findings", self._findings_table, self._finding_items
            )
        )
        layout.addWidget(self._findings_table, 1)
        nav = QHBoxLayout()
        prev = QPushButton("Previous candidates")
        prev.clicked.connect(lambda: self._findings_step(-1))
        next_ = QPushButton("Next candidates")
        next_.clicked.connect(lambda: self._findings_step(1))
        nav.addWidget(prev)
        nav.addWidget(next_)
        nav.addStretch(1)
        layout.addLayout(nav)
        self._findings_detail = self._detail_pane("Findings")
        layout.addWidget(self._findings_detail, 1)
        return self._page_scaffold("Findings", body)

    def _build_timeline_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Event kind:"))
        self._timeline_kind = QLineEdit()
        self._timeline_kind.setPlaceholderText("optional, e.g. file-write")
        filter_row.addWidget(self._timeline_kind, 1)
        self._timeline_duplicates = QCheckBox("Include duplicates")
        filter_row.addWidget(self._timeline_duplicates)
        apply_button = QPushButton("Apply")
        apply_button.clicked.connect(self._refresh_page("Timeline"))
        filter_row.addWidget(apply_button)
        layout.addLayout(filter_row)
        self._timeline_table = _table(
            ("Frame start", "Kind", "Target", "Status", "Group")
        )
        self._timeline_table.itemSelectionChanged.connect(
            lambda: self._show_selected_json(
                "Timeline", self._timeline_table, self._timeline_items
            )
        )
        layout.addWidget(self._timeline_table, 1)
        nav = QHBoxLayout()
        prev = QPushButton("Previous")
        prev.clicked.connect(lambda: self._page_step("Timeline", -1))
        next_ = QPushButton("Next")
        next_.clicked.connect(lambda: self._page_step("Timeline", 1))
        nav.addWidget(prev)
        nav.addWidget(next_)
        nav.addStretch(1)
        layout.addLayout(nav)
        self._timeline_detail = self._detail_pane("Timeline")
        layout.addWidget(self._timeline_detail, 1)
        return self._page_scaffold("Timeline", body)

    def _build_queue_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("State:"))
        self._queue_state = QComboBox()
        self._queue_state.addItem("all")
        self._queue_state.addItems(TASK_STATES)
        self._queue_state.currentTextChanged.connect(lambda _: self._refresh_page("Manual queue")())
        filter_row.addWidget(self._queue_state)
        filter_row.addStretch(1)
        change_button = QPushButton("Change state of selected…")
        change_button.clicked.connect(self._change_task_state)
        filter_row.addWidget(change_button)
        layout.addLayout(filter_row)
        self._queue_table = _table(
            ("Priority", "State", "Kind", "Subject", "Signals")
        )
        self._queue_table.itemSelectionChanged.connect(
            lambda: self._show_selected_json(
                "Manual queue", self._queue_table, self._queue_items
            )
        )
        layout.addWidget(self._queue_table, 1)
        nav = QHBoxLayout()
        prev = QPushButton("Previous")
        prev.clicked.connect(lambda: self._page_step("Manual queue", -1))
        next_ = QPushButton("Next")
        next_.clicked.connect(lambda: self._page_step("Manual queue", 1))
        nav.addWidget(prev)
        nav.addWidget(next_)
        nav.addStretch(1)
        layout.addLayout(nav)
        self._queue_detail = self._detail_pane("Manual queue")
        layout.addWidget(self._queue_detail, 1)
        return self._page_scaffold("Manual queue", body)

    def _build_notes_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.addWidget(QLabel("Add note / review mark:"))
        form = QFormLayout()
        self._note_kind = QComboBox()
        self._note_kind.addItems(SUBJECT_KINDS)
        form.addRow("Subject kind", self._note_kind)
        self._note_subject = QLineEdit()
        form.addRow("Subject ID", self._note_subject)
        self._note_body = QPlainTextEdit()
        self._note_body.setMaximumHeight(96)
        form.addRow("Note body", self._note_body)
        self._mark_state = QComboBox()
        self._mark_state.addItems(REVIEW_STATES)
        form.addRow("Review mark", self._mark_state)
        layout.addLayout(form)
        buttons = QHBoxLayout()
        add_note = QPushButton("Add note")
        add_note.clicked.connect(self._add_note)
        buttons.addWidget(add_note)
        set_mark = QPushButton("Apply review mark")
        set_mark.clicked.connect(self._apply_review_mark)
        buttons.addWidget(set_mark)
        update_note = QPushButton("Update selected note body")
        update_note.clicked.connect(self._update_selected_note)
        buttons.addWidget(update_note)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self._notes_table = _table(("Note ID", "Subject kind", "Subject ID", "Body"))
        layout.addWidget(self._notes_table, 1)
        return self._page_scaffold("Notes", body)

    def _build_export_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        self._export_evidence = QCheckBox("Include bounded evidence directory")
        self._export_evidence.setChecked(True)
        layout.addWidget(self._export_evidence)
        button = QPushButton("Choose directory and export bundle…")
        button.clicked.connect(self._export_bundle)
        layout.addWidget(button)
        layout.addWidget(QLabel("Last export result:"))
        self._export_result = QPlainTextEdit()
        self._export_result.setReadOnly(True)
        layout.addWidget(self._export_result, 1)
        return self._page_scaffold("Export", body)

    # ------------------------------------------------------------ navigation

    def _nav_changed(self, row: int) -> None:
        if 0 <= row < len(PAGE_NAMES):
            self._stack.setCurrentIndex(row)
            self._refresh_page(PAGE_NAMES[row])()

    def current_page_name(self) -> str:
        return PAGE_NAMES[self._nav.currentRow()]

    def refresh_current_page(self) -> None:
        self._refresh_page(self.current_page_name())()

    def _refresh_page(self, name: str) -> Callable[[], None]:
        def refresh() -> None:
            refresher = self._refreshers.get(name)
            if refresher is not None:
                refresher()
            banner = self._banners.get(name)
            if banner is not None and self.services is None:
                banner.setText(self._t("No project open — use File > Open project."))

        return refresh

    def _register_refresher(self, name: str, refresher: Callable[[], None]) -> None:
        self._refreshers[name] = refresher

    def _page_step(self, name: str, direction: int) -> None:
        offset = max(0, self._offsets.get(name, 0) + direction * PAGE_LIMIT)
        self._offsets[name] = offset
        self._refresh_page(name)()

    def _findings_step(self, direction: int) -> None:
        offset = max(0, self._offsets.get("Findings", 0) + direction * PAGE_LIMIT)
        self._offsets["Findings"] = offset
        self._refresh_page("Findings")()

    def _apply_uri_filter(self) -> None:
        self._uri_filter = self._uri_edit.text().strip()
        self._offsets["HTTP"] = 0
        self._refresh_page("HTTP")()

    # --------------------------------------------------------- project state

    def open_project(self, path: Path) -> None:
        try:
            services = ProjectServices(Path(path))
            info: ProjectInfo = services.info()
        except (OSError, ValueError, FileNotFoundError) as error:
            QMessageBox.critical(
                self, self._t("Auto-Shark"), self._t("Cannot open project: ") + str(error)
            )
            return
        self.services = services
        self._offsets = {name: 0 for name in PAGE_NAMES}
        self.statusBar().showMessage(
            f"{info.root} | capture {info.capture_sha256[:16]}… | "
            f"{info.capture_bytes} bytes | schema {info.database_schema}"
        )
        self.refresh_current_page()

    def _open_project_dialog(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, self._t("Open Auto-Shark project"))
        if directory:
            self.open_project(Path(directory))

    def _default_project_root(self, capture: Path) -> Path:
        return Settings.from_environment().project_root / f"{capture.stem}.auto-shark"

    def _tshark_path(self) -> Optional[Path]:
        configured = self._settings.tshark_path
        if configured and Path(configured).is_file():
            return Path(configured)
        return resolve_tshark(None)

    def _report_synced_path_error(self, error: Exception) -> None:
        QMessageBox.warning(
            self,
            self._t("Auto-Shark"),
            self._t("Projects cannot live in a synced directory (for example OneDrive).\n")
            +
            f"Use the default machine-local location instead:\n"
            f"{Settings.from_environment().project_root}",
        )

    def _open_capture_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, self._t("Open capture"), "", "Captures (*.pcap *.pcapng);;All files (*)"
        )
        if not path:
            return
        capture = Path(path)
        project_dir = self._default_project_root(capture)
        created = not (project_dir / "project.json").is_file()
        try:
            if created:
                create_project(capture, project_dir)
        except (OSError, ValueError, FileExistsError) as error:
            if "synced" in str(error):
                self._report_synced_path_error(error)
            else:
                QMessageBox.critical(
                    self, self._t("Auto-Shark"), self._t("Cannot create project: ") + str(error)
                )
            return
        self.open_project(project_dir)
        tshark = self._tshark_path()
        if tshark is None:
            QMessageBox.warning(
                self,
                self._t("Auto-Shark"),
                self._t(
                    "TShark was not found.\n"
                    "Install Wireshark, then set the path in Edit > Settings…"
                ),
            )
            return
        self.run_analysis(capture=capture if created else None, tshark=tshark)

    def _settings_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self._t("Auto-Shark settings"))
        form = QFormLayout(dialog)

        self._settings_tshark = QLineEdit(self._settings.tshark_path or "")
        tshark_row = QHBoxLayout()
        tshark_row.addWidget(self._settings_tshark, 1)
        browse = QPushButton("Browse…")
        probe = QPushButton("Probe")
        tshark_row.addWidget(browse)
        tshark_row.addWidget(probe)
        tshark_widget = QWidget()
        tshark_widget.setLayout(tshark_row)
        form.addRow("TShark executable", tshark_widget)

        self._settings_remote_host = QLineEdit(self._settings.remote_host or "")
        form.addRow("Remote host (optional)", self._settings_remote_host)
        self._settings_ssh = QLineEdit(self._settings.ssh_path or "")
        self._settings_sftp = QLineEdit(self._settings.sftp_path or "")
        self._settings_remote_root = QLineEdit(self._settings.remote_root)
        self._settings_remote_paths = QLineEdit("/usr/bin/python3")
        form.addRow("ssh executable", self._settings_ssh)
        form.addRow("sftp executable", self._settings_sftp)
        form.addRow("Remote working root", self._settings_remote_root)
        form.addRow("Remote paths to probe", self._settings_remote_paths)
        remote_probe = QPushButton("Probe remote node")
        form.addRow("", remote_probe)

        self._settings_output = QPlainTextEdit()
        self._settings_output.setReadOnly(True)
        self._settings_output.setMaximumHeight(140)
        form.addRow("Probe result", self._settings_output)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        def pick_tshark() -> None:
            path, _ = QFileDialog.getOpenFileName(dialog, self._t("Choose tshark executable"))
            if path:
                self._settings_tshark.setText(path)

        def run_probe() -> None:
            from ..engines.tshark import probe_tshark

            text = self._settings_tshark.text().strip()
            if not text:
                self._settings_output.setPlainText(self._t("Enter a TShark path first."))
                return
            try:
                result = probe_tshark(Path(text))
            except (OSError, ValueError) as error:
                self._settings_output.setPlainText(self._t("error: ") + str(error))
                return
            features = sum(1 for value in result.features.values() if value)
            self._settings_output.setPlainText(
                f"{result.version_line}\nusable: {'yes' if result.usable else 'no'} | "
                f"capabilities: {features}/{len(result.features)}"
            )

        def run_remote_probe() -> None:
            from ..remote import RemoteNodeConfig, find_ssh_tools, probe_remote_node

            host = self._settings_remote_host.text().strip()
            if not host:
                self._settings_output.setPlainText(self._t("Enter a remote host first."))
                return
            ssh, sftp = find_ssh_tools(
                Path(self._settings_ssh.text().strip())
                if self._settings_ssh.text().strip()
                else None,
                Path(self._settings_sftp.text().strip())
                if self._settings_sftp.text().strip()
                else None,
            )
            if ssh is None or sftp is None:
                self._settings_output.setPlainText(self._t("error: ssh and sftp clients not found"))
                return
            paths = [
                item.strip()
                for item in self._settings_remote_paths.text().split(",")
                if item.strip()
            ]
            try:
                probe = probe_remote_node(
                    RemoteNodeConfig(
                        host=host,
                        ssh_executable=ssh,
                        sftp_executable=sftp,
                        remote_root=self._settings_remote_root.text().strip()
                        or ".auto-shark-jobs",
                    ),
                    paths,
                )
            except (OSError, ValueError) as error:
                self._settings_output.setPlainText(self._t("error: ") + str(error))
                return
            self._settings_output.setPlainText(
                json.dumps(probe, ensure_ascii=False, sort_keys=True, indent=2)
            )

        browse.clicked.connect(pick_tshark)
        probe.clicked.connect(run_probe)
        remote_probe.clicked.connect(run_remote_probe)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._settings = GuiSettings(
            tshark_path=self._settings_tshark.text().strip() or None,
            remote_host=self._settings_remote_host.text().strip() or None,
            ssh_path=self._settings_ssh.text().strip() or None,
            sftp_path=self._settings_sftp.text().strip() or None,
            remote_root=self._settings_remote_root.text().strip() or ".auto-shark-jobs",
        )
        try:
            save_settings(self._settings)
        except OSError as error:
            QMessageBox.critical(
                self, self._t("Auto-Shark"), self._t("Cannot save settings: ") + str(error)
            )

    def _new_project_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self._t("New project from capture"))
        form = QFormLayout(dialog)
        capture_edit = QLineEdit()
        capture_button = QPushButton("Browse…")
        project_edit = QLineEdit()
        project_button = QPushButton("Browse…")
        tshark_edit = QLineEdit()
        resolved = resolve_tshark(None)
        if resolved is not None:
            tshark_edit.setText(str(resolved))
        capture_row = QHBoxLayout()
        capture_row.addWidget(capture_edit, 1)
        capture_row.addWidget(capture_button)
        project_row = QHBoxLayout()
        project_row.addWidget(project_edit, 1)
        project_row.addWidget(project_button)
        capture_widget = QWidget()
        capture_widget.setLayout(capture_row)
        project_widget = QWidget()
        project_widget.setLayout(project_row)
        form.addRow("Capture file", capture_widget)
        form.addRow("Project directory", project_widget)
        form.addRow("TShark executable", tshark_edit)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        def pick_capture() -> None:
            path, _ = QFileDialog.getOpenFileName(
                dialog, self._t("Choose capture"), "", "Captures (*.pcap *.pcapng);;All files (*)"
            )
            if path:
                capture_edit.setText(path)
                if not project_edit.text().strip():
                    project_edit.setText(str(self._default_project_root(Path(path))))

        def pick_project() -> None:
            path = QFileDialog.getExistingDirectory(dialog, self._t("Choose project directory"))
            if path:
                project_edit.setText(path)

        capture_button.clicked.connect(pick_capture)
        project_button.clicked.connect(pick_project)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        capture_text = capture_edit.text().strip()
        project_text = project_edit.text().strip()
        tshark_text = tshark_edit.text().strip()
        if not capture_text or not project_text:
            QMessageBox.warning(
                self, self._t("Auto-Shark"), self._t("Capture and project paths are required.")
            )
            return
        try:
            info = create_project(Path(capture_text), Path(project_text))
        except (OSError, ValueError, FileExistsError) as error:
            if "synced" in str(error):
                self._report_synced_path_error(error)
            else:
                QMessageBox.critical(
                    self, self._t("Auto-Shark"), self._t("Cannot create project: ") + str(error)
                )
            return
        self.open_project(info.root)
        tshark = (
            Path(tshark_text)
            if tshark_text and Path(tshark_text).is_file()
            else self._tshark_path()
        )
        if tshark is None:
            QMessageBox.warning(
                self,
                self._t("Auto-Shark"),
                self._t(
                    "TShark was not found.\n"
                    "Install Wireshark, then set the path in Edit > Settings…"
                ),
            )
            return
        self.run_analysis(capture=Path(capture_text), tshark=tshark)

    # ------------------------------------------------------------- analysis

    def run_analysis(
        self, *, capture: Optional[Path] = None, tshark: Optional[Path] = None
    ) -> None:
        if self.services is None:
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Open a project first."))
            return
        executable = tshark or self._tshark_path()
        if executable is None:
            QMessageBox.warning(
                self,
                self._t("Auto-Shark"),
                self._t(
                    "TShark was not found. Install Wireshark, then use Edit > Settings… "
                    "to configure the path."
                ),
            )
            return
        stages = self.services.analysis_stages(executable, capture=capture)
        self._start_stage_worker(stages)

    def _start_stage_worker(self, stages: list) -> None:
        dialog = QProgressDialog(
            self._t("Preparing analysis…"), self._t("Cancel"), 0, len(stages), self
        )
        dialog.setWindowTitle(self._t("Auto-Shark analysis"))
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.setMinimumDuration(0)
        worker = StageWorker(stages)
        self._worker = worker

        def on_started(title: str) -> None:
            dialog.setLabelText(self._t("Running: ") + title)

        def on_finished_stage(key: str, summary: str) -> None:
            dialog.setValue(dialog.value() + 1)

        def on_failed(key: str, error: str) -> None:
            QMessageBox.warning(
                self,
                self._t("Auto-Shark"),
                self._t("Stage '") + key + self._t("' failed:\n") + error,
            )

        def on_run_done(completed: bool, message: str) -> None:
            dialog.reset()
            self._worker = None
            self._cancel_action.setEnabled(False)
            if completed:
                QMessageBox.information(self, self._t("Auto-Shark"), message)
            else:
                QMessageBox.warning(self, self._t("Auto-Shark"), message)
            self.refresh_current_page()

        worker.stage_started.connect(on_started)
        worker.stage_finished.connect(on_finished_stage)
        worker.stage_failed.connect(on_failed)
        worker.finished_run.connect(on_run_done)
        dialog.canceled.connect(worker.cancel)
        self._cancel_action.setEnabled(True)
        worker.start()

    def cancel_analysis(self) -> None:
        if self._worker is not None:
            self._worker.cancel()

    # -------------------------------------------------------------- exports

    def _export_bundle(self) -> None:
        if self.services is None:
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Open a project first."))
            return
        directory = QFileDialog.getExistingDirectory(
            self, self._t("Choose a new or empty export directory")
        )
        if not directory:
            return
        include = self._export_evidence.isChecked()
        services = self.services

        class _Bound:
            def __call__(self) -> object:
                return services.export_bundle_to(
                    Path(directory), include_evidence=include
                )

        dialog = QProgressDialog(self._t("Exporting bounded bundle…"), None, 0, 0, self)
        dialog.setWindowTitle(self._t("Auto-Shark export"))
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.setMinimumDuration(0)
        worker = SingleRunWorker(_Bound())
        self._single_worker = worker

        def on_success(summary: str) -> None:
            dialog.reset()
            self._export_result.setPlainText(summary)
            self._banners["Export"].setText(self._t("Export finished."))

        def on_failure(error: str) -> None:
            dialog.reset()
            QMessageBox.critical(
                self, self._t("Auto-Shark"), self._t("Export failed:\n") + error
            )

        worker.succeeded.connect(on_success)
        worker.failed.connect(on_failure)
        worker.start()

    # ------------------------------------------------------------- mutations

    def _add_note(self) -> None:
        if self.services is None:
            return
        kind = self._note_kind.currentText()
        subject = self._note_subject.text().strip()
        body = self._note_body.toPlainText()
        if not subject or not body:
            QMessageBox.warning(
                self, self._t("Auto-Shark"), self._t("Subject ID and body are required.")
            )
            return
        try:
            self.services.add_note(kind, subject, body)
        except (OSError, ValueError) as error:
            QMessageBox.critical(self, self._t("Auto-Shark"), str(error))
            return
        self._note_body.clear()
        self._refresh_page("Notes")()

    def _apply_review_mark(self) -> None:
        if self.services is None:
            return
        kind = self._note_kind.currentText()
        subject = self._note_subject.text().strip()
        state = self._mark_state.currentText()
        if not subject:
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("Subject ID is required."))
            return
        try:
            self.services.set_review_mark(kind, subject, state)
        except (OSError, ValueError) as error:
            QMessageBox.critical(self, self._t("Auto-Shark"), str(error))
            return
        self.refresh_current_page()

    def _update_selected_note(self) -> None:
        if self.services is None:
            return
        row = self._notes_table.currentRow()
        if row < 0 or row >= len(self._note_items):
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Select a note first."))
            return
        note = self._note_items[row]
        note_id = str(note.get("note_id", ""))
        body = self._note_body.toPlainText()
        if not body:
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("Enter the new body first."))
            return
        try:
            self.services.update_note(note_id, body)
        except (OSError, ValueError) as error:
            QMessageBox.critical(self, self._t("Auto-Shark"), str(error))
            return
        self._refresh_page("Notes")()

    def _change_task_state(self) -> None:
        if self.services is None:
            return
        row = self._queue_table.currentRow()
        if row < 0 or row >= len(self._queue_items):
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Select a task first."))
            return
        task = self._queue_items[row]
        task_id = str(task.get("task_id", ""))
        dialog = QDialog(self)
        dialog.setWindowTitle(self._t("Change manual task state"))
        form = QFormLayout(dialog)
        combo = QComboBox()
        combo.addItems(TASK_STATES)
        current = str(task.get("state", "open"))
        index = combo.findText(current)
        if index >= 0:
            combo.setCurrentIndex(index)
        form.addRow("New state", combo)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.services.update_manual_task_state(task_id, combo.currentText())
        except (OSError, ValueError) as error:
            QMessageBox.critical(self, self._t("Auto-Shark"), str(error))
            return
        self._refresh_page("Manual queue")()

    # --------------------------------------------------------------- helpers

    def _require_services(self, name: str) -> bool:
        banner = self._banners[name]
        if self.services is None:
            banner.setText(self._t("No project open — use File > Open project."))
            return False
        return True

    def _set_banner(
        self, name: str, *, offset: int, count: int, total: int, extra: str = ""
    ) -> None:
        more = self._t(" — more available") if offset + count < total else ""
        suffix = f" {extra}" if extra else ""
        self._banners[name].setText(
            f"{self._t('Showing')} {count} {self._t('of')} {total} "
            f"{self._t('at offset')} {offset}{more}{suffix}"
        )

    def _show_http_detail(self) -> None:
        """Render the selected transaction's parameters plus the JSON detail."""
        row = self._http_table.currentRow()
        detail = self._details.get("HTTP")
        if detail is None or not 0 <= row < len(self._http_items):
            self._fill_table(self._params_table, [])
            if detail is not None:
                detail.setPlainText("")
            return
        item = self._http_items[row]
        if detail is not None:
            detail.setPlainText(
                json.dumps(item, ensure_ascii=False, sort_keys=True, indent=2)
            )
        rows = []
        transaction_id = str(item.get("transaction_id", ""))
        if self.services is not None and transaction_id:
            try:
                payload = self.services.transaction_detail(transaction_id)
            except (OSError, ValueError, KeyError):
                payload = None
            if payload is not None:
                request = payload.get("request") or {}
                for param in request.get("query_params", []):
                    rows.append((param.get("name"), "query", param.get("value")))
                for field in request.get("form_fields", []):
                    value = field.get("value")
                    if field.get("truncated"):
                        value = f"{value}…"
                    rows.append((field.get("name"), "form", value))
        self._fill_table(self._params_table, rows)

    def _show_selected_json(
        self, name: str, table: QTableWidget, items: list
    ) -> None:
        detail = self._details.get(name)
        if detail is None:
            return
        row = table.currentRow()
        if 0 <= row < len(items):
            detail.setPlainText(
                json.dumps(items[row], ensure_ascii=False, sort_keys=True, indent=2)
            )
        else:
            detail.setPlainText("")

    def _fill_table(self, table: QTableWidget, rows: list) -> None:
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column, value in enumerate(row):
                table.setItem(row_index, column, _cell(value))

    # ------------------------------------------------------------- refreshers

    def _register_refreshers(self) -> None:
        self._register_refresher("Overview", self._refresh_overview)
        self._register_refresher("HTTP", self._refresh_http)
        self._register_refresher("Streams", self._refresh_streams)
        self._register_refresher("Telnet", self._refresh_telnet)
        self._register_refresher("Findings", self._refresh_findings)
        self._register_refresher("Timeline", self._refresh_timeline)
        self._register_refresher("Manual queue", self._refresh_queue)
        self._register_refresher("Notes", self._refresh_notes)
        self._register_refresher("Export", self._refresh_export)

    def _paged_payload(self, name: str, loader: Callable[[], dict]) -> Optional[dict]:
        """Load one page payload or surface the error in the page banner."""
        if not self._require_services(name):
            return None
        try:
            return loader()
        except (OSError, ValueError, KeyError) as error:
            self._banners[name].setText(self._t("error: ") + str(error))
            return None

    def _refresh_overview(self) -> None:
        table = self._overview_table
        if not self._require_services("Overview"):
            table.setRowCount(0)
            self._overview_json.setPlainText("")
            return
        try:
            payload = self.services.overview()
        except (OSError, ValueError, KeyError) as error:
            self._banners["Overview"].setText(self._t("error: ") + str(error))
            return
        capture = payload.get("capture", {})
        overview = payload.get("overview", {})
        rows = [
            (self._t("Capture"), capture.get("source_name", "")),
            (self._t("Capture SHA-256"), str(capture.get("sha256", ""))),
            (self._t("Capture bytes"), capture.get("byte_length", "")),
            (self._t("Database schema"), capture.get("database_schema", "")),
        ]
        for name in sorted(overview):
            rows.append((name, overview[name]))
        for status, count in sorted(payload.get("coverage", {}).items()):
            rows.append((self._t("coverage: ") + self._t(str(status)), count))
        self._fill_table(table, rows)
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
        limit = 200_000
        if len(text) > limit:
            text = text[:limit] + "\n… (preview truncated)"
        self._overview_json.setPlainText(text)
        truncated = [
            name
            for name, value in payload.items()
            if isinstance(value, dict) and value.get("truncated")
        ]
        extra = (
            self._t("truncated collections: ") + ", ".join(sorted(truncated))
            if truncated
            else ""
        )
        self._banners["Overview"].setText(
            self._t("Overview ready.") + (f" {extra}" if extra else "")
        )

    def _refresh_http(self) -> None:
        offset = self._offsets.get("HTTP", 0)
        payload = self._paged_payload(
            "HTTP",
            lambda: self.services.transactions(
                uri=self._uri_filter or None, offset=offset
            ),
        )
        if payload is None:
            self._http_items = []
            self._fill_table(self._http_table, [])
            return
        items = list(payload.get("items", []))
        self._http_items = items
        rows = []
        for item in items:
            request = item.get("request") or {}
            response = item.get("response") or {}
            rows.append(
                (
                    request.get("frame"),
                    request.get("method"),
                    request.get("host"),
                    request.get("uri"),
                    item.get("status"),
                    response.get("code"),
                )
            )
        self._fill_table(self._http_table, rows)
        self._set_banner(
            "HTTP",
            offset=offset,
            count=payload.get("count", len(items)),
            total=payload.get("total", len(items)),
        )

    def _refresh_streams(self) -> None:
        offset = self._offsets.get("Streams", 0)
        payload = self._paged_payload(
            "Streams", lambda: self.services.streams(offset=offset)
        )
        if payload is None:
            self._streams_items = []
            self._fill_table(self._streams_table, [])
            return
        items = list(payload.get("items", []))
        self._streams_items = items
        rows = []
        for item in items:
            bytes_info = item.get("bytes") or {}
            rows.append(
                (
                    item.get("stream_index"),
                    item.get("conversation_id"),
                    " <-> ".join(str(endpoint) for endpoint in item.get("endpoints", [])),
                    item.get("direction"),
                    item.get("status"),
                    bytes_info.get("output"),
                )
            )
        self._fill_table(self._streams_table, rows)
        self._set_banner(
            "Streams",
            offset=offset,
            count=payload.get("count", len(items)),
            total=payload.get("total", len(items)),
        )

    def _refresh_telnet(self) -> None:
        offset = self._offsets.get("Telnet", 0)
        payload = self._paged_payload(
            "Telnet", lambda: self.services.telnet_dialogues(offset=offset)
        )
        if payload is None:
            self._telnet_items = []
            self._fill_table(self._telnet_table, [])
            return
        items = list(payload.get("items", []))
        self._telnet_items = items
        rows = []
        for item in items:
            directions = item.get("directions") or {}
            client = directions.get("client") or {}
            server = directions.get("server") or {}
            rows.append(
                (
                    item.get("conversation_id"),
                    item.get("status"),
                    item.get("current"),
                    client.get("byte_length"),
                    server.get("byte_length"),
                    item.get("record_count"),
                )
            )
        self._fill_table(self._telnet_table, rows)
        self._set_banner(
            "Telnet",
            offset=offset,
            count=payload.get("count", len(items)),
            total=payload.get("total", len(items)),
        )

    def _refresh_findings(self) -> None:
        offset = self._offsets.get("Findings", 0)
        payload = self._paged_payload(
            "Findings", lambda: self.services.findings(candidate_offset=offset)
        )
        if payload is None:
            self._candidate_items = []
            self._finding_items = []
            self._fill_table(self._candidates_table, [])
            self._fill_table(self._findings_table, [])
            return
        candidates = list(payload.get("candidates", []))
        findings = list(payload.get("findings", []))
        self._candidate_items = candidates
        self._finding_items = findings
        self._fill_table(
            self._candidates_table,
            [
                (
                    item.get("rank_score"),
                    item.get("kind"),
                    item.get("normalized_value"),
                    item.get("confidence"),
                )
                for item in candidates
            ],
        )
        self._fill_table(
            self._findings_table,
            [
                (
                    item.get("severity"),
                    item.get("detector"),
                    item.get("title"),
                    item.get("confidence"),
                )
                for item in findings
            ],
        )
        self._set_banner(
            "Findings",
            offset=offset,
            count=len(candidates),
            total=payload.get("candidate_total", len(candidates)),
            extra=f"; findings {len(findings)} of "
            f"{payload.get('finding_total', len(findings))}",
        )

    def _refresh_timeline(self) -> None:
        offset = self._offsets.get("Timeline", 0)
        kind = self._timeline_kind.text().strip() or None
        include = self._timeline_duplicates.isChecked()
        payload = self._paged_payload(
            "Timeline",
            lambda: self.services.timeline(
                event_kind=kind, include_duplicates=include, offset=offset
            ),
        )
        if payload is None:
            self._timeline_items = []
            self._fill_table(self._timeline_table, [])
            return
        items = list(payload.get("items", []))
        self._timeline_items = items
        self._fill_table(
            self._timeline_table,
            [
                (
                    item.get("request_frame"),
                    item.get("event_kind"),
                    item.get("target"),
                    item.get("status"),
                    item.get("semantic_key"),
                )
                for item in items
            ],
        )
        self._set_banner(
            "Timeline",
            offset=offset,
            count=payload.get("count", len(items)),
            total=payload.get("total", len(items)),
            extra=self._t("(duplicates included)") if include else "",
        )

    def _refresh_queue(self) -> None:
        offset = self._offsets.get("Manual queue", 0)
        state = self._queue_state.currentText()
        payload = self._paged_payload(
            "Manual queue",
            lambda: self.services.manual_queue(
                state=None if state == "all" else state, offset=offset
            ),
        )
        if payload is None:
            self._queue_items = []
            self._fill_table(self._queue_table, [])
            return
        items = list(payload.get("items", []))
        self._queue_items = items
        self._fill_table(
            self._queue_table,
            [
                (
                    item.get("suggested_priority"),
                    item.get("state"),
                    item.get("task_kind"),
                    f"{item.get('subject_kind')}:{item.get('subject_id')}",
                    item.get("signal_count"),
                )
                for item in items
            ],
        )
        self._set_banner(
            "Manual queue",
            offset=offset,
            count=payload.get("count", len(items)),
            total=payload.get("total", len(items)),
        )

    def _refresh_notes(self) -> None:
        payload = self._paged_payload("Notes", lambda: self.services.notes())
        if payload is None:
            self._note_items = []
            self._fill_table(self._notes_table, [])
            return
        items = list(payload.get("items", []))
        self._note_items = items
        self._fill_table(
            self._notes_table,
            [
                (
                    item.get("note_id"),
                    item.get("subject_kind"),
                    item.get("subject_id"),
                    item.get("body"),
                )
                for item in items
            ],
        )
        self._set_banner(
            "Notes",
            offset=payload.get("offset", 0),
            count=payload.get("count", len(items)),
            total=payload.get("total", len(items)),
        )

    def _refresh_export(self) -> None:
        if self._require_services("Export"):
            self._banners["Export"].setText(self._t("Ready to export a bounded offline bundle."))
