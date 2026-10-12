"""Main investigation window over the bounded read models."""

from __future__ import annotations

import json
from contextlib import suppress
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
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressDialog,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..config import Settings
from ..engines.tshark import (
    TSHARK_TOO_OLD_TEMPLATE,
    TlsRsaKey,
    _tshark_version,
    find_tls_keylog,
    load_tls_keylog,
    load_tls_rsa_key,
    tshark_too_old,
)
from ..project import ProjectInfo, create_project
from .i18n import apply_widget_translations, detect_language, translate
from .services import PAGE_LIMIT, ProjectServices, resolve_tshark
from .settings import GuiSettings, load_settings, save_settings
from .workers import SingleRunWorker, StageWorker

CORE_PAGES = (
    "Overview",
    "Files",
    "Frames",
    "Statistics",
    "HTTP",
    "Streams",
    "Findings",
)
OPTIONAL_PAGES = ("Telnet",)
HIDDEN_PAGES = ("Export",)
PAGE_NAMES = CORE_PAGES
STACK_PAGES = CORE_PAGES + OPTIONAL_PAGES + HIDDEN_PAGES
HELP_BODY = (
    "1. Drag a .pcap / .pcapng onto the window (or File > Open capture). "
    "Analysis starts automatically.\n"
    "2. Read the solve wizard: protocol mix, challenge type, and flag "
    "candidates. Double-click a suggestion to jump to the evidence.\n"
    "3. Double-click a flag candidate to copy it. If the contest uses a "
    "custom wrapper, enter that regex and press Rescan.\n"
    "4. Files lists exported objects. HTTP and TCP streams follow the "
    "conversation. Telnet appears only when that traffic exists.\n"
    "5. Findings lists flags, exam points, and the reconstructed "
    "operation log. Tick Technical details for the raw JSON.\n"
    "Search everywhere is the strings | grep replacement "
    "(plain text, hex, and Base64)."
)
TASK_STATES = ("open", "in-progress", "resolved", "dismissed")
DEFAULT_REMOTE_PROBE_PATHS = (
    "/usr/bin/python3,/usr/bin/file,/usr/bin/strings,/usr/bin/binwalk,"
    "/usr/local/bin/binwalk,/usr/bin/zsteg,/usr/local/bin/zsteg,"
    "/usr/bin/steghide,/usr/bin/exiftool,/usr/bin/tshark"
)


_MAX_TABLE_COLUMN_WIDTH = 720


def _cell(value: Any) -> QTableWidgetItem:
    text = "" if value is None else str(value)
    item = QTableWidgetItem(text)
    item.setToolTip(text)
    return item


def _fit_table_columns(table: QTableWidget) -> None:
    """Size columns to their contents, then cap runaway cells and stretch the last."""

    header = table.horizontalHeader()
    header.setStretchLastSection(False)
    table.resizeColumnsToContents()
    for column in range(table.columnCount()):
        width = table.columnWidth(column) + 12
        table.setColumnWidth(column, min(max(width, 72), _MAX_TABLE_COLUMN_WIDTH))
    header.setStretchLastSection(True)


def _table(headers: tuple[str, ...]) -> QTableWidget:
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    widget.setWordWrap(False)
    widget.setTextElideMode(Qt.TextElideMode.ElideRight)
    widget.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    header = widget.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    header.setMinimumSectionSize(72)
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
        self._language = detect_language()
        try:
            from importlib.metadata import PackageNotFoundError, version

            app_version = version("auto-shark")
        except PackageNotFoundError:  # pragma: no cover - source-tree runs
            app_version = "dev"
        self._app_version = app_version
        self.setWindowTitle(f"Auto-Shark v{app_version}")
        self.resize(1280, 820)
        self.setAcceptDrops(True)
        self._build_menu()
        self._build_body()
        apply_widget_translations(self, self._language)

    # ------------------------------------------------------------ drag & drop

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if url.isLocalFile() and Path(url.toLocalFile()).suffix.lower() in (
                    ".pcap",
                    ".pcapng",
                ):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt naming
        for url in event.mimeData().urls():
            if not url.isLocalFile():
                continue
            capture = Path(url.toLocalFile())
            if capture.suffix.lower() not in (".pcap", ".pcapng"):
                continue
            self.open_capture_file(capture)
            event.acceptProposedAction()
            return
        event.ignore()

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
        action = file_menu.addAction("Export analysis bundle…")
        action.triggered.connect(self._export_bundle)
        file_menu.addSeparator()
        action = file_menu.addAction("E&xit")
        action.triggered.connect(self.close)
        edit_menu = menu.addMenu("&Edit")
        action = edit_menu.addAction("&Settings…")
        action.triggered.connect(self._settings_dialog)
        analysis_menu = menu.addMenu("&Analysis")
        action = analysis_menu.addAction("&Re-run full analysis")
        action.triggered.connect(self.run_analysis)
        self._cancel_action = analysis_menu.addAction("&Cancel running analysis")
        self._cancel_action.triggered.connect(self.cancel_analysis)
        self._cancel_action.setEnabled(False)
        analysis_menu.addSeparator()
        action = analysis_menu.addAction("&Refresh page")
        action.triggered.connect(self.refresh_current_page)
        help_menu = menu.addMenu("&Help")
        action = help_menu.addAction("&How to use")
        action.triggered.connect(self._show_help)
        help_button = QToolButton()
        help_button.setText("?")
        help_button.setToolTip(self._t("How to use"))
        help_button.clicked.connect(self._show_help)
        menu.setCornerWidget(help_button)
        self._help_button = help_button

    def _build_body(self) -> None:
        splitter = QSplitter()
        self._nav = QListWidget()
        self._nav.currentRowChanged.connect(self._nav_changed)
        splitter.addWidget(self._nav)
        self._stack = QStackedWidget()
        builders: dict[str, Callable[[], QWidget]] = {
            "Overview": self._build_overview_page,
            "Files": self._build_files_page,
            "Frames": self._build_frames_page,
            "Statistics": self._build_statistics_page,
            "HTTP": self._build_http_page,
            "Streams": self._build_streams_page,
            "Telnet": self._build_telnet_page,
            "Findings": self._build_findings_page,
            "Export": self._build_export_page,
        }
        for name in STACK_PAGES:
            page = builders[name]()
            self._pages[name] = page
            self._stack.addWidget(page)
        self._aux_banner = QLabel("")
        self._aux_banner.hide()
        self._banners["Timeline"] = self._aux_banner
        self._banners["Manual queue"] = self._aux_banner
        splitter.addWidget(self._stack)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([180, 1100])
        self.setCentralWidget(splitter)
        self._register_refreshers()
        self._rebuild_nav()
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
        return self._page_scaffold("Overview", self._build_overview_stack())

    def _build_overview_stack(self) -> QStackedWidget:
        self._overview_stack = QStackedWidget()

        start = QWidget()
        start_layout = QVBoxLayout(start)
        start_layout.addStretch(1)
        hint = QLabel("Drop a .pcap / .pcapng file here to analyze it")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._start_hint = hint
        start_layout.addWidget(hint)
        secondary = QLabel("…or use File > Open capture. Analysis starts automatically.")
        secondary.setAlignment(Qt.AlignmentFlag.AlignCenter)
        start_layout.addWidget(secondary)
        self._start_tshark_status = QLabel("")
        self._start_tshark_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        start_layout.addWidget(self._start_tshark_status)
        self._start_recent = QListWidget()
        self._start_recent.itemDoubleClicked.connect(self._open_recent_capture)
        start_layout.addWidget(self._start_recent, 1)
        start_layout.addStretch(1)
        self._overview_stack.addWidget(start)

        report = QWidget()
        report_layout = QVBoxLayout(report)

        flag_row = QHBoxLayout()
        flag_row.addWidget(QLabel("Flag format (regex):"))
        self._flag_format_edit = QLineEdit()
        self._flag_format_edit.setPlaceholderText("e.g. SUCTF\\{[^}]{1,128}\\}")
        flag_row.addWidget(self._flag_format_edit, 1)
        rescan_button = QPushButton("Rescan")
        rescan_button.clicked.connect(self._rescan_flag_format)
        flag_row.addWidget(rescan_button)
        report_layout.addLayout(flag_row)

        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search everywhere:"))
        self._grep_edit = QLineEdit()
        self._grep_edit.setPlaceholderText("keyword, e.g. flag / password / PK")
        self._grep_edit.returnPressed.connect(self._run_grep)
        search_row.addWidget(self._grep_edit, 1)
        grep_button = QPushButton("Search")
        grep_button.clicked.connect(self._run_grep)
        search_row.addWidget(grep_button)
        report_layout.addLayout(search_row)

        self._wizard_hierarchy = QLabel("")
        self._wizard_hierarchy.setWordWrap(True)
        report_layout.addWidget(self._wizard_hierarchy)

        report_layout.addWidget(QLabel("Challenge types:"))
        self._suggestions_table = _table(("Type", "Evidence", "Suggestion"))
        self._suggestions_table.itemDoubleClicked.connect(self._open_suggestion)
        report_layout.addWidget(self._suggestions_table, 2)

        report_layout.addWidget(QLabel("Flag candidates (double-click to copy):"))
        self._wizard_candidates = _table(("Value", "Kind", "Rank"))
        self._wizard_candidates.itemDoubleClicked.connect(self._copy_candidate)
        report_layout.addWidget(self._wizard_candidates, 2)

        self._wizard_fallback = QLabel("")
        self._wizard_fallback.setWordWrap(True)
        report_layout.addWidget(self._wizard_fallback)

        report_layout.addWidget(QLabel("Next steps:"))
        queue_row = QHBoxLayout()
        queue_row.addWidget(QLabel("State:"))
        self._queue_state = QComboBox()
        for key in ("open", "all", "in-progress", "resolved", "dismissed"):
            self._queue_state.addItem(key, key)
        self._queue_state.currentTextChanged.connect(lambda _: self._refresh_queue())
        queue_row.addWidget(self._queue_state)
        change_button = QPushButton("Change state of selected…")
        change_button.clicked.connect(self._change_task_state)
        queue_row.addWidget(change_button)
        queue_row.addStretch(1)
        report_layout.addLayout(queue_row)
        self._queue_table = _table(("Priority", "State", "Kind", "Subject", "Signals"))
        self._queue_table.itemSelectionChanged.connect(
            lambda: self._show_selected_json(
                "Overview", self._queue_table, self._queue_items
            )
        )
        self._queue_table.setMaximumHeight(160)
        report_layout.addWidget(self._queue_table)

        self._overview_tech = QCheckBox("Technical details")
        self._overview_tech.toggled.connect(self._toggle_overview_tech)
        report_layout.addWidget(self._overview_tech)
        self._overview_table = _table(("Metric", "Value"))
        self._overview_table.hide()
        report_layout.addWidget(self._overview_table)
        self._overview_json_label = QLabel("Report JSON (bounded preview of report/v1):")
        self._overview_json_label.hide()
        report_layout.addWidget(self._overview_json_label)
        self._overview_json = QPlainTextEdit()
        self._overview_json.setReadOnly(True)
        self._overview_json.setMaximumHeight(160)
        self._overview_json.hide()
        report_layout.addWidget(self._overview_json)
        self._overview_stack.addWidget(report)
        return self._overview_stack

    def _refresh_start_panel(self) -> None:
        self._start_recent.clear()
        for entry in self._settings.recent_captures:
            path = Path(entry)
            if path.is_file():
                self._start_recent.addItem(str(path))
        tshark = self._tshark_path()
        if tshark is not None:
            parsed = _tshark_version(tshark)
            if tshark_too_old(parsed) and parsed is not None:
                self._start_tshark_status.setText(self._tshark_too_old_text(parsed))
            else:
                version = ""
                if parsed is not None:
                    version = f" (v{'.'.join(str(part) for part in parsed)})"
                self._start_tshark_status.setText(
                    self._t("TShark ready: ") + str(tshark) + version
                )
        else:
            self._start_tshark_status.setText(
                self._t("TShark was not found — install Wireshark or set the path in Settings.")
            )

    def _open_recent_capture(self, item) -> None:
        path = Path(item.text())
        if path.is_file():
            self.open_capture_file(path)

    # -------------------------------------------------------- statistics page

    def _build_statistics_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        tabs = QTabWidget()

        proto_tab = QWidget()
        proto_layout = QVBoxLayout(proto_tab)
        self._stats_protocol_table = _table(
            ("Protocol", "Frames", "Share", "First", "Last")
        )
        proto_layout.addWidget(self._stats_protocol_table)
        tabs.addTab(proto_tab, self._t("Protocol hierarchy"))

        conv_tab = QWidget()
        conv_layout = QVBoxLayout(conv_tab)
        conv_hint = QLabel(
            self._t(
                "Sorted by bytes. Double-click to filter the Frames page by stream."
            )
        )
        conv_hint.setWordWrap(True)
        conv_layout.addWidget(conv_hint)
        self._stats_conversation_table = _table(
            ("Proto", "Stream", "Endpoint A", "Endpoint B", "Frames", "Bytes", "Duration")
        )
        self._stats_conversation_table.itemDoubleClicked.connect(self._jump_to_stream)
        conv_layout.addWidget(self._stats_conversation_table)
        tabs.addTab(conv_tab, self._t("Conversations"))

        http_tab = QWidget()
        http_layout = QVBoxLayout(http_tab)
        http_layout.addWidget(QLabel(self._t("Status codes:")))
        self._stats_status_table = _table(("Code", "Count"))
        http_layout.addWidget(self._stats_status_table, 1)
        http_layout.addWidget(QLabel(self._t("Top request URIs:")))
        self._stats_uri_table = _table(("Count", "URI"))
        http_layout.addWidget(self._stats_uri_table, 2)
        tabs.addTab(http_tab, self._t("HTTP statistics"))

        dns_tab = QWidget()
        dns_layout = QVBoxLayout(dns_tab)
        self._stats_dns_table = _table(("First frame", "Query name"))
        dns_layout.addWidget(self._stats_dns_table)
        tabs.addTab(dns_tab, self._t("DNS query names"))

        layout.addWidget(tabs, 1)
        return self._page_scaffold("Statistics", body)

    def _jump_to_stream(self, item) -> None:
        row = item.row()
        items = getattr(self, "_stats_conversations", [])
        if not 0 <= row < len(items):
            return
        conv = items[row]
        proto = str(conv.get("protocol") or "tcp")
        stream = conv.get("stream_index")
        if stream is None:
            return
        self._filter_combo.setEditText(f"{proto}.stream eq {stream}")
        self._nav.setCurrentRow(list(PAGE_NAMES).index("Frames"))
        self._apply_display_filter()

    def _refresh_statistics(self) -> None:
        if not self._require_services("Statistics"):
            self._fill_table(self._stats_protocol_table, [])
            self._fill_table(self._stats_conversation_table, [])
            self._fill_table(self._stats_status_table, [])
            self._fill_table(self._stats_uri_table, [])
            self._fill_table(self._stats_dns_table, [])
            return
        try:
            payload = self.services.statistics()
        except (OSError, ValueError) as error:
            self._banners["Statistics"].setText(self._t("error: ") + str(error))
            return
        protocols = list(payload.get("protocols") or [])
        base = max((int(item.get("frame_count") or 0) for item in protocols), default=1)
        self._fill_table(
            self._stats_protocol_table,
            [
                (
                    item.get("protocol_label"),
                    item.get("frame_count"),
                    f"{int(item.get('frame_count') or 0) * 100.0 / base:.1f}%",
                    item.get("first_frame"),
                    item.get("last_frame"),
                )
                for item in protocols
            ],
        )
        conversations = list(payload.get("conversations") or [])
        self._stats_conversations = conversations
        self._fill_table(
            self._stats_conversation_table,
            [
                (
                    item.get("protocol"),
                    item.get("stream_index"),
                    item.get("endpoint_a"),
                    item.get("endpoint_b"),
                    item.get("frame_count"),
                    item.get("captured_bytes"),
                    (
                        (
                            f"{float(item.get('last_time') or 0)}"
                            f" - {float(item.get('first_time') or 0):.3f}s"
                        )
                        if item.get("first_time") is not None
                        else ""
                    ),
                )
                for item in conversations
            ],
        )
        self._fill_table(
            self._stats_status_table,
            [
                (item.get("code"), item.get("count"))
                for item in payload.get("status_codes") or []
            ],
        )
        self._fill_table(
            self._stats_uri_table,
            [
                (item.get("count"), item.get("uri"))
                for item in payload.get("top_uris") or []
            ],
        )
        try:
            names = self.services.dns_names()
        except (OSError, ValueError) as error:
            self._fill_table(self._stats_dns_table, [])
            self._banners["Statistics"].setText(self._t("error: ") + str(error)[:120])
            return
        self._fill_table(
            self._stats_dns_table,
            [(item.get("first_frame"), item.get("name")) for item in names],
        )
        self._banners["Statistics"].setText(
            self._t("Statistics ready.")
            + f"  conversations: {len(conversations)}  dns: {len(names)}"
        )

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
        view_request = QPushButton("View request body")
        view_request.clicked.connect(lambda: self._view_http_body("request"))
        filter_row.addWidget(view_request)
        view_response = QPushButton("View response body")
        view_response.clicked.connect(lambda: self._view_http_body("response"))
        filter_row.addWidget(view_response)
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
        view_button = QPushButton("View content")
        view_button.clicked.connect(self._view_selected_stream)
        nav.addWidget(view_button)
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
        view_button = QPushButton("View content")
        view_button.clicked.connect(self._view_selected_telnet)
        nav.addWidget(view_button)
        nav.addStretch(1)
        layout.addLayout(nav)
        self._telnet_detail = self._detail_pane("Telnet")
        layout.addWidget(self._telnet_detail, 1)
        return self._page_scaffold("Telnet", body)

    def _build_findings_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.addWidget(QLabel("Flag candidates (double-click to copy):"))
        self._candidates_table = _table(("Flag", "Exam point", "Evidence", "Confidence"))
        self._candidates_table.itemSelectionChanged.connect(self._show_findings_detail)
        self._candidates_table.itemDoubleClicked.connect(self._copy_findings_flag)
        layout.addWidget(self._candidates_table, 2)
        layout.addWidget(QLabel("Exam points:"))
        self._findings_table = _table(("Exam point", "What to look at", "Next action"))
        self._findings_table.itemSelectionChanged.connect(self._show_findings_detail)
        layout.addWidget(self._findings_table, 2)
        layout.addWidget(QLabel("Operation log:"))
        self._timeline_kind = QLineEdit()
        self._timeline_kind.hide()
        self._timeline_duplicates = QCheckBox("Include duplicates")
        self._timeline_duplicates.hide()
        self._timeline_table = _table(("Frame start", "What happened", "Target", "Status"))
        self._timeline_table.itemSelectionChanged.connect(
            lambda: self._show_selected_json(
                "Findings", self._timeline_table, self._timeline_items
            )
        )
        layout.addWidget(self._timeline_table, 2)
        nav = QHBoxLayout()
        prev = QPushButton("Previous candidates")
        prev.clicked.connect(lambda: self._findings_step(-1))
        next_ = QPushButton("Next candidates")
        next_.clicked.connect(lambda: self._findings_step(1))
        nav.addWidget(prev)
        nav.addWidget(next_)
        nav.addStretch(1)
        layout.addLayout(nav)
        self._findings_tech = QCheckBox("Technical details")
        self._findings_tech.toggled.connect(self._toggle_findings_tech)
        layout.addWidget(self._findings_tech)
        self._findings_detail = self._detail_pane("Findings")
        self._findings_detail.hide()
        layout.addWidget(self._findings_detail, 1)
        return self._page_scaffold("Findings", body)

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

    # --------------------------------------------------------- wizard/files

    def _populate_wizard(self) -> None:
        if self.services is None:
            return
        try:
            wizard = self.services.wizard()
        except (OSError, ValueError, KeyError) as error:
            self._wizard_hierarchy.setText(self._t("error: ") + str(error))
            return
        if not self._flag_format_edit.text().strip():
            self._flag_format_edit.setText(wizard.get("flag_format") or "")
        hierarchy = wizard.get("protocol_hierarchy") or []
        self._wizard_hierarchy.setText(
            self._t("Protocol hierarchy: ")
            + "  ".join(f"{item['label']} {item['share']}%" for item in hierarchy[:6])
        )
        suggestions = list(wizard.get("suggestions") or [])
        self._suggestion_actions = [item.get("action") for item in suggestions]
        self._suggestions_table.setVisible(bool(suggestions))
        self._fill_table(
            self._suggestions_table,
            [
                (item.get("title"), item.get("evidence"), item.get("detail"))
                for item in suggestions
            ],
        )
        candidates = list(wizard.get("flag_candidates") or [])
        self._fill_table(
            self._wizard_candidates,
            [
                (
                    ("* " if item.get("user_format_match") else "") + str(item.get("value")),
                    item.get("kind"),
                    item.get("rank_score"),
                )
                for item in candidates
            ],
        )
        if suggestions:
            self._wizard_fallback.setText("")
        else:
            steps = [
                f"{step.get('title')}: {step.get('detail')}"
                for step in wizard.get("fallback_steps") or []
            ]
            self._wizard_fallback.setText(
                self._t("No challenge type recognized yet. Standard checklist:") + "\n"
                + "\n".join(steps)
            )

    def _run_grep(self) -> None:
        if self.services is None:
            return
        needle = self._grep_edit.text().strip()
        if not needle:
            return
        try:
            result = self.services.grep(needle)
        except (OSError, ValueError) as error:
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("error: ") + str(error))
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(self._t("Search results"))
        dialog.resize(860, 480)
        layout = QVBoxLayout(dialog)
        summary = QLabel(
            self._t("matches")
            + f": {len(result.get('matches') or [])} · "
            + self._t("blobs scanned")
            + f": {result.get('blobs_scanned')}/{result.get('blobs_total')}"
        )
        layout.addWidget(summary)
        table = _table(("Variant", "Source", "Frame range", "Offset", "Context"))
        matches = list(result.get("matches") or [])
        self._fill_table(
            table,
            [
                (
                    match.get("variant"),
                    match.get("source_kind"),
                    f"{match.get('frame_start')}-{match.get('frame_end')}",
                    match.get("offset"),
                    match.get("context"),
                )
                for match in matches
            ],
        )
        layout.addWidget(table, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        buttons.addButton(QDialogButtonBox.StandardButton.Close).clicked.connect(dialog.accept)
        layout.addWidget(buttons)
        dialog.exec()

    def _rescan_flag_format(self) -> None:
        if self.services is None:
            return
        pattern = self._flag_format_edit.text().strip()
        from ..search import compile_flag_pattern

        try:
            compile_flag_pattern(pattern or None)
        except ValueError as error:
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("error: ") + str(error))
            return
        try:
            self.services.set_flag_format(pattern)
        except (OSError, ValueError) as error:
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("error: ") + str(error))
            return
        self._start_stage_worker(self.services.rescan_stages())

    def _open_suggestion(self, item) -> None:
        row = item.row()
        actions = getattr(self, "_suggestion_actions", [])
        if 0 <= row < len(actions):
            self._jump_action(actions[row])

    def _jump_action(self, action: str) -> None:
        mapping = {
            "files": "Files",
            "http": "HTTP",
            "streams": "Streams",
            "telnet": "Telnet",
            "findings": "Findings",
            "timeline": "Findings",
        }
        page = mapping.get(str(action))
        if page is None:
            return
        self._select_page(page)

    def _copy_candidate(self, item) -> None:
        value = item.text().lstrip("* ").strip()
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(value)
        self.statusBar().showMessage(self._t("Copied: ") + value, 5000)

    # ------------------------------------------------------------- frames page

    _FILTER_CHEATSHEET = (
        "http",
        "dns",
        "icmp",
        "usb",
        "tls",
        'frame contains "flag"',
        'tcp contains "flag"',
        'http.request.uri contains "flag"',
        "http.request.method == POST",
        "http.response.code == 200",
        "http.response.code >= 400",
        "telnet",
        "ftp || ftp-data",
        "usb.capdata || usbhid.data",
    )

    _FILTER_HELP = (
        (
            "协议",
            (
                ("http", "所有 HTTP 流量"),
                ("dns", "DNS 查询/应答"),
                ("icmp", "Ping 及 ICMP 隐写"),
                ("usb", "USB 键鼠流量"),
                ("tls", "加密流量（判断加密盲区）"),
                ("telnet || ftp", "远程登录与文件传输"),
            ),
        ),
        (
            "contains 搜索",
            (
                ('frame contains "flag"', "全帧字节搜 flag（Ctrl+F 分组字节流）"),
                ('tcp contains "password"', "TCP 载荷搜关键字"),
                ('http.request.uri contains "upload"', "URI 含 upload"),
                ("http contains \"flag\"", "HTTP 报文含 flag（含响应正文）"),
            ),
        ),
        (
            "字段匹配",
            (
                ("http.request.method == POST", "只看 POST（上传/登录）"),
                ("http.response.code == 200", "命中 200（爆破找成功）"),
                ("http.response.code >= 400", "异常响应（爆破 404/403）"),
                ("ip.addr == 192.168.1.1", "指定 IP 的全部流量"),
            ),
        ),
        (
            "流跟踪",
            (
                ("tcp.stream eq 0", "第 0 条 TCP 流"),
                ("udp.stream eq 3", "第 3 条 UDP 流"),
                ("tcp.len > 0", "有载荷的 TCP 包"),
                ("dns.flags.response == 0", "只看 DNS 查询（外带分析）"),
            ),
        ),
        (
            "逻辑组合",
            (
                ("http && ip.dst == 10.0.0.5", "AND 组合"),
                ("dns || icmp", "OR 组合"),
                ("!tls", "排除 TLS 噪音"),
                ('tcp && !(tcp contains "Chrome")', "括号取反"),
            ),
        ),
    )

    def _build_frames_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Display filter:"))
        self._filter_combo = QComboBox()
        self._filter_combo.setEditable(True)
        self._filter_combo.lineEdit().returnPressed.connect(self._apply_display_filter)
        self._filter_combo.lineEdit().setPlaceholderText(
            'e.g.  http.request.uri contains "flag"   (click ? for syntax)'
        )
        self._filter_combo.addItems(self._settings.filter_history)
        filter_row.addWidget(self._filter_combo, 2)
        help_button = QPushButton("?")
        help_button.setFixedWidth(32)
        help_button.clicked.connect(self._show_filter_help)
        filter_row.addWidget(help_button)
        apply_button = QPushButton("Apply")
        apply_button.clicked.connect(self._apply_display_filter)
        filter_row.addWidget(apply_button)
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self._clear_display_filter)
        filter_row.addWidget(clear_button)
        filter_row.addWidget(QLabel("Quick:"))
        self._filter_cheatsheet = QComboBox()
        self._filter_cheatsheet.addItems(self._FILTER_CHEATSHEET)
        self._filter_cheatsheet.activated.connect(self._use_cheatsheet_filter)
        filter_row.addWidget(self._filter_cheatsheet)
        self._follow_tcp_button = QPushButton("Follow TCP stream")
        self._follow_tcp_button.clicked.connect(lambda: self._follow_selected_stream("tcp"))
        filter_row.addWidget(self._follow_tcp_button)
        self._follow_udp_button = QPushButton("Follow UDP stream")
        self._follow_udp_button.clicked.connect(lambda: self._follow_selected_stream("udp"))
        filter_row.addWidget(self._follow_udp_button)
        self._follow_http_button = QPushButton("Follow HTTP stream")
        self._follow_http_button.clicked.connect(lambda: self._follow_selected_stream("http"))
        filter_row.addWidget(self._follow_http_button)
        layout.addLayout(filter_row)

        self._frames_table = _table(
            ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        )
        self._frames_table.itemDoubleClicked.connect(self._show_frame_detail)
        self._frames_table.itemSelectionChanged.connect(self._update_follow_buttons)
        layout.addWidget(self._frames_table, 1)

        nav = QHBoxLayout()
        prev = QPushButton("Previous")
        prev.clicked.connect(lambda: self._page_step("Frames", -1))
        next_ = QPushButton("Next")
        next_.clicked.connect(lambda: self._page_step("Frames", 1))
        nav.addWidget(prev)
        nav.addWidget(next_)
        nav.addStretch(1)
        layout.addLayout(nav)
        return self._page_scaffold("Frames", body)

    def _selected_frame(self):
        row = self._frames_table.currentRow()
        items = getattr(self, "_frames_items", [])
        if 0 <= row < len(items):
            return items[row]
        return None

    def _apply_display_filter(self) -> None:
        text = self._filter_combo.currentText().strip()
        self._offsets["Frames"] = 0
        if text:
            self._settings.remember_filter(text)
            with suppress(OSError):
                save_settings(self._settings)
            self._filter_combo.clear()
            self._filter_combo.addItems(self._settings.filter_history)
            self._filter_combo.setEditText(text)
        self._refresh_page("Frames")()

    def _clear_display_filter(self) -> None:
        self._filter_combo.setEditText("")
        self._offsets["Frames"] = 0
        self._refresh_page("Frames")()

    def _show_filter_help(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self._t("Display filter syntax"))
        dialog.resize(720, 520)
        layout = QVBoxLayout(dialog)
        hint = QLabel(self._t("Click a row to insert and run the filter."))
        layout.addWidget(hint)
        tabs = QTabWidget()
        for category, entries in self._FILTER_HELP:
            table = _table((self._t("Filter"), self._t("Meaning")))
            self._fill_table(table, entries)
            table.itemDoubleClicked.connect(
                lambda item, table=table: self._insert_filter_from_help(table, item, dialog)
            )
            tabs.addTab(table, self._t(category))
        layout.addWidget(tabs, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        buttons.addButton(QDialogButtonBox.StandardButton.Close).clicked.connect(dialog.accept)
        layout.addWidget(buttons)
        dialog.exec()

    def _insert_filter_from_help(self, table, item, dialog) -> None:
        row = item.row()
        if table.item(row, 0) is None:
            return
        text = table.item(row, 0).text()
        self._filter_combo.setEditText(text)
        dialog.accept()
        self._apply_display_filter()

    def _update_follow_buttons(self) -> None:
        frame = self._selected_frame()
        has_tcp = getattr(self, "_frames_has_tcp", True)
        has_udp = getattr(self, "_frames_has_udp", True)
        for button in (
            self._follow_tcp_button,
            self._follow_udp_button,
            self._follow_http_button,
        ):
            button.setVisible(has_tcp or has_udp)
        self._follow_tcp_button.setEnabled(
            bool(frame and frame.get("tcp_stream") is not None)
        )
        self._follow_udp_button.setEnabled(
            bool(frame and frame.get("udp_stream") is not None)
        )
        protocol = str((frame or {}).get("protocol") or "")
        self._follow_http_button.setEnabled(
            bool(frame and frame.get("tcp_stream") is not None and "HTTP" in protocol.upper())
        )

    def _use_cheatsheet_filter(self, index: int) -> None:
        self._filter_combo.setEditText(self._FILTER_CHEATSHEET[index])
        self._apply_display_filter()

    def _follow_selected_stream(self, proto: str) -> None:
        frame = self._selected_frame()
        if frame is None or self.services is None:
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Select a row first."))
            return
        if proto == "http" or proto == "tcp":
            stream = frame.get("tcp_stream")
        else:
            stream = frame.get("udp_stream")
        if stream is None:
            QMessageBox.information(
                self,
                self._t("Auto-Shark"),
                self._t("This frame has no {proto} stream index.").format(proto=proto),
            )
            return
        # The follow expression only lands in the filter history — the
        # current filter text is intentionally NOT replaced (the Wireshark
        # pain point this page exists to fix).
        wire = "tcp" if proto in ("tcp", "http") else "udp"
        self._settings.remember_filter(f"{wire}.stream eq {stream}")
        with suppress(OSError):
            save_settings(self._settings)
        try:
            payload = self.services.follow_stream(proto, int(stream))
        except (OSError, ValueError) as error:
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("error: ") + str(error))
            return
        from .hexview import view_bytes

        frames_note = ""
        if payload.get("frames"):
            frames_note = f"frames {payload['frames'][0]}-{payload['frames'][1]} · "
        title = f"{proto}.stream eq {stream} — client"
        note = (
            f"{frames_note}{len(payload['client'])} B client / "
            f"{len(payload['server'])} B server · close and follow server for the reply"
        )
        data = payload["client"] or payload["server"]
        view_bytes(self, title, data, note)

    def _show_frame_detail(self, item) -> None:
        row = item.row()
        items = getattr(self, "_frames_items", [])
        if not 0 <= row < len(items) or self.services is None:
            return
        frame = items[row]
        from .hexview import view_text

        try:
            detail = self.services.frame_detail(int(frame.get("frame")))
        except (OSError, ValueError) as error:
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("error: ") + str(error))
            return
        view_text(self, f"Frame {frame.get('frame')} — {frame.get('info', '')[:60]}", detail)

    def _refresh_frames(self) -> None:
        offset = self._offsets.get("Frames", 0)
        filter_text = (
            self._filter_combo.currentText().strip()
            if hasattr(self, "_filter_combo")
            else ""
        )
        if not self._require_services("Frames"):
            self._fill_table(self._frames_table, [])
            return
        try:
            payload = self.services.frames(offset=offset, filter_text=filter_text)
        except (OSError, ValueError) as error:
            self._banners["Frames"].setText(self._t("error: ") + str(error))
            return
        items = list(payload.get("items") or [])
        self._frames_items = items
        time_base = payload.get("time_base") or 0.0
        self._frames_has_tcp = bool(payload.get("has_tcp"))
        self._frames_has_udp = bool(payload.get("has_udp"))
        self._fill_table(
            self._frames_table,
            [
                (
                    item.get("frame"),
                    f"{(item.get('time') or 0.0) - time_base:.6f}",
                    item.get("src"),
                    item.get("dst"),
                    item.get("protocol"),
                    item.get("length"),
                    item.get("info"),
                )
                for item in items
            ],
        )
        self._update_follow_buttons()
        suffix = f" [filter: {filter_text}]" if filter_text else ""
        self._set_banner(
            "Frames",
            offset=offset,
            count=len(items),
            total=payload.get("total", 0),
            extra=suffix,
        )
        if not items and payload.get("total", 0) == 0 and not filter_text:
            self._banners["Frames"].setText(
                self._t("No packet rows yet — they appear after the frames stage "
                        "(run the full analysis).")
            )

    def _build_files_page(self) -> QWidget:
        body = QWidget()
        layout = QVBoxLayout(body)
        buttons = QHBoxLayout()
        open_button = QPushButton("Open in Explorer")
        open_button.clicked.connect(self._open_selected_artifact)
        buttons.addWidget(open_button)
        view_button = QPushButton("View content")
        view_button.clicked.connect(self._view_selected_artifact)
        buttons.addWidget(view_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self._files_table = _table(("Name", "Media type", "Magic", "Bytes", "SHA-256"))
        layout.addWidget(self._files_table, 1)
        return self._page_scaffold("Files", body)

    def _selected_artifact(self):
        row = self._files_table.currentRow()
        items = getattr(self, "_files_items", [])
        if 0 <= row < len(items):
            return items[row]
        return None

    def _open_selected_artifact(self) -> None:
        artifact = self._selected_artifact()
        if artifact is None:
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Select a file first."))
            return
        path = self.services.root / str(artifact.get("relative_path"))
        if not path.is_file():
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("error: file missing"))
            return
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _view_selected_artifact(self) -> None:
        artifact = self._selected_artifact()
        if artifact is None or self.services is None:
            return
        path = self.services.blob_path(str(artifact.get("sha256")))
        if path is None or not path.is_file():
            QMessageBox.warning(self, self._t("Auto-Shark"), self._t("error: file missing"))
            return
        from .hexview import read_bounded, view_bytes

        view_bytes(
            self,
            str(artifact.get("name")),
            read_bounded(path),
            f"{artifact.get('byte_length')} bytes · {artifact.get('magic') or ''}",
        )

    # ------------------------------------------------------------ navigation

    def _nav_changed(self, row: int) -> None:
        item = self._nav.item(row)
        if item is None:
            return
        name = item.data(Qt.ItemDataRole.UserRole)
        widget = self._pages.get(str(name))
        if widget is None:
            return
        self._stack.setCurrentWidget(widget)
        self._refresh_page(str(name))()

    def current_page_name(self) -> str:
        item = self._nav.currentItem()
        if item is None:
            return "Overview"
        name = item.data(Qt.ItemDataRole.UserRole)
        return str(name) if name else "Overview"

    def _rebuild_nav(self, extra: tuple[str, ...] = ()) -> None:
        current = self.current_page_name() if self._nav.count() else "Overview"
        names = list(CORE_PAGES)
        for name in extra:
            if name not in names:
                names.append(name)
        self._nav.blockSignals(True)
        self._nav.clear()
        selected = 0
        for index, name in enumerate(names):
            item = QListWidgetItem(self._t(name))
            item.setData(Qt.ItemDataRole.UserRole, name)
            self._nav.addItem(item)
            if name == current:
                selected = index
        self._nav.setCurrentRow(selected)
        self._nav.blockSignals(False)

    def _select_page(self, name: str) -> None:
        if name in OPTIONAL_PAGES:
            found = False
            for row in range(self._nav.count()):
                item = self._nav.item(row)
                if item is not None and item.data(Qt.ItemDataRole.UserRole) == name:
                    found = True
                    break
            if not found:
                extra = []
                for row in range(self._nav.count()):
                    item = self._nav.item(row)
                    stored = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
                    if stored in OPTIONAL_PAGES:
                        extra.append(str(stored))
                if name not in extra:
                    extra.append(name)
                self._rebuild_nav(tuple(extra))
        for row in range(self._nav.count()):
            item = self._nav.item(row)
            if item is not None and item.data(Qt.ItemDataRole.UserRole) == name:
                self._nav.setCurrentRow(row)
                return
        widget = self._pages.get(name)
        if widget is not None:
            self._stack.setCurrentWidget(widget)
            self._refresh_page(name)()

    def _sync_optional_nav(self) -> None:
        extra: list[str] = []
        if self.services is not None:
            try:
                payload = self.services.telnet_dialogues(offset=0)
                if int(payload.get("total") or 0) > 0:
                    extra.append("Telnet")
            except (OSError, ValueError, KeyError):
                extra = []
        self._rebuild_nav(tuple(extra))

    def _show_help(self) -> None:
        QMessageBox.information(
            self, self._t("How to use Auto-Shark"), self._t(HELP_BODY)
        )

    def _toggle_overview_tech(self, checked: bool) -> None:
        self._overview_table.setVisible(checked)
        self._overview_json_label.setVisible(checked)
        self._overview_json.setVisible(checked)

    def _toggle_findings_tech(self, checked: bool) -> None:
        self._findings_detail.setVisible(checked)

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
        self._offsets = {name: 0 for name in STACK_PAGES + ("Timeline", "Manual queue")}
        self._sync_optional_nav()
        self._nav.setCurrentRow(0)
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

    def _project_needs_analysis(self) -> bool:
        """True when the open project has no indexed HTTP facts yet."""

        if self.services is None:
            return False
        try:
            payload = self.services.transactions(offset=0)
        except (OSError, ValueError, KeyError):
            return True
        return int(payload.get("total", 0)) == 0

    def _tshark_path(self) -> Optional[Path]:
        configured = self._settings.tshark_path
        if configured and Path(configured).is_file():
            return Path(configured)
        return resolve_tshark(None)

    def _tshark_too_old_text(self, version: tuple[int, int, int]) -> str:
        found = ".".join(str(part) for part in version)
        return self._t(TSHARK_TOO_OLD_TEMPLATE).format(found=found)

    def _tshark_block_reason(self, executable: Optional[Path]) -> Optional[str]:
        if executable is None:
            return self._t(
                "TShark was not found.\n"
                "Install Wireshark, then set the path in Edit > Settings…"
            )
        parsed = _tshark_version(executable)
        if tshark_too_old(parsed) and parsed is not None:
            return self._tshark_too_old_text(parsed)
        return None

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
        if path:
            self.open_capture_file(Path(path))

    def open_capture_file(self, capture: Path) -> None:
        """Open (and if needed, fully analyze) one capture in one interaction.

        The project directory is an implementation detail: it is created in
        the default machine-local root, and analysis starts automatically
        unless this project was already analyzed.
        """
        if capture.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
            QMessageBox.information(
                self,
                self._t("Auto-Shark"),
                self._t(
                    "This is not a capture file. Nested challenges (mp3/png/zip hiding "
                    "a pcap) need file carving first — extract the inner .pcap/.pcapng "
                    "(binwalk/foremost or a hex editor) and open that."
                ),
            )
            return
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
        self._settings.remember_capture(capture)
        with suppress(OSError):
            save_settings(self._settings)
        self.open_project(project_dir)
        tshark = self._tshark_path()
        blocked = self._tshark_block_reason(tshark)
        if blocked:
            QMessageBox.warning(self, self._t("Auto-Shark"), blocked)
            return
        if created or self._project_needs_analysis():
            keylog = find_tls_keylog(capture)
            if keylog is not None:
                self.statusBar().showMessage(
                    self._t("Auto-detected TLS keylog: ") + keylog.path.name, 10_000
                )
            self.run_analysis(tls_keylog=keylog)

    def _settings_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self._t("Auto-Shark settings"))
        dialog.resize(680, 560)
        root = QVBoxLayout(dialog)

        intro = QLabel(
            self._t(
                "Local CTF analysis only needs TShark (it comes with Wireshark 4). "
                "The remote Linux node is an optional extra for image/stego tools; "
                "ordinary traffic challenges do not use it."
            )
        )
        intro.setWordWrap(True)
        intro.setObjectName("settingsIntro")
        root.addWidget(intro)

        form_host = QWidget()
        form = QFormLayout(form_host)
        form.setContentsMargins(0, 0, 0, 0)
        self._settings_tshark = QLineEdit(self._settings.tshark_path or "")
        tshark_row = QHBoxLayout()
        tshark_row.addWidget(self._settings_tshark, 1)
        browse = QPushButton(self._t("Browse…"))
        probe = QPushButton(self._t("Check"))
        tshark_row.addWidget(browse)
        tshark_row.addWidget(probe)
        tshark_widget = QWidget()
        tshark_widget.setLayout(tshark_row)
        form.addRow(self._t("TShark executable"), tshark_widget)
        self._settings_output = QPlainTextEdit()
        self._settings_output.setReadOnly(True)
        self._settings_output.setMaximumHeight(140)
        self._settings_output.setPlaceholderText(
            self._t("Click Check after choosing tshark.exe. Need Wireshark 4.0 or newer.")
        )
        form.addRow(self._t("Check result"), self._settings_output)
        root.addWidget(form_host)

        advanced_toggle = QCheckBox(self._t("Show advanced: remote Linux node (optional)"))
        advanced_toggle.setObjectName("settingsAdvancedToggle")
        root.addWidget(advanced_toggle)
        advanced = QWidget()
        advanced.setObjectName("settingsAdvanced")
        advanced_form = QFormLayout(advanced)
        advanced_form.setContentsMargins(0, 0, 0, 0)
        advanced_help = QLabel(
            self._t(
                "Optional Linux helper for extra tools (zsteg, binwalk, …). "
                "Local traffic challenges do not need this. Protocol is SSH + SFTP only. "
                "Host is user@IP or user@domain, for example ctf@192.168.1.10. "
                "Port defaults to 22. Passwords are not supported — use an OpenSSH "
                "private key or ssh-agent. Probe tests the connection; saving only "
                "stores the settings. Main analysis still runs locally with TShark."
            )
        )
        advanced_help.setWordWrap(True)
        advanced_form.addRow(advanced_help)
        self._settings_remote_host = QLineEdit(self._settings.remote_host or "")
        self._settings_remote_host.setObjectName("settingsRemoteHost")
        self._settings_remote_host.setPlaceholderText("ctf@192.168.1.10")
        advanced_form.addRow(self._t("SSH user@host"), self._settings_remote_host)
        self._settings_remote_port = QSpinBox()
        self._settings_remote_port.setObjectName("settingsRemotePort")
        self._settings_remote_port.setRange(1, 65535)
        self._settings_remote_port.setValue(int(self._settings.remote_port or 22))
        advanced_form.addRow(self._t("SSH port"), self._settings_remote_port)
        identity_row = QHBoxLayout()
        self._settings_identity = QLineEdit(self._settings.ssh_identity or "")
        self._settings_identity.setObjectName("settingsSshIdentity")
        self._settings_identity.setPlaceholderText(
            self._t("Optional private key; empty uses ssh-agent / default keys")
        )
        identity_browse = QPushButton(self._t("Browse…"))
        identity_row.addWidget(self._settings_identity, 1)
        identity_row.addWidget(identity_browse)
        identity_widget = QWidget()
        identity_widget.setLayout(identity_row)
        advanced_form.addRow(self._t("SSH private key"), identity_widget)
        self._settings_ssh = QLineEdit(self._settings.ssh_path or "")
        self._settings_sftp = QLineEdit(self._settings.sftp_path or "")
        self._settings_ssh.setPlaceholderText(self._t("Leave empty to auto-detect OpenSSH"))
        self._settings_sftp.setPlaceholderText(self._t("Leave empty to auto-detect OpenSSH"))
        self._settings_remote_root = QLineEdit(self._settings.remote_root)
        self._settings_remote_paths = QLineEdit(DEFAULT_REMOTE_PROBE_PATHS)
        advanced_form.addRow(self._t("ssh executable"), self._settings_ssh)
        advanced_form.addRow(self._t("sftp executable"), self._settings_sftp)
        advanced_form.addRow(self._t("Remote working root"), self._settings_remote_root)
        advanced_form.addRow(self._t("Remote paths to probe"), self._settings_remote_paths)
        remote_probe = QPushButton(self._t("Probe remote node"))
        advanced_form.addRow("", remote_probe)
        show_advanced = bool(self._settings.remote_host)
        advanced.setVisible(show_advanced)
        advanced_toggle.setChecked(show_advanced)
        advanced_toggle.toggled.connect(advanced.setVisible)
        root.addWidget(advanced)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        root.addWidget(buttons)

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
            path = Path(text)
            parsed = _tshark_version(path) if path.is_file() else None
            try:
                result = probe_tshark(path)
            except (OSError, ValueError) as error:
                message = self._t("error: ") + str(error)
                if tshark_too_old(parsed) and parsed is not None:
                    message = self._tshark_too_old_text(parsed) + "\n" + message
                self._settings_output.setPlainText(message)
                return
            features = sum(1 for value in result.features.values() if value)
            usable = self._t("Usable: yes") if result.usable else self._t("Usable: no")
            lines = [
                result.version_line,
                usable,
                f"{self._t('Capabilities:')} {features}/{len(result.features)}",
            ]
            if tshark_too_old(parsed) and parsed is not None:
                lines.insert(1, self._tshark_too_old_text(parsed))
            elif result.errors:
                lines.append(self._t("error: ") + "; ".join(result.errors[:3]))
            self._settings_output.setPlainText("\n".join(lines))

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
            identity_text = self._settings_identity.text().strip()
            try:
                probe = probe_remote_node(
                    RemoteNodeConfig(
                        host=host,
                        ssh_executable=ssh,
                        sftp_executable=sftp,
                        remote_root=self._settings_remote_root.text().strip()
                        or ".auto-shark-jobs",
                        port=int(self._settings_remote_port.value()),
                        identity_file=Path(identity_text) if identity_text else None,
                    ),
                    paths,
                )
            except (OSError, ValueError) as error:
                self._settings_output.setPlainText(self._t("error: ") + str(error))
                return
            self._settings_output.setPlainText(
                json.dumps(probe, ensure_ascii=False, sort_keys=True, indent=2)
            )

        def pick_identity() -> None:
            path, _ = QFileDialog.getOpenFileName(dialog, self._t("Choose SSH private key"))
            if path:
                self._settings_identity.setText(path)

        browse.clicked.connect(pick_tshark)
        probe.clicked.connect(run_probe)
        identity_browse.clicked.connect(pick_identity)
        remote_probe.clicked.connect(run_remote_probe)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._settings = GuiSettings(
            tshark_path=self._settings_tshark.text().strip() or None,
            remote_host=self._settings_remote_host.text().strip() or None,
            remote_port=int(self._settings_remote_port.value()),
            ssh_identity=self._settings_identity.text().strip() or None,
            ssh_path=self._settings_ssh.text().strip() or None,
            sftp_path=self._settings_sftp.text().strip() or None,
            remote_root=self._settings_remote_root.text().strip() or ".auto-shark-jobs",
            recent_captures=self._settings.recent_captures,
            flag_format=self._settings.flag_format,
        )
        try:
            save_settings(self._settings)
        except OSError as error:
            QMessageBox.critical(
                self, self._t("Auto-Shark"), self._t("Cannot save settings: ") + str(error)
            )
            return
        blocked = self._tshark_block_reason(self._tshark_path())
        if blocked and self._tshark_path() is not None:
            QMessageBox.warning(self, self._t("Auto-Shark"), blocked)
        self._refresh_start_panel()

    def _new_project_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self._t("New project from capture"))
        form = QFormLayout(dialog)
        capture_edit = QLineEdit()
        capture_edit.setObjectName("capturePath")
        capture_button = QPushButton(self._t("Browse…"))
        project_edit = QLineEdit()
        project_edit.setObjectName("projectPath")
        project_button = QPushButton(self._t("Browse…"))
        tshark_edit = QLineEdit()
        tshark_edit.setObjectName("tsharkPath")
        tls_key_edit = QLineEdit()
        tls_key_edit.setObjectName("tlsRsaKeyPath")
        tls_key_button = QPushButton(self._t("Browse…"))
        tls_keylog_edit = QLineEdit()
        tls_keylog_edit.setObjectName("tlsKeylogPath")
        tls_keylog_button = QPushButton(self._t("Browse…"))
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
        tls_key_row = QHBoxLayout()
        tls_key_row.addWidget(tls_key_edit, 1)
        tls_key_row.addWidget(tls_key_button)
        tls_key_widget = QWidget()
        tls_key_widget.setLayout(tls_key_row)
        tls_keylog_row = QHBoxLayout()
        tls_keylog_row.addWidget(tls_keylog_edit, 1)
        tls_keylog_row.addWidget(tls_keylog_button)
        tls_keylog_widget = QWidget()
        tls_keylog_widget.setLayout(tls_keylog_row)
        form.addRow(self._t("Capture file"), capture_widget)
        form.addRow(self._t("Project directory"), project_widget)
        form.addRow(self._t("TShark executable"), tshark_edit)
        form.addRow(self._t("Legacy TLS RSA private key (optional)"), tls_key_widget)
        form.addRow(self._t("TLS keylog file (optional)"), tls_keylog_widget)
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

        def pick_tls_keylog() -> None:
            path, _ = QFileDialog.getOpenFileName(
                dialog,
                self._t("Choose TLS keylog file"),
                "",
                "Keylog files (*.log *.txt);;All files (*)",
            )
            if path:
                tls_keylog_edit.setText(path)

        def pick_tls_key() -> None:
            path, _ = QFileDialog.getOpenFileName(
                dialog,
                self._t("Choose TLS RSA private key"),
                "",
                "Key files (*.pem *.key);;All files (*)",
            )
            if path:
                tls_key_edit.setText(path)

        capture_button.clicked.connect(pick_capture)
        project_button.clicked.connect(pick_project)
        tls_key_button.clicked.connect(pick_tls_key)
        tls_keylog_button.clicked.connect(pick_tls_keylog)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        capture_text = capture_edit.text().strip()
        project_text = project_edit.text().strip()
        tshark_text = tshark_edit.text().strip()
        tls_key_text = tls_key_edit.text().strip()
        tls_keylog_text = tls_keylog_edit.text().strip()
        if not capture_text or not project_text:
            QMessageBox.warning(
                self, self._t("Auto-Shark"), self._t("Capture and project paths are required.")
            )
            return
        tls_rsa_key = None
        tls_keylog = None
        if tls_keylog_text:
            try:
                tls_keylog = load_tls_keylog(Path(tls_keylog_text))
            except (OSError, ValueError) as error:
                QMessageBox.critical(
                    self,
                    self._t("Auto-Shark"),
                    self._t("Cannot load TLS keylog file: ") + str(error),
                )
                return
        if tls_key_text:
            try:
                tls_rsa_key = load_tls_rsa_key(Path(tls_key_text))
            except (OSError, ValueError) as error:
                QMessageBox.critical(
                    self,
                    self._t("Auto-Shark"),
                    self._t("Cannot load TLS RSA private key: ") + str(error),
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
        blocked = self._tshark_block_reason(tshark)
        if blocked:
            QMessageBox.warning(self, self._t("Auto-Shark"), blocked)
            return
        self.run_analysis(
            capture=Path(capture_text),
            tshark=tshark,
            tls_rsa_key=tls_rsa_key,
            tls_keylog=tls_keylog,
        )

    # ------------------------------------------------------------- analysis

    def run_analysis(
        self,
        *,
        capture: Optional[Path] = None,
        tshark: Optional[Path] = None,
        tls_rsa_key: Optional[TlsRsaKey] = None,
        tls_keylog=None,
    ) -> None:
        if self.services is None:
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Open a project first."))
            return
        executable = tshark or self._tshark_path()
        blocked = self._tshark_block_reason(executable)
        if blocked:
            QMessageBox.warning(self, self._t("Auto-Shark"), blocked)
            return
        stages = self.services.analysis_stages(
            executable,
            capture=capture,
            tls_rsa_key=tls_rsa_key,
            tls_keylog=tls_keylog,
        )
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
        failures: list[tuple[str, str]] = []
        skipped: list[str] = []

        def on_started(title: str) -> None:
            dialog.setLabelText(self._t("Running: ") + title)

        def on_finished_stage(key: str, summary: str) -> None:
            dialog.setValue(dialog.value() + 1)
            # Guarded stages report degradation as a status payload instead
            # of raising; surface those in the end-of-run summary so a
            # silently skipped analyzer can never look like a clean run.
            try:
                payload = json.loads(summary)
            except (TypeError, ValueError):
                return
            status = payload.get("status") if isinstance(payload, dict) else None
            if status in ("failed", "unavailable"):
                reason = str(payload.get("reason") or status)
                skipped.append(f"{key}: {reason[:200]}")

        def on_failed(key: str, error: str) -> None:
            # Collected and reported once at the end; one dialog per stage
            # turns a single degraded analyzer into a wall of error boxes.
            failures.append((key, error))
            dialog.setValue(dialog.value() + 1)

        def on_run_done(completed: bool, message: str) -> None:
            dialog.reset()
            self._worker = None
            self._cancel_action.setEnabled(False)
            all_issues = [*failures, *skipped]
            if all_issues:
                lines = "\n".join(f"- {item}" for item in all_issues)
                QMessageBox.warning(
                    self,
                    self._t("Auto-Shark"),
                    self._t("Analysis finished; the following stages were skipped:\n")
                    + lines
                    + "\n"
                    + self._t("Skipped stages do not block the remaining results."),
                )
            else:
                QMessageBox.information(
                    self, self._t("Auto-Shark"), self._t("Analysis finished.") + "\n" + message
                )
            self._sync_optional_nav()
            self._nav.setCurrentRow(0)
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
        for key in TASK_STATES:
            combo.addItem(self._t(key), key)
        current = str(task.get("state", "open"))
        index = combo.findData(current)
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
            self.services.update_manual_task_state(
                task_id, str(combo.currentData() or combo.currentText())
            )
        except (OSError, ValueError) as error:
            QMessageBox.critical(self, self._t("Auto-Shark"), str(error))
            return
        self._refresh_queue()

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
        _fit_table_columns(table)

    def _player_kind(self, kind: str) -> str:
        if not kind:
            return ""
        translated = self._t(kind)
        if translated != kind:
            return translated
        return kind.replace("_", " ").replace("-", " ")

    def _player_detector(self, detector: str) -> str:
        lower = detector.lower()
        if "sql" in lower:
            return self._t("SQL injection")
        if "webshell" in lower or "shell" in lower:
            return self._t("WebShell")
        if "flag" in lower:
            return self._t("known-flag")
        if "usb" in lower:
            return self._t("USB keyboard")
        if "password-protected" in lower:
            return self._t("Password-protected archive")
        if "pcap-header" in lower:
            return self._t("Repaired zeroed PCAP global header")
        if "nested-container" in lower:
            return self._t("Not a packet capture; nested files inside")
        if "http-status" in lower or "contradiction" in lower:
            return self._t("HTTP status/body mismatch")
        return self._t(detector.split(".")[-1].replace("_", " ") or detector)

    def _finding_look_at(self, item: dict) -> str:
        description = str(item.get("description") or "")
        typed_marker = "Typed string:"
        if typed_marker in description:
            typed = description.split(typed_marker, 1)[1].strip().rstrip(".")
            return f"{self._t('Typed keys:')} {typed}"
        marker = "Key-down sequence preview:"
        if marker in description:
            keys = description.split(marker, 1)[1].strip().rstrip(".")
            if typed_marker in keys:
                keys = keys.split(typed_marker, 1)[0].strip().rstrip(".")
            joined = keys.replace(", ", "")
            return f"{self._t('Typed keys:')} {joined}"
        title = str(item.get("title") or description)
        return self._t(title) or title

    def _evidence_sentence(self, item: dict) -> str:
        links = list(item.get("evidence") or [])
        if not links:
            return str(item.get("description") or item.get("title") or "")
        link = links[0]
        start = link.get("frame_start")
        end = link.get("frame_end")
        frame = "" if start in (None, "") else f"{self._t('Frame')} {start}"
        if end not in (None, "", start) and frame:
            frame = f"{frame}-{end}"
        bits = [part for part in (frame, link.get("source_kind"), link.get("field_name")) if part]
        extra = ""
        total = int(item.get("evidence_total") or len(links))
        if total > 1:
            extra = f" · {total}"
        return " · ".join(str(bit) for bit in bits) + extra

    def _show_findings_detail(self) -> None:
        table = self.sender()
        if table is self._findings_table:
            self._show_selected_json("Findings", self._findings_table, self._finding_items)
        else:
            self._show_selected_json("Findings", self._candidates_table, self._candidate_items)

    def _copy_findings_flag(self, item) -> None:
        row = item.row()
        if 0 <= row < len(self._candidate_items):
            value = str(
                self._candidate_items[row].get("normalized_value")
                or self._candidate_items[row].get("raw_value")
                or item.text()
            )
            from PySide6.QtWidgets import QApplication

            QApplication.clipboard().setText(value)
            self.statusBar().showMessage(self._t("Copied: ") + value, 5000)

    # -------------------------------------------------------- content viewers

    def _view_http_body(self, role: str) -> None:
        row = self._http_table.currentRow()
        if self.services is None or not 0 <= row < len(self._http_items):
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Select a row first."))
            return
        item = self._http_items[row]
        request = item.get("request") or {}
        response = item.get("response") or {}
        message_id = (
            request.get("message_id") if role == "request" else response.get("message_id")
        )
        path = self.services.http_body_path(str(message_id or ""))
        title = f"{request.get('method', '')} {request.get('uri', '')} [{role}]"
        if path is None or not path.is_file():
            QMessageBox.information(
                self,
                self._t("Auto-Shark"),
                self._t("No stored body for this message (absent or not extracted)."),
            )
            return
        from .hexview import read_bounded, view_bytes

        view_bytes(self, title, read_bounded(path), f"{role} body · {path.stat().st_size} bytes")

    def _view_selected_stream(self) -> None:
        row = self._streams_table.currentRow()
        if self.services is None or not 0 <= row < len(self._streams_items):
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Select a row first."))
            return
        item = self._streams_items[row]
        evidence = item.get("evidence") or {}
        sha256 = evidence.get("blob_sha256")
        path = self.services.blob_path(str(sha256)) if sha256 else None
        if path is None or not path.is_file():
            QMessageBox.information(
                self,
                self._t("Auto-Shark"),
                self._t("No stored stream content (run tcp-text/telnet stages first)."),
            )
            return
        from .hexview import read_bounded, view_bytes

        title = f"TCP stream {item.get('stream_index')} [{item.get('direction')}]"
        note = (
            f"frames {evidence.get('frame_start')}-{evidence.get('frame_end')} · "
            f"{evidence.get('byte_length')} bytes"
        )
        view_bytes(self, title, read_bounded(path), note)

    def _view_selected_telnet(self) -> None:
        row = self._telnet_table.currentRow()
        if self.services is None or not 0 <= row < len(self._telnet_items):
            QMessageBox.information(self, self._t("Auto-Shark"), self._t("Select a row first."))
            return
        item = self._telnet_items[row]
        # Prefer the raw reconstructed direction streams (full bytes); fall
        # back to the per-record bounded previews carried on the item.
        from .hexview import read_bounded, view_bytes, view_text

        directions = item.get("directions") or {}
        for name in ("client", "server"):
            direction = directions.get(name) or {}
            sha256 = direction.get("blob_sha256")
            if not sha256:
                continue
            path = self.services.blob_path(str(sha256))
            if path is not None and path.is_file():
                view_bytes(
                    self,
                    f"Telnet stream {item.get('stream_index')} [{name}]",
                    read_bounded(path),
                    f"{direction.get('byte_length')} bytes · {direction.get('status')}",
                )
                return
        records = []
        for record in list(item.get("records") or []):
            preview = record.get("preview")
            if preview:
                role = record.get("direction_role") or "?"
                records.append(f"[{role}] {preview}")
        if not records:
            QMessageBox.information(
                self,
                self._t("Auto-Shark"),
                self._t("No Telnet preview stored (run the telnet stage first)."),
            )
            return
        view_text(
            self,
            f"Telnet {item.get('dialogue_id')}",
            "\n".join(records),
            f"{len(records)} records",
        )

    # ------------------------------------------------------------- refreshers

    def _register_refreshers(self) -> None:
        self._register_refresher("Overview", self._refresh_overview)
        self._register_refresher("Files", self._refresh_files)
        self._register_refresher("Frames", self._refresh_frames)
        self._register_refresher("Statistics", self._refresh_statistics)
        self._register_refresher("HTTP", self._refresh_http)
        self._register_refresher("Streams", self._refresh_streams)
        self._register_refresher("Telnet", self._refresh_telnet)
        self._register_refresher("Findings", self._refresh_findings)
        self._register_refresher("Timeline", self._refresh_timeline)
        self._register_refresher("Manual queue", self._refresh_queue)
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
            self._fill_table(self._queue_table, [])
            self._overview_stack.setCurrentIndex(0)
            self._refresh_start_panel()
            return
        self._overview_stack.setCurrentIndex(1)
        try:
            payload = self.services.overview()
        except (OSError, ValueError, KeyError) as error:
            self._banners["Overview"].setText(self._t("error: ") + str(error))
            return
        capture = payload.get("capture", {})
        overview = payload.get("overview", {})
        self._populate_wizard()
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
        self._refresh_queue()

    def _refresh_files(self) -> None:
        if not self._require_services("Files"):
            self._fill_table(self._files_table, [])
            return
        try:
            payload = self.services.files()
        except (OSError, ValueError, KeyError) as error:
            self._banners["Files"].setText(self._t("error: ") + str(error))
            return
        items = list(payload.get("items") or [])
        self._files_items = items
        self._fill_table(
            self._files_table,
            [
                (
                    item.get("name"),
                    item.get("media_type"),
                    item.get("magic"),
                    item.get("byte_length"),
                    str(item.get("sha256"))[:16],
                )
                for item in items
            ],
        )
        if items:
            self._banners["Files"].setText(
                self._t("Showing") + f" {len(items)} " + self._t("of") + f" {payload.get('total')}"
            )
        else:
            self._banners["Files"].setText(
                self._t(
                    "No extracted files yet. They appear after the scan stage "
                    "(run the full analysis first)."
                )
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
            self._refresh_timeline()
            return
        if not payload.get("candidates") and not payload.get("findings"):
            # No detector fired on this challenge: point the player at the
            # generic traffic view instead of an intimidating empty table.
            self._banners["Findings"].setText(
                self._t(
                    "No automatic hits on this capture. Open the Frames page to browse "
                    "every packet and filter manually (e.g. http, dns, usb, "
                    'tcp contains "flag").'
                )
            )
            self._candidate_items = []
            self._finding_items = []
            self._fill_table(self._candidates_table, [])
            self._fill_table(self._findings_table, [])
            self._refresh_timeline()
            return
        candidates = list(payload.get("candidates", []))
        findings = list(payload.get("findings", []))
        self._candidate_items = candidates
        self._finding_items = findings
        self._fill_table(
            self._candidates_table,
            [
                (
                    item.get("normalized_value") or item.get("raw_value"),
                    self._player_kind(str(item.get("kind") or "")),
                    self._evidence_sentence(item),
                    item.get("confidence"),
                )
                for item in candidates
            ],
        )
        self._fill_table(
            self._findings_table,
            [
                (
                    self._player_detector(str(item.get("detector") or "")),
                    self._finding_look_at(item),
                    self._t(str(item.get("recommended_action") or ""))
                    or self._evidence_sentence(item),
                )
                for item in findings
            ],
        )
        self._set_banner(
            "Findings",
            offset=offset,
            count=len(candidates),
            total=payload.get("candidate_total", len(candidates)),
            extra=f"; {self._t('Exam points:')} {len(findings)} "
            f"{self._t('of')} {payload.get('finding_total', len(findings))}",
        )
        self._refresh_timeline()

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
                    self._player_kind(str(item.get("event_kind") or "")),
                    item.get("target"),
                    item.get("status"),
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
        state = self._queue_state.currentData() or self._queue_state.currentText()
        payload = self._paged_payload(
            "Manual queue",
            lambda: self.services.manual_queue(
                state=None if state == "all" else str(state), offset=offset
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

    def _refresh_export(self) -> None:
        if self._require_services("Export"):
            self._banners["Export"].setText(self._t("Ready to export a bounded offline bundle."))
