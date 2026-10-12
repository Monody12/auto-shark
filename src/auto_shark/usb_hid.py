"""Bounded USB HID endpoint triage and multi-device correlation hints."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from uuid import uuid4

from .core.ids import candidate_id, stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import probe_tshark
from .project import inspect_project
from .search import FLAG_PATTERN, _plausible_flag
from .storage import Database

USB_HID_FIELDS = (
    "frame.number",
    "usb.src",
    "usb.dst",
    "usb.endpoint_address",
    "usb.capdata",
    "usbhid.data",
)
USB_HID_REQUIRED_FIELDS = frozenset(USB_HID_FIELDS)
DETECTOR = "usb-hid-triage"
DETECTOR_VERSION = "auto-shark.usb-hid-triage/v1"

_KEY_NAMES = {
    **{code: chr(ord("a") + code - 4) for code in range(4, 30)},
    **{code: str((code - 29) % 10) for code in range(30, 40)},
    40: "enter",
    41: "esc",
    42: "backspace",
    43: "tab",
    44: "space",
    45: "-",
    46: "=",
    47: "[",
    48: "]",
    49: "\\",
    51: ";",
    52: "'",
    53: "`",
    54: ",",
    55: ".",
    56: "/",
}
_SHIFT_NAMES = {
    "1": "!",
    "2": "@",
    "3": "#",
    "4": "$",
    "5": "%",
    "6": "^",
    "7": "&",
    "8": "*",
    "9": "(",
    "0": ")",
    "-": "_",
    "=": "+",
    "[": "{",
    "]": "}",
    "\\": "|",
    ";": ":",
    "'": '"',
    "`": "~",
    ",": "<",
    ".": ">",
    "/": "?",
}
_SHIFT_MODIFIER = 0x22  # left or right Shift in the boot-keyboard modifier byte


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class UsbReport:
    frame: int
    source: str
    destination: str
    endpoint: str
    data: bytes


@dataclass(frozen=True)
class UsbEndpointResult:
    source: str
    endpoint: str
    first_frame: int
    last_frame: int
    reports: int
    report_lengths: dict[int, int]
    classification: str
    key_events: tuple[str, ...]
    coordinate_range: tuple[int, int, int, int] | None
    pressure_range: tuple[int, int] | None
    evidence_id: str


@dataclass(frozen=True)
class UsbHidSummary:
    schema_version: str
    status: str
    reports_seen: int
    malformed_rows: int
    skipped_report_limit: int
    skipped_endpoint_limit: int
    endpoints: tuple[UsbEndpointResult, ...]
    correlated_input_devices: bool
    hints: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def parse_usb_hid_line(line: bytes) -> UsbReport:
    rows = list(csv.reader(StringIO(line.decode("utf-8", errors="strict")), delimiter="\t"))
    if len(rows) != 1 or len(rows[0]) != len(USB_HID_FIELDS):
        raise ValueError("invalid USB HID field row")
    values = dict(zip(USB_HID_FIELDS, rows[0]))
    data_value = values["usb.capdata"] or values.get("usbhid.data") or ""
    if not values["frame.number"] or not values["usb.src"] or not data_value:
        raise ValueError("USB HID row lacks frame, source, or capture data")
    raw = data_value.replace(":", "")
    return UsbReport(
        int(values["frame.number"]),
        values["usb.src"],
        values["usb.dst"],
        values["usb.endpoint_address"],
        bytes.fromhex(raw),
    )


def tshark_usb_hid_arguments(executable: Path, capture: Path) -> list[str]:
    arguments = [
        str(executable),
        "-r",
        str(capture),
        "-Y",
        "usb.capdata || usbhid.data",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in USB_HID_FIELDS:
        arguments.extend(("-e", field))
    return arguments


def _key_glyph(code: int, shift: bool) -> str:
    base = _KEY_NAMES.get(code)
    if base is None:
        return f"key-0x{code:02x}"
    if shift and len(base) == 1 and "a" <= base <= "z":
        return base.upper()
    if shift:
        return _SHIFT_NAMES.get(base, base)
    return base


def _keyboard_events(reports: list[UsbReport]) -> tuple[str, ...]:
    events: list[str] = []
    previous: set[int] = set()
    for report in reports:
        if len(report.data) != 8:
            continue
        shift = bool(report.data[0] & _SHIFT_MODIFIER)
        pressed = {code for code in report.data[2:] if code}
        for code in sorted(pressed - previous):
            events.append(_key_glyph(code, shift))
        previous = pressed
    return tuple(events[:256])


def typed_string(events: tuple[str, ...]) -> str:
    """Collapse key-down names into the text a keyboard would have typed."""

    chars: list[str] = []
    for event in events:
        if event == "backspace":
            if chars:
                chars.pop()
            continue
        if event == "space":
            chars.append(" ")
            continue
        if event in {"enter", "esc", "tab"} or event.startswith("key-"):
            continue
        if len(event) == 1:
            chars.append(event)
    return "".join(chars)


def _is_keyboard_like(reports: list[UsbReport]) -> bool:
    eight = [report for report in reports if len(report.data) == 8]
    if len(eight) < 4 or len(eight) / len(reports) < 0.8:
        return False
    reserved_zero = sum(report.data[1] == 0 for report in eight) / len(eight)
    releases = sum(not any(report.data[2:]) for report in eight)
    codes = [code for report in eight for code in report.data[2:] if code]
    known_ratio = sum(code in _KEY_NAMES for code in codes) / max(len(codes), 1)
    return reserved_zero >= 0.9 and releases > 0 and known_ratio >= 0.8


def _pointer_ranges(
    reports: list[UsbReport],
) -> tuple[tuple[int, int, int, int], tuple[int, int]] | None:
    decoded = []
    for report in reports:
        if len(report.data) != 10 or report.data[0] != 0x02:
            continue
        x = int.from_bytes(report.data[2:4], "little")
        y = int.from_bytes(report.data[4:6], "little")
        if x and y:
            decoded.append((x, y, report.data[7]))
    if len(decoded) < 20:
        return None
    xs = [item[0] for item in decoded]
    ys = [item[1] for item in decoded]
    pressures = [item[2] for item in decoded]
    if max(xs) - min(xs) < 100 or max(ys) - min(ys) < 100:
        return None
    return (min(xs), max(xs), min(ys), max(ys)), (min(pressures), max(pressures))


def _persist_typed_flag(connection, evidence_db_id: int, typed: str) -> None:
    encoded = typed.encode("utf-8")
    for match in FLAG_PATTERN.finditer(encoded):
        value = match.group()
        if not _plausible_flag(value):
            continue
        text = value.decode("utf-8", errors="replace")
        public_id = candidate_id("known-flag", text.strip())
        connection.execute(
            "INSERT INTO candidate(candidate_id,kind,raw_value,normalized_value,"
            "confidence,rank_score,created_at) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(candidate_id) DO UPDATE SET "
            "confidence=max(candidate.confidence,excluded.confidence),"
            "rank_score=max(candidate.rank_score,excluded.rank_score)",
            (public_id, "known-flag", text, text.strip(), 0.95, 96.0, _now()),
        )
        candidate_db_id = int(
            connection.execute(
                "SELECT id FROM candidate WHERE candidate_id=?", (public_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO candidate_evidence(candidate_id,evidence_id,role) "
            "VALUES(?,?,?)",
            (candidate_db_id, evidence_db_id, "usb-typed-keys"),
        )


def _persist_endpoint(
    database: Database,
    capture_id: int,
    capture_sha256: str,
    reports: list[UsbReport],
    project_root=None,
) -> UsbEndpointResult:
    first = min(item.frame for item in reports)
    last = max(item.frame for item in reports)
    lengths = dict(sorted(Counter(len(item.data) for item in reports).items()))
    keyboard_like = _is_keyboard_like(reports)
    keys = _keyboard_events(reports) if keyboard_like else ()
    typed = typed_string(keys) if keys else ""
    pointer = _pointer_ranges(reports)
    if keyboard_like and keys:
        classification = "boot-keyboard-like"
    elif pointer is not None:
        classification = "absolute-pointer-like"
    else:
        classification = "unclassified"
    coordinate_range, pressure_range = pointer if pointer is not None else (None, None)
    identity = {
        "capture_sha256": capture_sha256,
        "source": reports[0].source,
        "endpoint": reports[0].endpoint,
    }
    evidence_public_id = stable_id("usb-hid-endpoint-evidence", identity)
    locator = {
        **identity,
        "classification": classification,
        "coordinate_range": coordinate_range,
        "key_events": keys,
        "pressure_range": pressure_range,
        "report_lengths": lengths,
        "reports": len(reports),
        "samples": [item.data.hex() for item in reports[:8]],
        "typed_string": typed,
    }
    text = typed or (", ".join(keys) if keys else classification)
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "direction,byte_offset,byte_length,field_name,text_value,locator_json) "
            "VALUES(?,?,'usb-hid-report-series',?,?,?,0,?,'usb.capdata',?,?) "
            "ON CONFLICT(evidence_id) DO UPDATE SET frame_start=excluded.frame_start,"
            "frame_end=excluded.frame_end,byte_length=excluded.byte_length,"
            "text_value=excluded.text_value,locator_json=excluded.locator_json",
            (
                evidence_public_id,
                capture_id,
                first,
                last,
                f"{reports[0].source}->{reports[0].destination}",
                sum(len(item.data) for item in reports),
                text,
                json.dumps(locator, ensure_ascii=False, sort_keys=True),
            ),
        )
        evidence_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?", (evidence_public_id,)
            ).fetchone()[0]
        )
        keystroke_evidence_db_id = evidence_db_id
        if typed and len(typed) >= 4 and project_root is not None:
            # Typed text is evidence, not only a flag-shaped subset: passwords
            # and commands typed on a captured keyboard (e.g. BugKu
            # whereiskey) must surface even without a flag{} wrapper.
            from .storage import BlobStore

            store = BlobStore(project_root / "blobs")
            blob = store.put_bytes(typed.encode("utf-8"))
            relative_path = blob.path.relative_to(project_root).as_posix()
            keystroke_public_id = stable_id(
                "usb-keystrokes-evidence", dict(identity, typed=typed)
            )
            connection.execute(
                "INSERT INTO blob(sha256,byte_length,relative_path,media_type,"
                "magic_description,complete,created_at) VALUES (?,?,?,?,?,1,?) "
                "ON CONFLICT(sha256) DO NOTHING",
                (blob.sha256, len(typed), relative_path, None,
                 "reconstructed USB keyboard input", _now()),
            )
            keystroke_blob_id = int(
                connection.execute(
                    "SELECT id FROM blob WHERE sha256=?", (blob.sha256,)
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,"
                "frame_end,direction,byte_offset,byte_length,field_name,text_value,"
                "blob_id,locator_json) VALUES(?,?,'usb-keystrokes',?,?,NULL,0,?,NULL,?,?,?) "
                "ON CONFLICT(evidence_id) DO UPDATE SET text_value=excluded.text_value,"
                "blob_id=excluded.blob_id,locator_json=excluded.locator_json",
                (keystroke_public_id, capture_id, first, last, len(typed), typed,
                 keystroke_blob_id,
                 json.dumps({"typed_string": typed, "source": reports[0].source},
                            ensure_ascii=False, sort_keys=True)),
            )
            keystroke_evidence_db_id = int(
                connection.execute(
                    "SELECT id FROM evidence WHERE evidence_id=?",
                    (keystroke_public_id,),
                ).fetchone()[0]
            )
            typed_public_id = candidate_id("usb-keystrokes", typed.strip())
            connection.execute(
                "INSERT INTO candidate(candidate_id,kind,raw_value,normalized_value,"
                "confidence,rank_score,created_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(candidate_id) DO UPDATE SET "
                "confidence=max(candidate.confidence,excluded.confidence),"
                "rank_score=max(candidate.rank_score,excluded.rank_score)",
                (typed_public_id, "usb-keystrokes", typed, typed.strip(), 0.8, 78.0, _now()),
            )
            typed_candidate_db_id = int(
                connection.execute(
                    "SELECT id FROM candidate WHERE candidate_id=?", (typed_public_id,)
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT OR IGNORE INTO candidate_evidence(candidate_id,evidence_id,role) "
                "VALUES(?,?,?)",
                (typed_candidate_db_id, keystroke_evidence_db_id, "usb-typed-keys"),
            )
        if classification != "unclassified":
            finding_public_id = stable_id("usb-hid-endpoint-finding", identity)
            if classification == "boot-keyboard-like":
                typed_clause = f" Typed string: {typed}." if typed else ""
                description = (
                    f"USB source {reports[0].source} has {len(reports)} keyboard-like "
                    f"8-byte reports. Key-down sequence preview: {', '.join(keys[:80])}."
                    f"{typed_clause}"
                )
                action = (
                    "Review key-down/release edges and correlate held keys with other USB devices."
                )
            else:
                description = (
                    f"USB source {reports[0].source} has {len(reports)} 10-byte reports "
                    f"with changing little-endian coordinate fields {coordinate_range} and "
                    f"pressure-like byte range {pressure_range}."
                )
                action = (
                    "Plot coordinates by frame and test pressure thresholds for pen-down strokes."
                )
            connection.execute(
                "INSERT INTO finding(finding_id,detector,detector_version,title,description,"
                "severity,confidence,recommended_action,created_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(finding_id) DO UPDATE SET description=excluded.description,"
                "confidence=excluded.confidence,recommended_action=excluded.recommended_action",
                (
                    finding_public_id,
                    DETECTOR,
                    DETECTOR_VERSION,
                    f"USB HID {classification} endpoint",
                    description,
                    "medium",
                    0.88 if classification == "boot-keyboard-like" else 0.8,
                    action,
                    _now(),
                ),
            )
            finding_db_id = int(
                connection.execute(
                    "SELECT id FROM finding WHERE finding_id=?", (finding_public_id,)
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT OR IGNORE INTO finding_evidence(finding_id,evidence_id,role) "
                "VALUES(?,?,?)",
                (finding_db_id, evidence_db_id, "usb-report-series"),
            )
            if typed:
                _persist_typed_flag(connection, keystroke_evidence_db_id, typed)
    return UsbEndpointResult(
        reports[0].source,
        reports[0].endpoint,
        first,
        last,
        len(reports),
        lengths,
        classification,
        keys,
        coordinate_range,
        pressure_range,
        evidence_public_id,
    )


def triage_usb_hid(
    project_path: Path,
    tshark: Path,
    *,
    max_reports: int = 100_000,
    max_endpoints: int = 256,
) -> UsbHidSummary:
    if min(max_reports, max_endpoints) <= 0:
        raise ValueError("USB HID limits must be positive")
    project = inspect_project(project_path)
    capabilities = probe_tshark(tshark)
    missing = USB_HID_REQUIRED_FIELDS - set(capabilities.fields)
    if "usb.capdata" in missing and "usbhid.data" in capabilities.fields:
        # USBPcap flows dissected as usbhid expose usbhid.data instead of
        # usb.capdata (e.g. BugKu whereiskey); either carries the reports.
        missing.discard("usb.capdata")
        missing = frozenset(missing)
    if not capabilities.usable or missing:
        return UsbHidSummary(
            DETECTOR_VERSION,
            "unavailable",
            0,
            0,
            0,
            0,
            (),
            False,
            ("TShark does not expose the required USB capture-data fields.",),
        )
    database = Database(project.root / "project.sqlite")
    database.initialize()
    argv = tshark_usb_hid_arguments(tshark, project.capture_path)
    run_id = uuid4().hex
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,tool_version,argv_json,capability_json,"
            "started_at,status) VALUES(?,?,?,?,?,?,'running')",
            (
                run_id,
                "tshark-usb-hid-triage",
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_provenance_json(),
                _now(),
            ),
        )
    groups: dict[tuple[str, str], list[UsbReport]] = {}
    reports_seen = malformed = 0
    skipped_report_limit = skipped_endpoint_limit = 0

    def on_line(line: bytes) -> None:
        nonlocal reports_seen, malformed, skipped_report_limit, skipped_endpoint_limit
        reports_seen += 1
        if reports_seen > max_reports:
            skipped_report_limit += 1
            return
        try:
            report = parse_usb_hid_line(line)
        except (UnicodeError, ValueError, TypeError):
            malformed += 1
            return
        key = (report.source, report.endpoint)
        if key not in groups and len(groups) >= max_endpoints:
            skipped_endpoint_limit += 1
            return
        groups.setdefault(key, []).append(report)

    try:
        process = run_streaming_lines(
            argv,
            on_line,
            timeout_seconds=120,
            max_line_bytes=256 * 1024,
            stderr_limit=256 * 1024,
        )
    except BaseException as error:
        with database.connect() as connection:
            connection.execute(
                "UPDATE tool_run SET ended_at=?,status='failed',stderr_text=? WHERE run_id=?",
                (_now(), f"{type(error).__name__}: {error}"[:4096], run_id),
            )
        raise
    failed = process.timed_out or process.output_limit_exceeded or process.returncode != 0
    tool_status = (
        "failed"
        if failed
        else "budget-limited"
        if skipped_report_limit or skipped_endpoint_limit
        else "completed"
    )
    with database.connect() as connection:
        connection.execute(
            "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
            "stderr_truncated=? WHERE run_id=?",
            (
                _now(),
                tool_status,
                process.returncode,
                process.stderr.decode("utf-8", errors="replace"),
                int(process.stderr_truncated),
                run_id,
            ),
        )
    if failed:
        return UsbHidSummary(
            DETECTOR_VERSION,
            "error",
            reports_seen,
            malformed,
            skipped_report_limit,
            skipped_endpoint_limit,
            (),
            False,
            (process.stderr.decode("utf-8", errors="replace")[-1000:],),
        )
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
    endpoints = tuple(
        _persist_endpoint(
            database, capture_id, project.capture_sha256, reports, project.root
        )
        for reports in sorted(groups.values(), key=lambda items: min(item.frame for item in items))
    )
    keyboard = [item for item in endpoints if item.classification == "boot-keyboard-like"]
    pointer = [item for item in endpoints if item.classification == "absolute-pointer-like"]
    correlated = bool(keyboard and pointer)
    hints = []
    if correlated:
        held = sorted({key for item in keyboard for key in item.key_events})
        hints.append(
            "Keyboard-like and absolute-pointer-like USB endpoints coexist. Correlate key hold "
            f"windows ({', '.join(held[:20])}) with pointer reports by frame or timestamp."
        )
    elif keyboard:
        hints.append("Decode USB keyboard key-down edges; do not emit held keys repeatedly.")
    elif pointer:
        hints.append("Plot absolute coordinates and use pressure-like byte changes as pen state.")
    else:
        hints.append("No standard keyboard-like or supported absolute-pointer pattern was found.")
    return UsbHidSummary(
        DETECTOR_VERSION,
        "budget-limited" if skipped_report_limit or skipped_endpoint_limit else "completed",
        reports_seen,
        malformed,
        skipped_report_limit,
        skipped_endpoint_limit,
        endpoints,
        correlated,
        tuple(hints),
    )
