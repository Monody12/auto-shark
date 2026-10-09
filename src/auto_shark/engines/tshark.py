"""TShark discovery and structured capability probing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .process import ProcessResult, run_bounded

TLS_RSA_KEY_MAX_BYTES = 1024 * 1024

CORE_FIELDS = frozenset(
    {
        "frame.number",
        "frame.time_epoch",
        "tcp.stream",
        "tcp.srcport",
        "tcp.dstport",
    }
)

FEATURE_FIELDS = {
    "http": frozenset(
        {
            "http.request.method",
            "http.request.uri",
            "http.response.code",
            "http.response_in",
            "http.request_in",
            "http.file_data",
        }
    ),
    "tcp_reassembly": frozenset({"tcp.payload", "tcp.segment_data", "tcp.reassembled.data"}),
    "tcp_stream": frozenset(
        {
            "frame.number",
            "frame.time_epoch",
            "frame.cap_len",
            "frame.len",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.stream",
            "tcp.seq",
            "tcp.seq_raw",
            "tcp.len",
            "tcp.payload",
            "tcp.flags.syn",
            "tcp.flags.ack",
            "tcp.flags.fin",
            "tcp.flags.reset",
            "tcp.analysis.retransmission",
            "tcp.analysis.spurious_retransmission",
            "tcp.analysis.out_of_order",
            "tcp.analysis.lost_segment",
        }
    ),
    "tcp_urgent": frozenset({"tcp.flags.urg", "tcp.urgent_pointer"}),
    "usb_hid": frozenset(
        {"usb.src", "usb.dst", "usb.endpoint_address", "usb.capdata"}
    ),
    "ftp": frozenset(
        {
            "ftp.request.command",
            "ftp.request.arg",
            "ftp.response.code",
            "ftp.response.arg",
            "ftp.passive.ip",
            "ftp.passive.port",
            "ftp-data.setup-frame",
            "ftp-data.setup-method",
            "ftp-data.command-frame",
            "ftp-data.command",
        }
    ),
    "telnet": frozenset({"telnet.data"}),
    "multipart": frozenset(
        {
            "mime_multipart.header.content-disposition",
            "mime_multipart.header.content-type",
        }
    ),
    "smtp": frozenset(
        {
            "smtp.req.command",
            "smtp.data.reassembled.length",
        }
    ),
}


@dataclass(frozen=True)
class TlsRsaKey:
    path: Path
    byte_length: int
    sha256: str

    @property
    def preference_value(self) -> str:
        return f'uat:rsa_keys:"{self.path.as_posix()}",""'

    @property
    def arguments(self) -> tuple[str, str]:
        return ("-o", self.preference_value)

    def redact_argv(self, argv: Sequence[str]) -> list[str]:
        replacement = (
            'uat:rsa_keys:"<redacted '
            f'sha256={self.sha256} bytes={self.byte_length}>",""'
        )
        return [replacement if value == self.preference_value else value for value in argv]


TLS_KEYLOG_MAX_BYTES = 1024 * 1024
_KEYLOG_LABELS = (
    b"CLIENT_RANDOM",
    b"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    b"SERVER_HANDSHAKE_TRAFFIC_SECRET",
    b"CLIENT_EARLY_TRAFFIC_SECRET",
    b"EXPORTER_SECRET",
)
_KEYLOG_FILENAMES = (
    "ssl_keys.log",
    "sslkeylogfile.txt",
    "tls_keys.log",
    "keylog.txt",
    "ssl.log",
)


@dataclass(frozen=True)
class TlsKeylog:
    """A TLS keylog file (NSS format) enabling ECDHE/TLS 1.3 decryption."""

    path: Path
    byte_length: int
    sha256: str

    @property
    def preference_value(self) -> str:
        return f"tls.keylog_file:{self.path}"

    @property
    def arguments(self) -> tuple[str, str]:
        return ("-o", self.preference_value)

    def redact_argv(self, argv: Sequence[str]) -> list[str]:
        replacement = (
            f"tls.keylog_file:<redacted sha256={self.sha256} bytes={self.byte_length}>"
        )
        return [replacement if value == self.preference_value else value for value in argv]


def load_tls_keylog(path: Path) -> TlsKeylog:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(str(resolved))
    byte_length = resolved.stat().st_size
    if byte_length <= 0:
        raise ValueError("TLS keylog file is empty")
    if byte_length > TLS_KEYLOG_MAX_BYTES:
        raise ValueError(f"TLS keylog file exceeds {TLS_KEYLOG_MAX_BYTES} bytes")
    digest = hashlib.sha256()
    saw_label = False
    bytes_read = 0
    with resolved.open("rb") as handle:
        for index, line in enumerate(handle):
            if index >= 50:
                break
            if any(line.startswith(label) for label in _KEYLOG_LABELS):
                saw_label = True
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            bytes_read += len(chunk)
            digest.update(chunk)
    if bytes_read != byte_length:
        raise ValueError("TLS keylog file changed while it was being read")
    if not saw_label:
        raise ValueError(
            "TLS keylog file has no recognized key lines "
            "(expected CLIENT_RANDOM / *_TRAFFIC_SECRET entries)"
        )
    return TlsKeylog(resolved, byte_length, digest.hexdigest())


def find_tls_keylog(capture: Path) -> Optional[TlsKeylog]:
    """Auto-detect a sibling keylog next to the capture (challenge layouts)."""

    directory = Path(capture).expanduser().resolve().parent
    for name in _KEYLOG_FILENAMES:
        candidate = directory / name
        if not candidate.is_file():
            continue
        try:
            return load_tls_keylog(candidate)
        except (OSError, ValueError):
            continue
    return None


def load_tls_rsa_key(path: Path) -> TlsRsaKey:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(str(resolved))
    byte_length = resolved.stat().st_size
    if byte_length <= 0:
        raise ValueError("TLS RSA private key is empty")
    if byte_length > TLS_RSA_KEY_MAX_BYTES:
        raise ValueError(f"TLS RSA private key exceeds {TLS_RSA_KEY_MAX_BYTES} bytes")
    preference_path = resolved.as_posix()
    if any(character in preference_path for character in ('"', "\r", "\n")):
        raise ValueError("TLS RSA private key path contains unsupported characters")
    digest = hashlib.sha256()
    bytes_read = 0
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            bytes_read += len(chunk)
            if bytes_read > TLS_RSA_KEY_MAX_BYTES:
                raise ValueError(f"TLS RSA private key exceeds {TLS_RSA_KEY_MAX_BYTES} bytes")
            digest.update(chunk)
    if bytes_read != byte_length:
        raise ValueError("TLS RSA private key changed while it was being read")
    return TlsRsaKey(resolved, byte_length, digest.hexdigest())


@dataclass(frozen=True)
class TsharkCapabilities:
    executable: str
    version_line: str
    fields: tuple[str, ...]
    protocols: tuple[str, ...]
    export_objects: tuple[str, ...]
    features: Mapping[str, bool]
    missing_core_fields: tuple[str, ...]
    usable: bool
    errors: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2)

    def to_provenance_json(
        self,
        *,
        tls_rsa_key: Optional[TlsRsaKey] = None,
        tls_keylog: Optional[TlsKeylog] = None,
    ) -> str:
        """Return a compact, stable snapshot suitable for repeated tool runs."""

        def registry(values: tuple[str, ...]) -> dict[str, object]:
            digest = hashlib.sha256()
            for value in values:
                encoded = value.encode("utf-8")
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
            return {"count": len(values), "sha256": digest.hexdigest()}

        payload = {
            "schema_version": "auto-shark.tshark-capability/v1",
            "executable": self.executable,
            "version_line": self.version_line,
            "registries": {
                "fields": registry(self.fields),
                "protocols": registry(self.protocols),
                "export_objects": registry(self.export_objects),
            },
            "features": dict(sorted(self.features.items())),
            "missing_core_fields": self.missing_core_fields,
            "usable": self.usable,
            "errors": self.errors,
        }
        if tls_rsa_key is not None:
            payload["tls_rsa_key"] = {
                "byte_length": tls_rsa_key.byte_length,
                "sha256": tls_rsa_key.sha256,
            }
        if tls_keylog is not None:
            payload["tls_keylog"] = {
                "byte_length": tls_keylog.byte_length,
                "sha256": tls_keylog.sha256,
            }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


_WINDOWS_INSTALL_LAYOUTS = (
    "Wireshark",
    "Wireshark-Portable",
    "Apps\\Wireshark",
)
_VERSION_PATTERN = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_VERSION_CACHE: dict[tuple[str, int, int], Optional[tuple[int, int, int]]] = {}
_PROBE_CACHE: dict[tuple[str, int, int], TsharkCapabilities] = {}
# Auto-discovered tshark must be 4.x+: 2.x/3.x builds lack the ``-E``
# field-output options this tool's adapters rely on (see README requirements).
MINIMUM_TSHARK_VERSION = (4, 0, 0)
TSHARK_TOO_OLD_TEMPLATE = (
    "This TShark is too old (found {found}, need ≥ 4.0). "
    "Install Wireshark 4, or in Settings choose the tshark.exe from a portable "
    "Wireshark 4."
)


def tshark_too_old(version: Optional[tuple[int, int, int]]) -> bool:
    """True when a parsed TShark version is below the supported floor."""

    return version is not None and version < MINIMUM_TSHARK_VERSION


def format_tshark_too_old(version: tuple[int, int, int]) -> str:
    found = ".".join(str(part) for part in version)
    return TSHARK_TOO_OLD_TEMPLATE.format(found=found)


class _Missing:
    pass


_MISSING = _Missing()


def _parse_version_line(line: str) -> Optional[tuple[int, int, int]]:
    match = _VERSION_PATTERN.search(line)
    if match is None:
        return None
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch or 0))


def _tshark_version(executable: Path) -> Optional[tuple[int, int, int]]:
    """Best-effort ``--version`` probe used only to rank discovered copies."""

    try:
        stat = executable.stat()
        cache_key = (str(executable), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return None
    cached = _VERSION_CACHE.get(cache_key, _MISSING)
    if cached is not _MISSING:
        return cached
    try:
        result = run_bounded(
            [str(executable), "--version"],
            timeout_seconds=10,
            stdout_limit=64 * 1024,
            stderr_limit=16 * 1024,
        )
        version: Optional[tuple[int, int, int]] = None
        if result.returncode == 0:
            decoded = result.stdout.decode("utf-8", errors="replace")
            first_line = next((line for line in decoded.splitlines() if line), "")
            version = _parse_version_line(first_line)
    except (OSError, ValueError):
        version = None
    _VERSION_CACHE[cache_key] = version
    return version


def _registry_install_dirs() -> list[Path]:
    if os.name != "nt":  # pragma: no cover - platform guard for non-Windows CI
        return []
    try:
        import winreg
    except ImportError:  # pragma: no cover - defensive
        return []
    dirs: list[Path] = []
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for subkey in ("SOFTWARE\\Wireshark", "SOFTWARE\\WOW6432Node\\Wireshark"):
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    value, _ = winreg.QueryValueEx(key, "InstallDir")
            except OSError:
                continue
            if isinstance(value, str) and value.strip():
                dirs.append(Path(value.strip()))
    return dirs


def _default_search_dirs() -> list[Path]:
    dirs: list[Path] = []
    for variable in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
        base = os.environ.get(variable)
        if base:
            for layout in _WINDOWS_INSTALL_LAYOUTS:
                dirs.append(Path(base) / layout / "tshark.exe")
    local_programs = os.environ.get("LOCALAPPDATA")
    if local_programs:
        dirs.append(Path(local_programs) / "Programs" / "Wireshark" / "tshark.exe")
    return dirs


def discover_tshark_candidates(
    explicit: Optional[Path] = None,
    *,
    extra_dirs: Sequence[Path] = (),
) -> list[Path]:
    """Return existing tshark candidates in user-configured-to-system order."""

    candidates: list[Path] = []
    if explicit is not None:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            candidates.append(candidate.resolve())
    environment_path = os.environ.get("AUTO_SHARK_TSHARK")
    if environment_path:
        candidate = Path(environment_path).expanduser()
        if candidate.is_file() and candidate.resolve() not in candidates:
            candidates.append(candidate.resolve())
    discovered = shutil.which("tshark") or shutil.which("tshark.exe")
    if discovered:
        resolved = Path(discovered).resolve()
        if resolved not in candidates:
            candidates.append(resolved)
    for candidate in [*extra_dirs, *_registry_install_dirs(), *_default_search_dirs()]:
        expanded = Path(candidate).expanduser()
        if not expanded.is_file():
            continue
        resolved = expanded.resolve()
        if resolved not in candidates:
            candidates.append(resolved)
    return candidates


def find_tshark(
    explicit: Optional[Path] = None,
    extra_dirs: Sequence[Path] = (),
) -> Optional[Path]:
    """Locate the best available tshark, preferring the newest version.

    An explicit path always wins (the user chose it). Auto-discovered
    candidates must report a supported version: a decade-old bundled copy
    (for example 2.x) fails mid-analysis with cryptic ``-E`` option errors,
    so it is rejected up front and the caller can ask for an install.
    """

    candidates = discover_tshark_candidates(explicit, extra_dirs=extra_dirs)
    if not candidates:
        return None
    if explicit is not None:
        return candidates[0]
    supported = [
        candidate
        for candidate in candidates
        if (version := _tshark_version(candidate)) is not None
        and version >= MINIMUM_TSHARK_VERSION
    ]
    if not supported:
        return None
    if len(supported) == 1:
        return supported[0]
    best = supported[0]
    best_version = _tshark_version(best)
    for candidate in supported[1:]:
        version = _tshark_version(candidate)
        if version is not None and version > (best_version or (0, 0, 0)):
            best, best_version = candidate, version
    return best


def _run(executable: Path, arguments: Sequence[str]) -> ProcessResult:
    return run_bounded(
        [str(executable), *arguments],
        timeout_seconds=30,
        stdout_limit=32 * 1024 * 1024,
        stderr_limit=512 * 1024,
    )


def _decode(result: ProcessResult) -> str:
    return result.stdout.decode("utf-8", errors="replace")


def parse_field_registry(text: str) -> set[str]:
    fields: set[str] = set()
    for line in text.splitlines():
        columns = line.split("\t")
        if len(columns) >= 3 and columns[0] == "F" and columns[2]:
            fields.add(columns[2])
    return fields


def parse_protocol_registry(text: str) -> set[str]:
    protocols: set[str] = set()
    for line in text.splitlines():
        columns = line.split("\t")
        if len(columns) >= 3 and columns[2]:
            protocols.add(columns[2])
    return protocols


def parse_export_objects(text: str) -> set[str]:
    return {
        stripped
        for line in text.splitlines()
        if (stripped := line.strip()) and " " not in stripped and "\t" not in stripped
    }


def _error_for(label: str, result: ProcessResult) -> Optional[str]:
    if result.timed_out:
        return f"{label} probe timed out"
    if result.output_limit_exceeded:
        return f"{label} probe exceeded its output limit"
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        return f"{label} probe exited {result.returncode}: {detail[:500]}"
    return None


def probe_tshark(path: Path) -> TsharkCapabilities:
    executable = Path(path).expanduser().resolve()
    if not executable.is_file():
        raise FileNotFoundError(str(executable))
    try:
        stat = executable.stat()
        cache_key = (str(executable), stat.st_mtime_ns, stat.st_size)
    except OSError:
        cache_key = None
    if cache_key is not None:
        cached = _PROBE_CACHE.get(cache_key)
        if cached is not None:
            return cached

    version_result = _run(executable, ["--version"])
    fields_result = _run(executable, ["-G", "fields"])
    protocols_result = _run(executable, ["-G", "protocols"])
    exports_result = _run(executable, ["--export-objects", "help"])
    errors = tuple(
        error
        for error in (
            _error_for("version", version_result),
            _error_for("fields", fields_result),
            _error_for("protocols", protocols_result),
            _error_for("export objects", exports_result),
        )
        if error is not None
    )
    fields = (
        parse_field_registry(_decode(fields_result)) if fields_result.returncode == 0 else set()
    )
    protocols = (
        parse_protocol_registry(_decode(protocols_result))
        if protocols_result.returncode == 0
        else set()
    )
    exports_text = (
        _decode(exports_result) + "\n" + exports_result.stderr.decode("utf-8", errors="replace")
    )
    exports = parse_export_objects(exports_text) if exports_result.returncode == 0 else set()
    missing_core = tuple(sorted(CORE_FIELDS - fields))
    features = {name: required.issubset(fields) for name, required in FEATURE_FIELDS.items()}
    features["http_export"] = "http" in exports
    features["ftp_data_export"] = "ftp-data" in exports
    first_line = next((line.strip() for line in _decode(version_result).splitlines() if line), "")
    parsed_version = _parse_version_line(first_line)
    version_errors: tuple[str, ...] = ()
    if tshark_too_old(parsed_version) and parsed_version is not None:
        found = ".".join(str(part) for part in parsed_version)
        version_errors = (
            f"tshark {found} is below the required {MINIMUM_TSHARK_VERSION[0]}.0.0",
        )
        errors = errors + version_errors
    # ``--export-objects`` support is an optional accelerator: an old or
    # stripped-down build that rejects it still parses protocols fine, so it
    # only disables the export features instead of marking tshark unusable.
    fatal = tuple(
        error
        for error in (
            _error_for("version", version_result),
            _error_for("fields", fields_result),
            _error_for("protocols", protocols_result),
        )
        if error is not None
    )
    capabilities = TsharkCapabilities(
        executable=str(executable),
        version_line=first_line,
        fields=tuple(sorted(fields)),
        protocols=tuple(sorted(protocols)),
        export_objects=tuple(sorted(exports)),
        features=features,
        missing_core_fields=missing_core,
        usable=not fatal and not missing_core and not version_errors,
        errors=errors,
    )
    if cache_key is not None:
        _PROBE_CACHE[cache_key] = capabilities
    return capabilities
