"""TShark discovery and structured capability probing."""

from __future__ import annotations

import hashlib
import json
import os
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

    def to_provenance_json(self, *, tls_rsa_key: Optional[TlsRsaKey] = None) -> str:
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
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def find_tshark(explicit: Optional[Path] = None) -> Optional[Path]:
    if explicit is not None:
        candidate = Path(explicit).expanduser()
        return candidate.resolve() if candidate.is_file() else None
    environment_path = os.environ.get("AUTO_SHARK_TSHARK")
    if environment_path:
        candidate = Path(environment_path).expanduser()
        if candidate.is_file():
            return candidate.resolve()
    discovered = shutil.which("tshark") or shutil.which("tshark.exe")
    return Path(discovered).resolve() if discovered else None


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
    return TsharkCapabilities(
        executable=str(executable),
        version_line=first_line,
        fields=tuple(sorted(fields)),
        protocols=tuple(sorted(protocols)),
        export_objects=tuple(sorted(exports)),
        features=features,
        missing_core_fields=missing_core,
        usable=not errors and not missing_core,
        errors=errors,
    )
