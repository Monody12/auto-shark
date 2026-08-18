"""Bounded DNS encoded-label triage and conservative file recovery."""

from __future__ import annotations

import base64
import binascii
import csv
import json
import re
import sqlite3
import zlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from uuid import uuid4

from .core.ids import stable_id
from .engines.stream import run_streaming_lines
from .engines.tshark import probe_tshark
from .project import inspect_project
from .storage import BlobStore, Database

DNS_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.stream",
    "dns.qry.name",
)
DNS_REQUIRED_FIELDS = frozenset(DNS_FIELDS)
DETECTOR_VERSION = "auto-shark.dns-label-triage/v1"
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BASE32 = re.compile(r"^[A-Za-z2-7]+$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class DnsQuery:
    frame_number: int
    source: str
    destination: str
    udp_stream: int | None
    query_name: str


@dataclass(frozen=True, order=True)
class _GroupKey:
    source: str
    destination: str
    base_domain: str
    encoding: str


@dataclass
class _Group:
    key: _GroupKey
    frames: list[int]
    chunks: list[bytes]
    encoded_names: list[str]
    decoded_bytes: int = 0


@dataclass(frozen=True)
class DnsGroupResult:
    evidence_id: str
    source: str
    destination: str
    base_domain: str
    encoding: str
    score: int
    query_count: int
    unique_chunks: int
    duplicate_chunks: int
    decoded_bytes: int
    first_frame: int
    last_frame: int
    inferred_header_bytes: int | None
    preview_hex: str
    artifact_id: str | None
    artifact_name: str | None
    artifact_bytes: int | None
    artifact_sha256: str | None


@dataclass(frozen=True)
class DnsTriageSummary:
    schema_version: str
    project: str
    status: str
    queries_seen: int
    encoded_queries: int
    decoded_bytes: int
    malformed_rows: int
    skipped_query_limit: int
    skipped_group_limit: int
    skipped_decoded_budget: int
    groups: tuple[DnsGroupResult, ...]
    hints: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def parse_dns_line(line: bytes) -> DnsQuery:
    rows = list(
        csv.reader(
            StringIO(line.decode("utf-8", errors="strict")),
            delimiter="\t",
            quotechar='"',
        )
    )
    if len(rows) != 1 or len(rows[0]) != len(DNS_FIELDS):
        raise ValueError("invalid DNS field row")
    data = dict(zip(DNS_FIELDS, rows[0]))
    source = data["ip.src"] or data["ipv6.src"]
    destination = data["ip.dst"] or data["ipv6.dst"]
    if not source or not destination or not data["dns.qry.name"]:
        raise ValueError("DNS row lacks endpoints or query name")
    return DnsQuery(
        frame_number=int(data["frame.number"]),
        source=source,
        destination=destination,
        udp_stream=int(data["udp.stream"]) if data["udp.stream"] else None,
        query_name=data["dns.qry.name"].rstrip("."),
    )


def tshark_dns_arguments(executable: Path, capture: Path) -> list[str]:
    arguments = [
        str(executable),
        "-r",
        str(capture),
        "-Y",
        "dns.flags.response == 0 && dns.qry.name",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
        "-E",
        "occurrence=f",
    ]
    for field in DNS_FIELDS:
        arguments.extend(("-e", field))
    return arguments


def _decode_label(value: str) -> tuple[str, bytes] | None:
    if len(value) >= 16 and len(value) % 2 == 0 and _HEX.fullmatch(value):
        return "hex", bytes.fromhex(value)
    if len(value) >= 16 and _BASE32.fullmatch(value):
        try:
            padded = value.upper() + "=" * ((-len(value)) % 8)
            return "base32", base64.b32decode(padded, casefold=True)
        except binascii.Error:
            return None
    if len(value) >= 24 and _BASE64URL.fullmatch(value):
        if not (re.search(r"[A-Za-z]", value) and re.search(r"[0-9_-]", value)):
            return None
        try:
            padded = value + "=" * ((-len(value)) % 4)
            return "base64url", base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError):
            return None
    return None


def decode_query_name(query_name: str) -> tuple[str, str, bytes, str] | None:
    labels = query_name.split(".")
    encoded_labels: list[str] = []
    encoding: str | None = None
    decoded = bytearray()
    for label in labels:
        item = _decode_label(label)
        if item is None or (encoding is not None and item[0] != encoding):
            break
        encoding = item[0]
        encoded_labels.append(label)
        decoded.extend(item[1])
    if encoding is None or not encoded_labels or len(encoded_labels) == len(labels):
        return None
    base_domain = ".".join(labels[len(encoded_labels) :]).lower()
    return encoding, base_domain, bytes(decoded), ".".join(encoded_labels)


class _Collector:
    def __init__(self, max_queries: int, max_groups: int, max_decoded_bytes: int) -> None:
        self.max_queries = max_queries
        self.max_groups = max_groups
        self.max_decoded_bytes = max_decoded_bytes
        self.groups: dict[_GroupKey, _Group] = {}
        self.route_queries: dict[tuple[str, str], int] = {}
        self.queries_seen = 0
        self.encoded_queries = 0
        self.decoded_bytes = 0
        self.malformed_rows = 0
        self.skipped_query_limit = 0
        self.skipped_group_limit = 0
        self.skipped_decoded_budget = 0

    @property
    def budget_limited(self) -> bool:
        return bool(
            self.skipped_query_limit
            or self.skipped_group_limit
            or self.skipped_decoded_budget
        )

    def add_line(self, line: bytes) -> None:
        self.queries_seen += 1
        if self.queries_seen > self.max_queries:
            self.skipped_query_limit += 1
            return
        try:
            query = parse_dns_line(line)
        except (UnicodeError, ValueError):
            self.malformed_rows += 1
            return
        route = (query.source, query.destination)
        self.route_queries[route] = self.route_queries.get(route, 0) + 1
        decoded = decode_query_name(query.query_name)
        if decoded is None:
            return
        encoding, base_domain, chunk, encoded_name = decoded
        if self.decoded_bytes + len(chunk) > self.max_decoded_bytes:
            self.skipped_decoded_budget += 1
            return
        key = _GroupKey(query.source, query.destination, base_domain, encoding)
        group = self.groups.get(key)
        if group is None:
            if len(self.groups) >= self.max_groups:
                self.skipped_group_limit += 1
                return
            group = _Group(key, [], [], [])
            self.groups[key] = group
        group.frames.append(query.frame_number)
        group.chunks.append(chunk)
        if len(group.encoded_names) < 3:
            group.encoded_names.append(encoded_name[:256])
        group.decoded_bytes += len(chunk)
        self.encoded_queries += 1
        self.decoded_bytes += len(chunk)


def _unique_chunks(chunks: list[bytes], offset: int) -> list[bytes]:
    unique: list[bytes] = []
    seen: set[bytes] = set()
    for chunk in chunks:
        if len(chunk) <= offset:
            continue
        payload = chunk[offset:]
        if payload not in seen:
            seen.add(payload)
            unique.append(payload)
    return unique


def _validated_pngs(data: bytes, max_artifact_bytes: int) -> list[tuple[int, int]]:
    results: list[tuple[int, int]] = []
    search = 0
    while True:
        start = data.find(_PNG_SIGNATURE, search)
        if start < 0:
            break
        cursor = start + len(_PNG_SIGNATURE)
        saw_ihdr = False
        while cursor + 12 <= len(data) and cursor - start <= max_artifact_bytes:
            length = int.from_bytes(data[cursor : cursor + 4], "big")
            chunk_end = cursor + 12 + length
            if (
                length > max_artifact_bytes
                or chunk_end > len(data)
                or chunk_end - start > max_artifact_bytes
            ):
                break
            chunk_type = data[cursor + 4 : cursor + 8]
            chunk_data = data[cursor + 8 : cursor + 8 + length]
            expected_crc = int.from_bytes(data[cursor + 8 + length : chunk_end], "big")
            actual_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                break
            if not saw_ihdr:
                if chunk_type != b"IHDR" or length != 13:
                    break
                saw_ihdr = True
            cursor = chunk_end
            if chunk_type == b"IEND" and length == 0:
                results.append((start, cursor))
                break
        search = start + 1
    return results


def _recover_png(
    chunks: list[bytes], *, max_stream_bytes: int, max_artifact_bytes: int
) -> tuple[int, bytes, int, int, bytes] | None:
    candidates: dict[bytes, tuple[int, bytes, int, int]] = {}
    for offset in range(33):
        unique = _unique_chunks(chunks, offset)
        if len(unique) < 3:
            continue
        stream = b"".join(unique)
        if len(stream) > max_stream_bytes:
            continue
        for start, end in _validated_pngs(stream, max_artifact_bytes):
            artifact = stream[start:end]
            candidates.setdefault(artifact, (offset, stream, start, end))
    if len(candidates) != 1:
        return None
    artifact, (offset, stream, start, end) = next(iter(candidates.items()))
    return offset, stream, start, end, artifact


def _score(group: _Group, route_queries: int) -> int:
    query_count = len(group.chunks)
    unique_count = len(set(group.chunks))
    ratio = query_count / max(route_queries, 1)
    score = 35
    score += 15 if query_count >= 5 else 0
    score += 10 if query_count >= 20 else 0
    score += 10 if group.decoded_bytes >= 512 else 0
    score += 10 if group.decoded_bytes >= 4096 else 0
    score += 10 if ratio >= 0.5 else 0
    score += 5 if unique_count >= 5 else 0
    score += 5 if max(map(len, group.chunks), default=0) >= 32 else 0
    return min(score, 100)


def _store_blob(
    connection: sqlite3.Connection,
    project_root: Path,
    data: bytes,
    *,
    media_type: str,
    description: str,
    complete: bool,
) -> tuple[int, str]:
    blob = BlobStore(project_root / "blobs").put_bytes(data)
    relative = blob.path.relative_to(project_root).as_posix()
    connection.execute(
        "INSERT INTO blob(sha256,byte_length,relative_path,media_type,magic_description,"
        "complete,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
        "media_type=coalesce(blob.media_type,excluded.media_type),"
        "magic_description=coalesce(blob.magic_description,excluded.magic_description),"
        "complete=max(blob.complete,excluded.complete)",
        (
            blob.sha256,
            blob.byte_length,
            relative,
            media_type,
            description,
            int(complete),
            _now(),
        ),
    )
    blob_id = int(
        connection.execute("SELECT id FROM blob WHERE sha256=?", (blob.sha256,)).fetchone()[0]
    )
    return blob_id, blob.sha256


def _persist_group(
    connection: sqlite3.Connection,
    project_root: Path,
    capture_id: int,
    capture_sha256: str,
    group: _Group,
    route_queries: int,
    *,
    max_preview_bytes: int,
    max_stream_bytes: int,
    max_artifact_bytes: int,
) -> DnsGroupResult | None:
    score = _score(group, route_queries)
    if score < 60 or len(group.chunks) < 5 or group.decoded_bytes < 128:
        return None
    recovered = _recover_png(
        group.chunks,
        max_stream_bytes=max_stream_bytes,
        max_artifact_bytes=max_artifact_bytes,
    )
    if recovered is None:
        inferred_header = None
        stream = b"".join(_unique_chunks(group.chunks, 0))[:max_preview_bytes]
        artifact_range = artifact = None
    else:
        inferred_header, stream, start, end, artifact = recovered
        artifact_range = (start, end)
    preview = stream[:max_preview_bytes]
    source_data = stream if recovered is not None else preview
    source_blob_id, _ = _store_blob(
        connection,
        project_root,
        source_data,
        media_type="application/octet-stream",
        description="inferred DNS encoded-label byte stream",
        complete=False,
    )
    unique_chunks = len(set(group.chunks))
    locator = {
        "base_domain": group.key.base_domain,
        "capture_sha256": capture_sha256,
        "decoded_bytes": group.decoded_bytes,
        "destination": group.key.destination,
        "detector": DETECTOR_VERSION,
        "duplicate_chunks": len(group.chunks) - unique_chunks,
        "encoding": group.key.encoding,
        "inferred_header_bytes": inferred_header,
        "ordering": "capture-first-seen",
        "preview_hex": preview.hex(),
        "query_count": len(group.chunks),
        "route_query_count": route_queries,
        "sample_labels": group.encoded_names,
        "score": score,
        "source": group.key.source,
        "unique_chunks": unique_chunks,
    }
    identity = {
        "capture_sha256": capture_sha256,
        "source": group.key.source,
        "destination": group.key.destination,
        "base_domain": group.key.base_domain,
        "encoding": group.key.encoding,
        "detector": DETECTOR_VERSION,
    }
    evidence_public_id = stable_id("dns-label-stream-evidence", identity)
    connection.execute(
        "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
        "direction,byte_offset,byte_length,field_name,blob_id,locator_json) "
        "VALUES(?,?,'dns-label-stream',?,?,'source-to-destination',0,?,'dns.qry.name',?,?) "
        "ON CONFLICT(evidence_id) DO UPDATE SET frame_start=excluded.frame_start,"
        "frame_end=excluded.frame_end,byte_length=excluded.byte_length,"
        "blob_id=excluded.blob_id,locator_json=excluded.locator_json",
        (
            evidence_public_id,
            capture_id,
            min(group.frames),
            max(group.frames),
            len(source_data),
            source_blob_id,
            json.dumps(locator, sort_keys=True),
        ),
    )
    artifact_id = artifact_name = artifact_sha256 = None
    artifact_bytes = None
    if artifact is not None and artifact_range is not None:
        artifact_start, artifact_end = artifact_range
        artifact_blob_id, artifact_sha256 = _store_blob(
            connection,
            project_root,
            artifact,
            media_type="image/png",
            description="validated PNG recovered from DNS labels",
            complete=True,
        )
        artifact_id = stable_id(
            "dns-label-artifact", {**identity, "sha256": artifact_sha256}
        )
        artifact_name = f"dns-{group.key.base_domain.replace('.', '-')}-{artifact_sha256[:12]}.png"
        artifact_bytes = len(artifact)
        carved_locator = {
            **locator,
            "artifact_end": artifact_end,
            "artifact_start": artifact_start,
            "source_evidence_id": evidence_public_id,
        }
        carved_evidence_public_id = stable_id(
            "dns-carved-file-evidence",
            {**identity, "artifact_sha256": artifact_sha256, "start": artifact_start},
        )
        connection.execute(
            "INSERT INTO evidence(evidence_id,capture_id,source_kind,frame_start,frame_end,"
            "direction,byte_offset,byte_length,field_name,blob_id,locator_json) "
            "VALUES(?,?,'dns-carved-file',?,?,'source-to-destination',?,?,"
            "'dns.qry.name',?,?) ON CONFLICT(evidence_id) DO UPDATE SET "
            "byte_offset=excluded.byte_offset,byte_length=excluded.byte_length,"
            "blob_id=excluded.blob_id,locator_json=excluded.locator_json",
            (
                carved_evidence_public_id,
                capture_id,
                min(group.frames),
                max(group.frames),
                artifact_start,
                artifact_bytes,
                source_blob_id,
                json.dumps(carved_locator, sort_keys=True),
            ),
        )
        carved_evidence_db_id = int(
            connection.execute(
                "SELECT id FROM evidence WHERE evidence_id=?",
                (carved_evidence_public_id,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO artifact(artifact_id,blob_id,source_evidence_id,suggested_name,"
            "declared_media_type,detected_media_type,review_state,created_at) "
            "VALUES(?,?,?,?,'image/png','image/png','unreviewed',?) "
            "ON CONFLICT(artifact_id) DO UPDATE SET blob_id=excluded.blob_id,"
            "source_evidence_id=excluded.source_evidence_id,"
            "suggested_name=excluded.suggested_name,"
            "declared_media_type=excluded.declared_media_type,"
            "detected_media_type=excluded.detected_media_type",
            (artifact_id, artifact_blob_id, carved_evidence_db_id, artifact_name, _now()),
        )
        artifact_db_id = int(
            connection.execute(
                "SELECT id FROM artifact WHERE artifact_id=?", (artifact_id,)
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT OR IGNORE INTO artifact_evidence(artifact_id,evidence_id,role) "
            "VALUES(?,?,'recovered-from')",
            (artifact_db_id, carved_evidence_db_id),
        )
    return DnsGroupResult(
        evidence_id=evidence_public_id,
        source=group.key.source,
        destination=group.key.destination,
        base_domain=group.key.base_domain,
        encoding=group.key.encoding,
        score=score,
        query_count=len(group.chunks),
        unique_chunks=unique_chunks,
        duplicate_chunks=len(group.chunks) - unique_chunks,
        decoded_bytes=group.decoded_bytes,
        first_frame=min(group.frames),
        last_frame=max(group.frames),
        inferred_header_bytes=inferred_header,
        preview_hex=preview.hex(),
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        artifact_bytes=artifact_bytes,
        artifact_sha256=artifact_sha256,
    )


def triage_dns_tunnels(
    project_path: Path,
    tshark: Path,
    *,
    max_queries: int = 100_000,
    max_groups: int = 256,
    max_decoded_bytes: int = 64 * 1024 * 1024,
    max_preview_bytes: int = 4096,
    max_stream_bytes: int = 16 * 1024 * 1024,
    max_artifact_bytes: int = 16 * 1024 * 1024,
) -> DnsTriageSummary:
    if min(
        max_queries,
        max_groups,
        max_decoded_bytes,
        max_preview_bytes,
        max_stream_bytes,
        max_artifact_bytes,
    ) <= 0:
        raise ValueError("DNS triage limits must be positive")
    project = inspect_project(project_path)
    capabilities = probe_tshark(tshark)
    missing = DNS_REQUIRED_FIELDS - set(capabilities.fields)
    if not capabilities.usable or missing:
        raise ValueError("TShark lacks required DNS fields: " + ", ".join(sorted(missing)))
    argv = tshark_dns_arguments(tshark, project.capture_path)
    collector = _Collector(max_queries, max_groups, max_decoded_bytes)
    database = Database(project.root / "project.sqlite")
    database.initialize()
    run_id = uuid4().hex
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO tool_run(run_id,tool_name,tool_version,argv_json,capability_json,"
            "started_at,status) VALUES(?,?,?,?,?,?,'running')",
            (
                run_id,
                "tshark-dns-label-triage",
                capabilities.version_line,
                json.dumps(argv, ensure_ascii=False),
                capabilities.to_provenance_json(),
                _now(),
            ),
        )
    result = run_streaming_lines(
        argv,
        collector.add_line,
        timeout_seconds=300,
        max_line_bytes=2 * 1024 * 1024,
        stderr_limit=512 * 1024,
    )
    failed = result.timed_out or result.output_limit_exceeded or result.returncode != 0
    status = "failed" if failed else "budget-limited" if collector.budget_limited else "completed"
    with database.connect() as connection:
        connection.execute(
            "UPDATE tool_run SET ended_at=?,status=?,exit_code=?,stderr_text=?,"
            "stderr_truncated=? WHERE run_id=?",
            (
                _now(),
                status,
                result.returncode,
                result.stderr.decode("utf-8", errors="replace"),
                int(result.stderr_truncated),
                run_id,
            ),
        )
    if failed:
        raise RuntimeError(f"TShark DNS extraction failed with exit {result.returncode}")
    groups: list[DnsGroupResult] = []
    with database.connect() as connection:
        capture_id = int(
            connection.execute(
                "SELECT id FROM capture WHERE sha256=?", (project.capture_sha256,)
            ).fetchone()[0]
        )
        for key in sorted(collector.groups):
            group = collector.groups[key]
            persisted = _persist_group(
                connection,
                project.root,
                capture_id,
                project.capture_sha256,
                group,
                collector.route_queries.get((key.source, key.destination), 0),
                max_preview_bytes=max_preview_bytes,
                max_stream_bytes=max_stream_bytes,
                max_artifact_bytes=max_artifact_bytes,
            )
            if persisted is not None:
                groups.append(persisted)
    return DnsTriageSummary(
        schema_version="auto-shark.dns-triage/v1",
        project=str(project.root),
        status=status,
        queries_seen=collector.queries_seen,
        encoded_queries=collector.encoded_queries,
        decoded_bytes=collector.decoded_bytes,
        malformed_rows=collector.malformed_rows,
        skipped_query_limit=collector.skipped_query_limit,
        skipped_group_limit=collector.skipped_group_limit,
        skipped_decoded_budget=collector.skipped_decoded_budget,
        groups=tuple(groups),
        hints=(
            "Review source, destination, base domain, duplicate rate, and decoded preview.",
            "Recovered PNG artifacts require valid chunk CRCs; other decoded streams "
            "remain suggestions.",
            "Capture order is only a first-seen heuristic, so ambiguous streams are "
            "not exported as files.",
        ),
    )
