"""Global needle search across stored blobs."""

from __future__ import annotations

import base64
import binascii
import codecs
import json
from pathlib import Path

from auto_shark.grep import grep_project, needle_variants
from auto_shark.project import create_project
from auto_shark.storage import BlobStore, Database


def _project_with_blobs(tmp_path: Path) -> Path:
    capture = tmp_path / "cap.pcap"
    capture.write_bytes(b"pcap")
    root = tmp_path / "case.auto-shark"
    create_project(capture, root, allow_synced=True)
    store = BlobStore(root / "blobs")
    database = Database(root / "project.sqlite")

    def add(data: bytes, source_kind: str) -> None:
        blob = store.put_bytes(data)
        with database.connect() as connection:
            capture_id = int(connection.execute("SELECT id FROM capture").fetchone()[0])
            cursor = connection.execute(
                "INSERT INTO blob(sha256, byte_length, relative_path, media_type, "
                "magic_description, complete, created_at) VALUES (?,?,?,?,?,1,'x')",
                (blob.sha256, len(data), blob.path.relative_to(root).as_posix(), None, None),
            )
            blob_id = cursor.lastrowid
            connection.execute(
                "INSERT INTO evidence(evidence_id, capture_id, source_kind, frame_start,"
                "frame_end, byte_offset, byte_length, text_value, blob_id, locator_json) "
                "VALUES('ev-'||?, ?, ?, 1, 2, 0, ?, NULL, ?, '{}')",
                (str(blob_id), capture_id, source_kind, len(data), blob_id),
            )

    add(b"plain flag{grep_hit_one} rest", "http-body")
    add(b"encoded: " + base64.b64encode(b"hidden flag{b64_hit} tail"), "http-body")
    add(b"hexform: " + binascii.hexlify(b"flag{hex_hit}"), "http-body")
    add(b"unrelated blob", "tcp-stream")
    add(b"zip -P PaSsZiPWorD flag.zip", "http-body")
    return root


def test_needle_variants_cover_raw_hex_and_base64_phases() -> None:
    variants = dict(needle_variants("flag"))
    assert variants["raw"] == b"flag"
    assert variants["hex-lower"] == b"666c6167"
    assert base64.b64decode(variants["base64"] + b"==") == b"flag"
    assert any(key.startswith("base64-phase") for key in variants)
    # A longer needle produces both alignment phases.
    long_variants = dict(needle_variants("flagcontent"))
    assert "base64-phase1" in long_variants and "base64-phase2" in long_variants


def test_needle_variants_include_rot13() -> None:
    variants = dict(needle_variants("TFTPDoesnt"))
    assert variants.get("rot13") == codecs.encode("tftpdoesnt", "rot13").encode()


def test_grep_project_finds_rot13_disguised_text(tmp_path) -> None:
    root = _project_with_blobs(tmp_path)
    import codecs

    disguised = codecs.encode(
        "TFTP DOESN'T ENCRYPT OUR TRAFFIC", "rot13"
    ).encode()
    (root / "blobs" / "sha256" / "zz").mkdir(parents=True, exist_ok=True)
    store = BlobStore(root / "blobs")
    blob = store.put_bytes(b"note: " + disguised)
    from auto_shark.storage import Database

    database = Database(root / "project.sqlite")
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO blob(sha256, byte_length, relative_path, complete, created_at) "
            "VALUES (?,?,?,?,?)",
            (blob.sha256, blob.byte_length, blob.path.relative_to(root).as_posix(), 1, "x"),
        )
    result = grep_project(root, "TFTP DOESN'T ENCRYPT")
    assert any(match["variant"] == "rot13" for match in result["matches"])


def test_grep_project_searches_raw_case_insensitively(tmp_path) -> None:
    root = _project_with_blobs(tmp_path)
    (root / "blobs" / "sha256" / "zz").mkdir(parents=True, exist_ok=True)
    # Mixed-case needle and mixed-case content must still meet.
    result = grep_project(root, "PaSsZiPWorD")
    assert any("PaSsZiPWorD" in match["context"] for match in result["matches"])


def test_grep_project_finds_raw_encoded_hits_with_context(tmp_path) -> None:
    root = _project_with_blobs(tmp_path)
    result = grep_project(root, "flag{")
    variants_hit = {match["variant"] for match in result["matches"]}
    values = " ".join(match["context"] for match in result["matches"])
    assert "raw" in variants_hit
    assert "base64" in variants_hit or "base64-phase1" in variants_hit
    assert "hex-lower" in variants_hit
    assert "grep_hit_one" in values
    assert result["blobs_scanned"] == 5
    kinds = {match["source_kind"] for match in result["matches"]}
    assert kinds == {"http-body"}


def test_grep_project_rejects_empty_needle(tmp_path) -> None:
    root = _project_with_blobs(tmp_path)
    try:
        grep_project(root, "")
    except ValueError as error:
        assert "needle" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_grep_result_is_json_serializable(tmp_path) -> None:
    root = _project_with_blobs(tmp_path)
    result = grep_project(root, "flag")
    json.dumps(result)
