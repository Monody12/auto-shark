import binascii
import io
import struct
import zipfile

import pytest

from auto_shark.files.signatures import discover_file_candidates


def _png_chunk(kind: bytes, data: bytes = b"") -> bytes:
    crc = binascii.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def _minimal_png() -> bytes:
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", b"\0" * 13) + _png_chunk(b"IEND")


def _minimal_jpeg(entropy: bytes = b"image") -> bytes:
    return (
        b"\xff\xd8"
        b"\xff\xe0\x00\x04JF"
        b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + entropy + b"\xff\xd9"
    )


def test_discovers_embedded_zip_with_eocd_comment_and_trailing_bytes(tmp_path) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("flag.txt", "content")
        output.comment = b"comment"
    path = tmp_path / "body.bin"
    path.write_bytes(b"->|" + archive.getvalue() + b"|<-")
    result = discover_file_candidates(path, window_bytes=5)
    candidate = next(item for item in result.candidates if item.format == "zip")
    assert candidate.start_offset == 3
    assert candidate.byte_length == len(archive.getvalue())
    assert candidate.structural_status == "validated"
    assert candidate.prefix_length == 3
    assert candidate.trailing_length == 3
    assert not result.scan_truncated


def test_discovers_zip_before_large_trailing_region(tmp_path) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("data.txt", "content")
    path = tmp_path / "body.bin"
    path.write_bytes(archive.getvalue() + b"T" * 70_000)
    candidate = discover_file_candidates(path, window_bytes=257).candidates[0]
    assert candidate.format == "zip"
    assert candidate.byte_length == len(archive.getvalue())
    assert candidate.trailing_length == 70_000


def test_discovers_jpeg_with_stuffed_ff_and_trailing_data(tmp_path) -> None:
    jpeg = _minimal_jpeg(b"image\xff\x00data\xff\xd0more")
    path = tmp_path / "body.bin"
    path.write_bytes(b"prefix" + jpeg + b"flag{tail}")
    result = discover_file_candidates(path, window_bytes=4)
    candidate = next(item for item in result.candidates if item.format == "jpeg")
    assert candidate.start_offset == 6
    assert candidate.byte_length == len(jpeg)
    assert candidate.trailing_offset == 6 + len(jpeg)
    assert candidate.trailing_length == len(b"flag{tail}")


def test_rejects_jpeg_signature_with_false_eoi_inside_segment(tmp_path) -> None:
    path = tmp_path / "false.jpg"
    path.write_bytes(b"\xff\xd8\xff\xe0\x00\x08A\xff\xd9BCD")
    assert not discover_file_candidates(path).candidates


def test_validates_png_crc_and_rejects_corruption(tmp_path) -> None:
    valid = tmp_path / "valid.bin"
    valid.write_bytes(b"x" + _minimal_png() + b"tail")
    candidate = discover_file_candidates(valid).candidates[0]
    assert candidate.format == "png"
    assert candidate.structural_status == "validated"
    corrupt = tmp_path / "corrupt.bin"
    data = bytearray(_minimal_png())
    data[-1] ^= 1
    corrupt.write_bytes(data)
    assert not discover_file_candidates(corrupt).candidates


def test_reports_scan_truncation_without_reading_to_structural_end(tmp_path) -> None:
    path = tmp_path / "large.bin"
    jpeg = _minimal_jpeg(b"A" * 1024)
    path.write_bytes(jpeg)
    result = discover_file_candidates(path, max_scan_bytes=100, window_bytes=17)
    assert result.scan_truncated
    assert result.scanned_bytes == 100
    assert result.candidates[0].structural_status == "scan-truncated"
    assert result.candidates[0].byte_length == 100


def test_sparse_large_file_respects_scan_budget(tmp_path) -> None:
    path = tmp_path / "sparse.bin"
    with path.open("wb") as stream:
        stream.write(_minimal_jpeg(b"A" * 512))
        stream.seek(128 * 1024 * 1024)
        stream.write(b"end")
    result = discover_file_candidates(path, max_scan_bytes=4096, window_bytes=257)
    assert result.file_length > 128 * 1024 * 1024
    assert result.scanned_bytes == 4096
    assert result.scan_truncated
    assert result.candidates[0].structural_status == "validated"


def test_reports_artifact_truncation_after_validating_structure(tmp_path) -> None:
    path = tmp_path / "large.jpg"
    path.write_bytes(_minimal_jpeg(b"A" * 1024))
    candidate = discover_file_candidates(path, max_artifact_bytes=100).candidates[0]
    assert candidate.structural_status == "artifact-truncated"
    assert candidate.byte_length == 100
    assert candidate.trailing_length == 0


def test_filters_false_pe_and_gzip_headers(tmp_path) -> None:
    path = tmp_path / "false.bin"
    path.write_bytes(b"MZnot-a-pe\0\0\x1f\x8b\x09\xe0")
    assert not discover_file_candidates(path).candidates


@pytest.mark.parametrize("value", [0, -1])
def test_rejects_nonpositive_limits(tmp_path, value) -> None:
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    with pytest.raises(ValueError, match="positive"):
        discover_file_candidates(path, max_scan_bytes=value)
