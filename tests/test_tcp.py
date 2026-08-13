from pathlib import Path

from auto_shark.tcp import _AcceptedSpan, _plan_segment


def _write(tmp_path: Path, name: str, value: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(value)
    return path


def test_segment_plan_deduplicates_exact_retransmission(tmp_path) -> None:
    first = _write(tmp_path, "first", b"abcdef")
    retransmission = _write(tmp_path, "second", b"abcdef")
    accepted = [_AcceptedSpan(10, 16, 1, first, 0)]
    additions, sources, conflicts, duplicates = _plan_segment(
        accepted,
        segment_id=2,
        segment_start=10,
        segment_length=6,
        blob_path=retransmission,
    )
    assert additions == []
    assert [(item.sequence_offset, item.byte_length) for item in sources] == [(10, 6)]
    assert conflicts == []
    assert duplicates == 6


def test_segment_plan_preserves_first_seen_and_splits_conflict_runs(tmp_path) -> None:
    first = _write(tmp_path, "first", b"abcdef")
    overlap = _write(tmp_path, "second", b"cXefYZ")
    accepted = [_AcceptedSpan(10, 16, 1, first, 0)]
    additions, sources, conflicts, duplicates = _plan_segment(
        accepted,
        segment_id=2,
        segment_start=12,
        segment_length=6,
        blob_path=overlap,
    )
    assert [(item.start, item.end, item.blob_offset) for item in additions] == [(16, 18, 4)]
    assert [(item.sequence_offset, item.byte_length) for item in sources] == [(12, 1), (14, 2)]
    assert [(item.sequence_start, item.byte_length) for item in conflicts] == [(13, 1)]
    assert duplicates == 3
    assert [(item.start, item.end, item.segment_id) for item in accepted] == [
        (10, 16, 1),
        (16, 18, 2),
    ]


def test_segment_plan_keeps_nonoverlapping_gap(tmp_path) -> None:
    first = _write(tmp_path, "first", b"abc")
    second = _write(tmp_path, "second", b"xyz")
    accepted = [_AcceptedSpan(1, 4, 1, first, 0)]
    additions, sources, conflicts, duplicates = _plan_segment(
        accepted,
        segment_id=2,
        segment_start=7,
        segment_length=3,
        blob_path=second,
    )
    assert [(item.start, item.end) for item in additions] == [(7, 10)]
    assert not sources and not conflicts and duplicates == 0
