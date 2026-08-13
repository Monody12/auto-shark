import sys

import pytest

from auto_shark.engines.hexstream import run_hex_to_file


def _run(tmp_path, source: str, limit: int = 100):
    output = tmp_path / "output.bin"
    with output.open("wb") as target:
        result = run_hex_to_file(
            [sys.executable, "-c", f"import sys; sys.stdout.write({source!r})"],
            target,
            timeout_seconds=5,
            max_decoded_bytes=limit,
            stderr_limit=100,
        )
    return result, output.read_bytes()


def test_hex_stream_decodes_across_separators(tmp_path) -> None:
    result, data = _run(tmp_path, "41:42 43\n44")
    assert data == b"ABCD"
    assert result.decoded_bytes == 4
    assert not result.limit_truncated


def test_hex_stream_enforces_decoded_limit(tmp_path) -> None:
    result, data = _run(tmp_path, "41424344", limit=3)
    assert data == b"ABC"
    assert result.decoded_bytes == 3
    assert result.limit_truncated


@pytest.mark.parametrize("source", ["4", "41zz"])
def test_hex_stream_rejects_malformed_output(tmp_path, source) -> None:
    with pytest.raises(ValueError):
        _run(tmp_path, source)
