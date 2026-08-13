from auto_shark.search import find_flag_matches, scan_flag_matches


def test_flag_search_finds_chunk_boundary_match_once(tmp_path) -> None:
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"x" * 14 + b"flag{cross-boundary}" + b"y" * 20)
    matches = find_flag_matches(path, chunk_size=16)
    assert [(match.offset, match.value) for match in matches] == [(14, b"flag{cross-boundary}")]


def test_flag_search_ignores_unbounded_or_malformed_text(tmp_path) -> None:
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"flag{} flag{bad\nvalue} " + b"a" * 300)
    assert find_flag_matches(path, chunk_size=8) == []


def test_bounded_flag_scan_reports_truncation_and_limit(tmp_path) -> None:
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"xxflag{one}yyflag{two}tail")
    truncated = scan_flag_matches(path, max_bytes=12, max_matches=10, chunk_size=5)
    assert [(item.offset, item.value) for item in truncated.matches] == [(2, b"flag{one}")]
    assert truncated.scanned_bytes == 12
    assert truncated.input_truncated
    limited = scan_flag_matches(path, max_bytes=100, max_matches=1, chunk_size=64)
    assert [(item.offset, item.value) for item in limited.matches] == [(2, b"flag{one}")]
    assert limited.candidate_limited


def test_bounded_flag_scan_offsets_are_relative_to_selected_slice(tmp_path) -> None:
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"prefixflag{slice}")
    result = scan_flag_matches(path, start_offset=6, max_bytes=11, max_matches=2, chunk_size=4)
    assert [(item.offset, item.value) for item in result.matches] == [(0, b"flag{slice}")]
