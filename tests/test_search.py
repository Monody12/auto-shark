from auto_shark.search import find_flag_matches


def test_flag_search_finds_chunk_boundary_match_once(tmp_path) -> None:
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"x" * 14 + b"flag{cross-boundary}" + b"y" * 20)
    matches = find_flag_matches(path, chunk_size=16)
    assert [(match.offset, match.value) for match in matches] == [(14, b"flag{cross-boundary}")]


def test_flag_search_ignores_unbounded_or_malformed_text(tmp_path) -> None:
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"flag{} flag{bad\nvalue} " + b"a" * 300)
    assert find_flag_matches(path, chunk_size=8) == []
