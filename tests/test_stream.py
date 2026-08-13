import sys

from auto_shark.engines.stream import run_streaming_lines


def test_streaming_runner_delivers_lines_without_retaining_stdout() -> None:
    lines = []
    result = run_streaming_lines(
        [sys.executable, "-c", "print('one'); print('two')"],
        lines.append,
        timeout_seconds=5,
        max_line_bytes=100,
        stderr_limit=100,
    )
    assert lines == [b"one", b"two"]
    assert result.line_count == 2
    assert result.returncode == 0


def test_streaming_runner_enforces_line_limit() -> None:
    result = run_streaming_lines(
        [sys.executable, "-c", "print('x' * 1000)"],
        lambda line: None,
        timeout_seconds=5,
        max_line_bytes=10,
        stderr_limit=100,
    )
    assert result.output_limit_exceeded


def test_streaming_runner_enforces_timeout() -> None:
    result = run_streaming_lines(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        lambda line: None,
        timeout_seconds=0.1,
        max_line_bytes=100,
        stderr_limit=100,
    )
    assert result.timed_out
