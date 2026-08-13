import sys

from auto_shark.engines.process import run_bounded


def test_process_runner_captures_output() -> None:
    result = run_bounded(
        [sys.executable, "-c", "print('structured')"],
        timeout_seconds=5,
        stdout_limit=1024,
        stderr_limit=1024,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == b"structured"
    assert not result.timed_out


def test_process_runner_enforces_output_limit() -> None:
    result = run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"],
        timeout_seconds=5,
        stdout_limit=100,
        stderr_limit=100,
    )
    assert result.output_limit_exceeded
    assert result.stdout_truncated
    assert len(result.stdout) == 100


def test_process_runner_enforces_timeout() -> None:
    result = run_bounded(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_seconds=0.1,
        stdout_limit=100,
        stderr_limit=100,
    )
    assert result.timed_out
