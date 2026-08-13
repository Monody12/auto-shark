"""Streaming subprocess execution without accumulating stdout in memory."""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class StreamProcessResult:
    argv: tuple[str, ...]
    returncode: int
    line_count: int
    stderr: bytes
    stderr_truncated: bool
    timed_out: bool
    output_limit_exceeded: bool


def run_streaming_lines(
    argv: Sequence[str],
    on_line: Callable[[bytes], None],
    *,
    timeout_seconds: float,
    max_line_bytes: int,
    stderr_limit: int,
    cwd: Optional[Path] = None,
    environment: Optional[Mapping[str, str]] = None,
) -> StreamProcessResult:
    """Deliver each stdout line to ``on_line`` and retain only bounded stderr."""
    if not argv:
        raise ValueError("argv cannot be empty")
    if timeout_seconds <= 0 or max_line_bytes <= 0 or stderr_limit < 0:
        raise ValueError("invalid streaming process limit")

    process = subprocess.Popen(
        [str(item) for item in argv],
        cwd=str(cwd) if cwd else None,
        env=dict(environment) if environment is not None else None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert process.stdout is not None and process.stderr is not None
    stderr_buffer = bytearray()
    stderr_truncated = threading.Event()
    output_limit_exceeded = threading.Event()
    timed_out = threading.Event()
    finished = threading.Event()

    def drain_stderr() -> None:
        while True:
            chunk = process.stderr.read(64 * 1024)
            if not chunk:
                return
            remaining = stderr_limit - len(stderr_buffer)
            if remaining > 0:
                stderr_buffer.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                stderr_truncated.set()

    def enforce_timeout() -> None:
        if not finished.wait(timeout_seconds):
            timed_out.set()
            with suppress(OSError):
                process.kill()

    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
    timeout_thread = threading.Thread(target=enforce_timeout, daemon=True)
    stderr_thread.start()
    timeout_thread.start()
    line_count = 0
    callback_error: Optional[BaseException] = None
    try:
        while True:
            line = process.stdout.readline(max_line_bytes + 1)
            if not line:
                break
            if len(line) > max_line_bytes and not line.endswith(b"\n"):
                output_limit_exceeded.set()
                process.kill()
                break
            line_count += 1
            try:
                on_line(line.rstrip(b"\r\n"))
            except BaseException as error:
                callback_error = error
                process.kill()
                break
        process.wait()
    finally:
        finished.set()
        stderr_thread.join()
        timeout_thread.join()
        process.stdout.close()
        process.stderr.close()
    if callback_error is not None:
        raise callback_error
    return StreamProcessResult(
        argv=tuple(str(item) for item in argv),
        returncode=int(process.returncode),
        line_count=line_count,
        stderr=bytes(stderr_buffer),
        stderr_truncated=stderr_truncated.is_set(),
        timed_out=timed_out.is_set(),
        output_limit_exceeded=output_limit_exceeded.is_set(),
    )
