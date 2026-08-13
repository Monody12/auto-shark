"""Argument-list subprocess execution with bounded captured output."""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    output_limit_exceeded: bool


def run_bounded(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
    cwd: Optional[Path] = None,
    environment: Optional[Mapping[str, str]] = None,
) -> ProcessResult:
    if not argv:
        raise ValueError("argv cannot be empty")
    if timeout_seconds <= 0 or stdout_limit < 0 or stderr_limit < 0:
        raise ValueError("timeout must be positive and output limits cannot be negative")

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
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    limit_exceeded = threading.Event()

    def drain(name: str, stream: object, limit: int) -> None:
        assert hasattr(stream, "read")
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            remaining = limit - len(buffers[name])
            if remaining > 0:
                buffers[name].extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                truncated[name] = True
                limit_exceeded.set()
                with suppress(OSError):
                    process.kill()

    assert process.stdout is not None and process.stderr is not None
    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout, stdout_limit)),
        threading.Thread(target=drain, args=("stderr", process.stderr, stderr_limit)),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    finally:
        for thread in threads:
            thread.join()
        process.stdout.close()
        process.stderr.close()

    return ProcessResult(
        argv=tuple(str(item) for item in argv),
        returncode=int(process.returncode),
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
        timed_out=timed_out,
        output_limit_exceeded=limit_exceeded.is_set(),
    )
