"""Decode a bounded hexadecimal stdout stream directly into a binary file."""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional

_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
_SEPARATORS = frozenset(b" \t\r\n:")


@dataclass(frozen=True)
class HexStreamResult:
    argv: tuple[str, ...]
    returncode: int
    decoded_bytes: int
    stderr: bytes
    stderr_truncated: bool
    timed_out: bool
    limit_truncated: bool


def _clean_hex(chunk: bytes) -> bytes:
    invalid = set(chunk) - _HEX_DIGITS - _SEPARATORS
    if invalid:
        rendered = ", ".join(f"0x{value:02x}" for value in sorted(invalid)[:8])
        raise ValueError(f"hex stream contains invalid bytes: {rendered}")
    return bytes(value for value in chunk if value in _HEX_DIGITS)


def _strip_ignored_tokens(
    data: bytes, tokens: tuple[bytes, ...], *, final: bool
) -> tuple[bytes, bytes]:
    if not tokens:
        return data, b""
    output = bytearray()
    index = 0
    while index < len(data):
        token = next((item for item in tokens if data.startswith(item, index)), None)
        if token is not None:
            index += len(token)
            continue
        remainder = data[index:]
        if not final and any(item.startswith(remainder) for item in tokens):
            return bytes(output), remainder
        output.append(data[index])
        index += 1
    return bytes(output), b""


def run_hex_to_file(
    argv: Sequence[str],
    target: BinaryIO,
    *,
    timeout_seconds: float,
    max_decoded_bytes: int,
    stderr_limit: int,
    cwd: Optional[Path] = None,
    environment: Optional[Mapping[str, str]] = None,
    ignored_tokens: tuple[bytes, ...] = (),
) -> HexStreamResult:
    """Run a command and incrementally decode its hexadecimal stdout."""
    if not argv:
        raise ValueError("argv cannot be empty")
    if timeout_seconds <= 0 or max_decoded_bytes <= 0 or stderr_limit < 0:
        raise ValueError("invalid hexadecimal stream limit")
    if any(not token for token in ignored_tokens):
        raise ValueError("ignored hexadecimal stream tokens cannot be empty")
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
    carry = b""
    raw_carry = b""
    decoded_bytes = 0
    limit_truncated = False
    caught: Optional[BaseException] = None
    try:
        while True:
            raw = process.stdout.read(64 * 1024)
            if not raw:
                break
            cleanable, raw_carry = _strip_ignored_tokens(
                raw_carry + raw, ignored_tokens, final=False
            )
            cleaned = carry + _clean_hex(cleanable)
            even_length = len(cleaned) - (len(cleaned) % 2)
            carry = cleaned[even_length:]
            if even_length == 0:
                continue
            decoded = bytes.fromhex(cleaned[:even_length].decode("ascii"))
            remaining = max_decoded_bytes - decoded_bytes
            if len(decoded) > remaining:
                target.write(decoded[:remaining])
                decoded_bytes += remaining
                limit_truncated = True
                process.kill()
                break
            target.write(decoded)
            decoded_bytes += len(decoded)
        cleanable, raw_carry = _strip_ignored_tokens(raw_carry, ignored_tokens, final=True)
        cleaned = carry + _clean_hex(cleanable)
        if cleaned:
            if len(cleaned) % 2:
                raise ValueError("hex stream ended with an incomplete byte")
            decoded = bytes.fromhex(cleaned.decode("ascii"))
            remaining = max_decoded_bytes - decoded_bytes
            if len(decoded) > remaining:
                target.write(decoded[:remaining])
                decoded_bytes += remaining
                limit_truncated = True
            else:
                target.write(decoded)
                decoded_bytes += len(decoded)
        if raw_carry:
            raise ValueError("hex stream ended with an incomplete ignored token")
        process.wait()
    except BaseException as error:
        caught = error
        with suppress(OSError):
            process.kill()
        process.wait()
    finally:
        finished.set()
        stderr_thread.join()
        timeout_thread.join()
        process.stdout.close()
        process.stderr.close()
    if caught is not None:
        raise caught
    return HexStreamResult(
        argv=tuple(str(item) for item in argv),
        returncode=int(process.returncode),
        decoded_bytes=decoded_bytes,
        stderr=bytes(stderr_buffer),
        stderr_truncated=stderr_truncated.is_set(),
        timed_out=timed_out.is_set(),
        limit_truncated=limit_truncated,
    )
