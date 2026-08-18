#!/usr/bin/env python3
"""Generic subprocess adapter that runs a declared tool inside the job output directory.

Contract (argument list only, never a shell):

    cwd_adapter.py <timeout-seconds> <executable> [inner-argument ...] <output-dir>

Auto-Shark substitutes ``{input}`` and ``{output_dir}`` placeholders in the
inner arguments before this adapter starts; the LAST argument must therefore
be the ``{output_dir}`` placeholder so the adapter can use it as the working
directory. Anything the inner tool writes to its current directory lands in
the isolated job output directory, where the Auto-Shark plugin runner hashes
every produced file.

The adapter never parses tool stdout/stderr into structured results. Instead
the inner tool's terminal output is preserved verbatim as ``stdout.txt`` and
``stderr.txt`` inside the job output directory, where the Auto-Shark plugin
runner hashes them like any other produced file; interpreting them stays with
the human. The adapter itself prints nothing on success and exits with the
inner tool's exit code, or 124 when the inner tool exceeds the declared
timeout.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

TIMEOUT_EXIT_CODE = 124


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(
            "usage: cwd_adapter.py <timeout-seconds> <executable> "
            "[inner-argument ...] <output-dir>",
            file=sys.stderr,
        )
        return 2
    try:
        timeout = float(argv[1])
    except ValueError:
        print("error: timeout must be numeric", file=sys.stderr)
        return 2
    if timeout <= 0:
        print("error: timeout must be positive", file=sys.stderr)
        return 2
    def absolutize(argument: str) -> str:
        # Inner tools run with the output directory as their working
        # directory; relative paths must be resolved against OUR cwd first
        # (the remote runner addresses job files relative to the login home).
        looks_like_path = (
            argument.startswith(".") or "/" in argument or "\\" in argument
        )
        if looks_like_path and not os.path.isabs(argument) and os.path.exists(argument):
            return os.path.abspath(argument)
        return argument

    executable = argv[2]
    inner_arguments = [absolutize(item) for item in argv[3:-1]]
    output_directory = Path(absolutize(argv[-1]))
    output_directory.mkdir(parents=True, exist_ok=True)
    try:
        with (output_directory / "stdout.txt").open("wb") as stdout_stream, (
            output_directory / "stderr.txt"
        ).open("wb") as stderr_stream:
            completed = subprocess.run(
                [executable, *inner_arguments],
                cwd=str(output_directory),
                stdin=subprocess.DEVNULL,
                stdout=stdout_stream,
                stderr=stderr_stream,
                timeout=timeout,
                check=False,
            )
    except subprocess.TimeoutExpired:
        return TIMEOUT_EXIT_CODE
    except OSError as error:
        print(f"error: cannot start inner tool: {error}", file=sys.stderr)
        return 2
    return int(completed.returncode)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
