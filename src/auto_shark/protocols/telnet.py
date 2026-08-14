"""Incremental byte-accurate RFC 854 Telnet record parsing."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Optional

IAC = 255
SE = 240
SB = 250
WILL = 251
WONT = 252
DO = 253
DONT = 254
NEGOTIATION_COMMANDS = frozenset({WILL, WONT, DO, DONT})

TELNET_REQUIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "telnet.data",
)
TELNET_ENDPOINT_FIELDS = ("ip.src", "ipv6.src", "ip.dst", "ipv6.dst")
TELNET_FIELDS = TELNET_REQUIRED_FIELDS[:5] + TELNET_ENDPOINT_FIELDS + TELNET_REQUIRED_FIELDS[5:]


@dataclass(frozen=True)
class TelnetFrame:
    frame_number: int
    time_epoch: str
    frame_length: int
    captured_length: int
    stream_index: int
    source: str
    source_port: int
    destination: str
    destination_port: int


def selected_telnet_fields(available_fields: set[str]) -> tuple[str, ...]:
    return tuple(
        field
        for field in TELNET_FIELDS
        if field in TELNET_REQUIRED_FIELDS or field in available_fields
    )


def parse_telnet_line(
    line: bytes, fields: Optional[tuple[str, ...]] = None
) -> TelnetFrame:
    selected = TELNET_FIELDS if fields is None else fields
    rows = list(
        csv.reader(
            StringIO(line.decode("utf-8", errors="strict")),
            delimiter="\t",
            quotechar='"',
            strict=True,
        )
    )
    if len(rows) != 1 or len(rows[0]) != len(selected):
        actual = len(rows[0]) if rows else 0
        raise ValueError(f"expected {len(selected)} Telnet columns, received {actual}")
    values = dict(zip(selected, rows[0]))
    source = values.get("ip.src", "") or values.get("ipv6.src", "")
    destination = values.get("ip.dst", "") or values.get("ipv6.dst", "")
    if not source or not destination:
        raise ValueError("Telnet row lacks source or destination address")
    return TelnetFrame(
        frame_number=int(values["frame.number"]),
        time_epoch=values["frame.time_epoch"],
        frame_length=int(values["frame.len"]),
        captured_length=int(values["frame.cap_len"]),
        stream_index=int(values["tcp.stream"]),
        source=source,
        source_port=int(values["tcp.srcport"]),
        destination=destination,
        destination_port=int(values["tcp.dstport"]),
    )


def tshark_telnet_arguments(
    executable: Path, capture: Path, *, available_fields: set[str]
) -> list[str]:
    arguments = [
        str(executable),
        "-2",
        "-r",
        str(capture),
        "-Y",
        "telnet",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
        "-E",
        "occurrence=f",
    ]
    for field in selected_telnet_fields(available_fields):
        arguments.extend(("-e", field))
    return arguments


@dataclass(frozen=True)
class TelnetByteRecord:
    kind: str
    start: int
    end: int
    command: Optional[int] = None
    option: Optional[int] = None

    @property
    def byte_length(self) -> int:
        return self.end - self.start


class TelnetParser:
    """Parse arbitrary chunks while retaining absolute source-byte ranges."""

    def __init__(self) -> None:
        self._offset = 0
        self._state = "data"
        self._record_start: Optional[int] = None
        self._command: Optional[int] = None
        self._pending: list[TelnetByteRecord] = []

    @property
    def offset(self) -> int:
        return self._offset

    def _emit(
        self,
        kind: str,
        end: int,
        *,
        command: Optional[int] = None,
        option: Optional[int] = None,
    ) -> None:
        if self._record_start is None or end <= self._record_start:
            raise ValueError("invalid Telnet record range")
        self._pending.append(
            TelnetByteRecord(
                kind=kind,
                start=self._record_start,
                end=end,
                command=command,
                option=option,
            )
        )
        self._record_start = None

    def _flush_data(self, end: int) -> None:
        if self._record_start is not None:
            self._emit("application", end)

    def feed(self, chunk: bytes) -> tuple[TelnetByteRecord, ...]:
        if self._state == "finished":
            raise ValueError("Telnet parser is already finished")
        for value in chunk:
            position = self._offset
            self._offset += 1
            if self._state == "data":
                if value == IAC:
                    self._flush_data(position)
                    self._record_start = position
                    self._state = "iac"
                elif self._record_start is None:
                    self._record_start = position
                continue
            if self._state == "iac":
                if value == IAC:
                    self._emit("application", self._offset)
                    self._state = "data"
                elif value in NEGOTIATION_COMMANDS:
                    self._command = value
                    self._state = "negotiation-option"
                elif value == SB:
                    self._command = value
                    self._state = "subnegotiation-option"
                else:
                    self._emit("command", self._offset, command=value)
                    self._state = "data"
                continue
            if self._state == "negotiation-option":
                self._emit("negotiation", self._offset, command=self._command, option=value)
                self._command = None
                self._state = "data"
                continue
            if self._state == "subnegotiation-option":
                self._command = value
                self._state = "subnegotiation"
                continue
            if self._state == "subnegotiation":
                if value == IAC:
                    self._state = "subnegotiation-iac"
                continue
            if self._state == "subnegotiation-iac":
                if value == SE:
                    self._emit("subnegotiation", self._offset, command=SB, option=self._command)
                    self._command = None
                    self._state = "data"
                elif value == IAC:
                    self._state = "subnegotiation"
                else:
                    self._state = "subnegotiation"
        produced = tuple(self._pending)
        self._pending.clear()
        return produced

    def boundary(self) -> tuple[TelnetByteRecord, ...]:
        """Flush application bytes at a source boundary without breaking IAC state."""
        if self._state == "finished":
            raise ValueError("Telnet parser is already finished")
        if self._state == "data":
            self._flush_data(self._offset)
        produced = tuple(self._pending)
        self._pending.clear()
        return produced

    def finish(self) -> tuple[TelnetByteRecord, ...]:
        if self._state == "finished":
            return ()
        if self._state == "data":
            self._flush_data(self._offset)
        elif self._record_start is not None:
            self._emit("incomplete-control", self._offset, command=self._command)
        self._state = "finished"
        self._command = None
        produced = tuple(self._pending)
        self._pending.clear()
        return produced


def parse_telnet_chunks(chunks: list[bytes]) -> tuple[TelnetByteRecord, ...]:
    parser = TelnetParser()
    records: list[TelnetByteRecord] = []
    for chunk in chunks:
        records.extend(parser.feed(chunk))
    records.extend(parser.finish())
    return tuple(records)
