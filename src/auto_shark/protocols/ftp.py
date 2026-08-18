"""Structured FTP and FTP-DATA records produced by TShark."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from io import StringIO
from pathlib import Path
from typing import Optional

FTP_REQUIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "ftp.response.arg",
    "ftp.passive.ip",
    "ftp.passive.port",
    "ftp-data.setup-frame",
    "ftp-data.setup-method",
    "ftp-data.command-frame",
    "ftp-data.command",
)

FTP_ENDPOINT_FIELDS = ("ip.src", "ipv6.src", "ip.dst", "ipv6.dst")
FTP_FIELDS = FTP_REQUIRED_FIELDS[:5] + FTP_ENDPOINT_FIELDS + FTP_REQUIRED_FIELDS[5:]


def _optional_int(value: str) -> Optional[int]:
    return int(value) if value else None


@dataclass(frozen=True)
class FtpPacket:
    frame_number: int
    time_epoch: str
    frame_length: int
    captured_length: int
    tcp_stream: int
    source: str
    destination: str
    source_port: int
    destination_port: int
    payload_length: int
    kind: str
    request_command: Optional[str]
    request_argument: Optional[str]
    response_code: Optional[int]
    response_argument: Optional[str]
    passive_ip: Optional[str]
    passive_port: Optional[int]
    setup_frame: Optional[int]
    setup_method: Optional[str]
    command_frame: Optional[int]
    data_command: Optional[str]

    @property
    def direction(self) -> str:
        return f"{self.source}:{self.source_port}>{self.destination}:{self.destination_port}"

    def fields(self) -> dict[str, object]:
        return asdict(self)


def selected_ftp_fields(available_fields: set[str]) -> tuple[str, ...]:
    return tuple(
        field for field in FTP_FIELDS if field in FTP_REQUIRED_FIELDS or field in available_fields
    )


def parse_ftp_line(line: bytes, fields: Optional[tuple[str, ...]] = None) -> FtpPacket:
    selected = FTP_FIELDS if fields is None else fields
    text = line.decode("utf-8", errors="strict")
    rows = list(csv.reader(StringIO(text), delimiter="\t", quotechar='"', strict=True))
    if len(rows) != 1 or len(rows[0]) != len(selected):
        actual = len(rows[0]) if rows else 0
        raise ValueError(f"expected {len(selected)} FTP columns, received {actual}")
    values = dict(zip(selected, rows[0]))
    source = values.get("ip.src", "") or values.get("ipv6.src", "")
    destination = values.get("ip.dst", "") or values.get("ipv6.dst", "")
    if not source or not destination:
        raise ValueError("FTP row lacks source or destination address")
    request_command = values["ftp.request.command"] or None
    response_code = _optional_int(values["ftp.response.code"])
    data_command = values["ftp-data.command"] or None
    if data_command or values["ftp-data.setup-frame"] or values["ftp-data.command-frame"]:
        kind = "data"
    elif request_command:
        kind = "request"
    elif response_code is not None or values["ftp.response.arg"]:
        kind = "response"
    else:
        raise ValueError("TShark row is neither FTP control nor FTP-DATA")
    return FtpPacket(
        frame_number=int(values["frame.number"]),
        time_epoch=values["frame.time_epoch"],
        frame_length=int(values["frame.len"]),
        captured_length=int(values["frame.cap_len"]),
        tcp_stream=int(values["tcp.stream"]),
        source=source,
        destination=destination,
        source_port=int(values["tcp.srcport"]),
        destination_port=int(values["tcp.dstport"]),
        payload_length=int(values["tcp.len"] or "0"),
        kind=kind,
        request_command=request_command,
        request_argument=values["ftp.request.arg"] or None,
        response_code=response_code,
        response_argument=values["ftp.response.arg"] or None,
        passive_ip=values["ftp.passive.ip"] or None,
        passive_port=_optional_int(values["ftp.passive.port"]),
        setup_frame=_optional_int(values["ftp-data.setup-frame"]),
        setup_method=values["ftp-data.setup-method"] or None,
        command_frame=_optional_int(values["ftp-data.command-frame"]),
        data_command=data_command,
    )


def tshark_ftp_arguments(
    executable: Path, capture: Path, *, available_fields: set[str]
) -> list[str]:
    arguments = [
        str(executable),
        "-2",
        "-r",
        str(capture),
        "-Y",
        "ftp || ftp-data",
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
    for field in selected_ftp_fields(available_fields):
        arguments.extend(("-e", field))
    return arguments
