"""Structured HTTP metadata records produced by TShark."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from io import StringIO
from pathlib import Path
from typing import Optional

HTTP_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "http.request.method",
    "http.request.uri",
    "http.request.full_uri",
    "http.host",
    "http.response.code",
    "http.response.phrase",
    "http.response_in",
    "http.request_in",
    "http.content_length",
    "http.content_type",
)


def _optional_int(value: str) -> Optional[int]:
    return int(value) if value else None


@dataclass(frozen=True)
class HttpMessage:
    frame_number: int
    time_epoch: str
    frame_length: int
    captured_length: int
    tcp_stream: int
    source: str
    destination: str
    source_port: int
    destination_port: int
    kind: str
    method: Optional[str]
    uri: Optional[str]
    full_uri: Optional[str]
    host: Optional[str]
    response_code: Optional[int]
    response_phrase: Optional[str]
    response_in_frame: Optional[int]
    request_in_frame: Optional[int]
    content_length: Optional[int]
    content_type: Optional[str]

    def fields(self) -> dict[str, object]:
        return asdict(self)


def parse_http_line(line: bytes) -> HttpMessage:
    text = line.decode("utf-8", errors="strict")
    rows = list(csv.reader(StringIO(text), delimiter="\t", quotechar='"', strict=True))
    if len(rows) != 1 or len(rows[0]) != len(HTTP_FIELDS):
        actual = len(rows[0]) if rows else 0
        raise ValueError(f"expected {len(HTTP_FIELDS)} HTTP columns, received {actual}")
    values = dict(zip(HTTP_FIELDS, rows[0]))
    method = values["http.request.method"] or None
    response_code = _optional_int(values["http.response.code"])
    if method:
        kind = "request"
    elif response_code is not None:
        kind = "response"
    else:
        raise ValueError("TShark row is neither an HTTP request nor response")
    source = values["ip.src"] or values["ipv6.src"]
    destination = values["ip.dst"] or values["ipv6.dst"]
    if not source or not destination:
        raise ValueError("HTTP row lacks source or destination address")
    return HttpMessage(
        frame_number=int(values["frame.number"]),
        time_epoch=values["frame.time_epoch"],
        frame_length=int(values["frame.len"]),
        captured_length=int(values["frame.cap_len"]),
        tcp_stream=int(values["tcp.stream"]),
        source=source,
        destination=destination,
        source_port=int(values["tcp.srcport"]),
        destination_port=int(values["tcp.dstport"]),
        kind=kind,
        method=method,
        uri=values["http.request.uri"] or None,
        full_uri=values["http.request.full_uri"] or None,
        host=values["http.host"] or None,
        response_code=response_code,
        response_phrase=values["http.response.phrase"] or None,
        response_in_frame=_optional_int(values["http.response_in"]),
        request_in_frame=_optional_int(values["http.request_in"]),
        content_length=_optional_int(values["http.content_length"]),
        content_type=values["http.content_type"] or None,
    )


def tshark_http_arguments(
    executable: Path, capture: Path, *, preferences: Sequence[str] = ()
) -> list[str]:
    arguments = [
        str(executable),
        "-2",
        "-r",
        str(capture),
        *preferences,
        "-Y",
        "tcp && (http.request || http.response)",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
    ]
    for field in HTTP_FIELDS:
        arguments.extend(("-e", field))
    return arguments
