"""Structured MIME multipart header metadata from TShark."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Optional

MULTIPART_FIELDS = (
    "frame.number",
    "mime_multipart.header.content-disposition",
    "mime_multipart.header.content-type",
)
MULTIPART_AGGREGATOR = "|"
_PARAMETER = re.compile(r"(?:^|;)\s*([A-Za-z0-9_-]+)\s*=\s*(?:\"([^\"]*)\"|([^;]*))")


@dataclass(frozen=True)
class MultipartPartHeader:
    frame_number: int
    ordinal: int
    field_name: Optional[str]
    filename: Optional[str]
    declared_media_type: Optional[str]
    disposition: Optional[str]


def _parameters(disposition: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in _PARAMETER.finditer(disposition):
        value = match.group(2) if match.group(2) is not None else match.group(3)
        result[match.group(1).lower()] = (value or "").strip()
    return result


def parse_multipart_line(line: bytes) -> tuple[MultipartPartHeader, ...]:
    rows = list(
        csv.reader(
            StringIO(line.decode("utf-8", errors="strict")),
            delimiter="\t",
            quotechar='"',
            strict=True,
        )
    )
    if len(rows) != 1 or len(rows[0]) != len(MULTIPART_FIELDS):
        actual = len(rows[0]) if rows else 0
        raise ValueError(
            f"expected {len(MULTIPART_FIELDS)} multipart columns, received {actual}"
        )
    frame_number = int(rows[0][0])
    dispositions = rows[0][1].split(MULTIPART_AGGREGATOR) if rows[0][1] else []
    media_types = rows[0][2].split(MULTIPART_AGGREGATOR) if rows[0][2] else []
    count = max(len(dispositions), len(media_types), 1)
    parts = []
    for ordinal in range(count):
        disposition = dispositions[ordinal] if ordinal < len(dispositions) else ""
        media_type = media_types[ordinal] if ordinal < len(media_types) else ""
        parameters = _parameters(disposition)
        parts.append(
            MultipartPartHeader(
                frame_number=frame_number,
                ordinal=ordinal,
                field_name=parameters.get("name") or None,
                filename=parameters.get("filename") or None,
                declared_media_type=media_type.strip().lower() or None,
                disposition=disposition or None,
            )
        )
    return tuple(parts)


def tshark_multipart_arguments(executable: Path, capture: Path) -> list[str]:
    arguments = [
        str(executable),
        "-r",
        str(capture),
        "-Y",
        "mime_multipart",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "escape=y",
        "-E",
        "occurrence=a",
        "-E",
        f"aggregator={MULTIPART_AGGREGATOR}",
    ]
    for field in MULTIPART_FIELDS:
        arguments.extend(("-e", field))
    return arguments
