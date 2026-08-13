"""Conservative recognition of common CTF encodings."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Optional

_BASE64 = re.compile(rb"[A-Za-z0-9+/]*={0,2}")
_BASE64URL = re.compile(rb"[A-Za-z0-9_-]*={0,2}")
_HEX = re.compile(rb"[0-9A-Fa-f]+")


@dataclass(frozen=True)
class DecodedValue:
    transform: str
    version: str
    output: bytes
    parameters: dict[str, object]


def _padding(value: bytes) -> bytes:
    return value + b"=" * ((-len(value)) % 4)


def decode_recognized(value: bytes, *, max_output_bytes: int) -> Optional[DecodedValue]:
    """Decode one high-confidence Base64/Base64URL/hex value, or return None."""
    if max_output_bytes <= 0:
        raise ValueError("max output bytes must be positive")
    stripped = value.strip()
    if len(stripped) >= 8 and len(stripped) % 2 == 0 and _HEX.fullmatch(stripped):
        output_length = len(stripped) // 2
        if output_length > max_output_bytes:
            return None
        return DecodedValue(
            transform="hex",
            version="1",
            output=bytes.fromhex(stripped.decode("ascii")),
            parameters={"input_length": len(stripped)},
        )
    if len(stripped) < 8:
        return None
    decoder = None
    name = ""
    if _BASE64.fullmatch(stripped) and (b"+" in stripped or b"/" in stripped or b"=" in stripped):
        decoder = base64.b64decode
        name = "base64"
    elif _BASE64URL.fullmatch(stripped) and (b"-" in stripped or b"_" in stripped):
        decoder = base64.urlsafe_b64decode
        name = "base64url"
    elif _BASE64.fullmatch(stripped) and len(stripped) % 4 == 0:
        decoder = base64.b64decode
        name = "base64"
    if decoder is None:
        return None
    try:
        output = decoder(_padding(stripped))
    except (binascii.Error, ValueError):
        return None
    if not output or len(output) > max_output_bytes:
        return None
    return DecodedValue(
        transform=name,
        version="1",
        output=output,
        parameters={"input_length": len(stripped), "padding_inferred": len(stripped) % 4 != 0},
    )
