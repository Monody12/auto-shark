import base64

from auto_shark.transforms.recognize import decode_recognized


def test_recognizes_base64_and_hex() -> None:
    original = b"D:\\www\\flag.jpg"
    encoded = base64.b64encode(original)
    assert decode_recognized(encoded, max_output_bytes=100).output == original
    assert decode_recognized(b"ffd8ffe000104a46", max_output_bytes=100).output.startswith(
        b"\xff\xd8"
    )


def test_rejects_ambiguous_short_or_oversized_values() -> None:
    assert decode_recognized(b"abcd", max_output_bytes=100) is None
    assert decode_recognized(b"414243444546", max_output_bytes=2) is None
