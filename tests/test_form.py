import pytest

from auto_shark.transforms.form import parse_urlencoded_form


def test_form_parser_preserves_order_duplicates_and_offsets() -> None:
    data = b"a=one+two&b=%41%42&a="
    fields = parse_urlencoded_form(data)
    assert [(field.name, field.decoded_value) for field in fields] == [
        ("a", b"one two"),
        ("b", b"AB"),
        ("a", b""),
    ]
    assert data[fields[1].raw_offset : fields[1].raw_offset + fields[1].raw_length] == b"%41%42"


def test_form_parser_enforces_field_limit() -> None:
    with pytest.raises(ValueError, match="field limit"):
        parse_urlencoded_form(b"a=1&b=2", max_fields=1)
