from auto_shark.protocols.multipart import parse_multipart_line, tshark_multipart_arguments


def test_parse_single_and_multiple_multipart_headers() -> None:
    single = parse_multipart_line(
        b'233\t"form-data;name=""upfile"";filename=""flag.jpg"""\t"image/jpeg"'
    )
    assert len(single) == 1
    assert single[0].frame_number == 233
    assert single[0].field_name == "upfile"
    assert single[0].filename == "flag.jpg"
    assert single[0].declared_media_type == "image/jpeg"

    multiple = parse_multipart_line(
        b'5\t"form-data;name=""a""|form-data;name=""b"""\t"text/plain|image/png"'
    )
    assert [(part.ordinal, part.field_name) for part in multiple] == [(0, "a"), (1, "b")]


def test_multipart_arguments_are_header_only() -> None:
    arguments = tshark_multipart_arguments("tshark", "capture.pcap")
    assert "mime_multipart.part" not in arguments
    assert "tcp.payload" not in arguments
    assert "occurrence=a" in arguments
