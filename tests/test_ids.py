import math

import pytest

from auto_shark.core.ids import EvidenceLocator, candidate_id, evidence_id, stable_id

CAPTURE = "a" * 64


def test_stable_id_is_order_independent_and_namespaced() -> None:
    assert stable_id("test", {"a": 1, "b": 2}) == stable_id("test", {"b": 2, "a": 1})
    assert stable_id("test", {"a": 1}) != stable_id("other", {"a": 1})


def test_stable_id_rejects_noncanonical_nan() -> None:
    with pytest.raises(ValueError):
        stable_id("test", {"value": math.nan})


def test_evidence_id_tracks_byte_location() -> None:
    first = EvidenceLocator(CAPTURE, "http-body", frame_start=10, byte_offset=4, byte_length=8)
    second = EvidenceLocator(CAPTURE, "http-body", frame_start=10, byte_offset=5, byte_length=8)
    assert evidence_id(first) != evidence_id(second)
    assert evidence_id(first) == evidence_id(first)


def test_candidate_id_ignores_supporting_evidence() -> None:
    assert candidate_id("flag", "flag{value}") == candidate_id("flag", "flag{value}")
