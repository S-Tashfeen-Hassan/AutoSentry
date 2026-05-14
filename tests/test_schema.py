from __future__ import annotations

from utils.schema import build_event_envelope, derive_event_id, derive_timestamp, stable_hash


def test_schema_derives_timestamp_id_and_envelope_contract():
    raw = {
        "_id": "abc-123",
        "@timestamp": "2026-04-14T12:00:00Z",
        "src_ip": "192.168.56.10",
        "dest_ip": "203.0.113.5",
    }

    envelope = build_event_envelope(raw)

    assert derive_timestamp(raw) == "2026-04-14T12:00:00Z"
    assert derive_event_id(raw) == "abc-123"
    assert envelope["event_id"] == "abc-123"
    assert envelope["timestamp"] == "2026-04-14T12:00:00Z"
    assert envelope["raw_event"] == raw
    assert envelope["raw_event"] is not raw
    assert envelope["trace_metadata"]["trace_id"]
    assert envelope["trace_metadata"]["pipeline_version"]
    assert envelope["trace_metadata"]["feature_version"]


def test_stable_hash_is_order_insensitive_for_dicts():
    assert stable_hash({"b": 2, "a": 1}) == stable_hash({"a": 1, "b": 2})
