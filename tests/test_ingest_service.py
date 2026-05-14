from __future__ import annotations

import json

from agents.ingest_service import IngestService


def test_ingest_fetch_batch_skips_bad_lines_and_advances_checkpoint(tmp_path):
    source = tmp_path / "logs.ndjson"
    checkpoint = tmp_path / "checkpoint.json"
    source.write_text(
        "\n".join(
            [
                json.dumps({"_id": "one"}),
                "{bad-json",
                json.dumps({"_id": "two"}),
                json.dumps({"_id": "three"}),
            ]
        ),
        encoding="utf-8",
    )
    ingest = IngestService(source, checkpoint)

    first = ingest.fetch_batch(2)
    second = ingest.fetch_batch(2)

    assert [row["_id"] for row in first] == ["one", "two"]
    assert [row["_id"] for row in second] == ["three"]
    assert json.loads(checkpoint.read_text(encoding="utf-8"))["line"] == 4


def test_ingest_replay_recent_load_all_and_slice(tmp_path):
    source = tmp_path / "logs.ndjson"
    source.write_text(
        "\n".join(json.dumps({"_id": str(index)}) for index in range(4)),
        encoding="utf-8",
    )
    ingest = IngestService(source, tmp_path / "checkpoint.json")

    assert [row["_id"] for row in ingest.replay_recent(2)] == ["2", "3"]
    assert [row["_id"] for row in ingest.load_all()] == ["0", "1", "2", "3"]
    batch, cursor = ingest.replay_slice(3, 3)
    assert [row["_id"] for row in batch] == ["3"]
    assert cursor == 0


def test_ingest_missing_source_returns_empty(tmp_path):
    ingest = IngestService(tmp_path / "missing.ndjson", tmp_path / "checkpoint.json")

    assert ingest.fetch_batch(5) == []
    assert ingest.replay_recent(5) == []
    assert ingest.load_all() == []
