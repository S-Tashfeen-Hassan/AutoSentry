from __future__ import annotations

import json

import utils.db_logger as db_logger
from agents.ingest_service import IngestService
from core.graph import AgentGraph


def test_pipeline_smoke_writes_dashboard_compatible_traces(monkeypatch, tmp_path, sample_events):
    raw_path = tmp_path / "logs.ndjson"
    trace_path = tmp_path / "traces.ndjson"
    action_path = tmp_path / "actions.log"
    checkpoint_path = tmp_path / "checkpoint.json"
    raw_path.write_text(
        "\n".join(json.dumps(event) for event in [sample_events["benign"], sample_events["malicious"]]),
        encoding="utf-8",
    )
    monkeypatch.setattr(db_logger, "TRACE_LOG_PATH", trace_path)
    monkeypatch.setattr(db_logger, "ACTION_LOG_PATH", action_path)

    logs = IngestService(raw_path, checkpoint_path).fetch_batch(10)
    results = AgentGraph().process_many(logs)
    persisted = db_logger.read_jsonl(trace_path)

    assert len(results) == 2
    assert len(persisted) == 2
    for trace in persisted:
        assert trace["event_id"]
        assert trace["planner_result"]["route"]
        assert trace["detection_result"]["verdict"]
        assert trace["response_result"]["action"]
        assert trace["trace_metadata"]["trace_id"]
