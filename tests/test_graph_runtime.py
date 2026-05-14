from __future__ import annotations

from core.graph import AgentGraph


def test_graph_process_event_contract_state_and_logs(monkeypatch, sample_events):
    traces = []
    monkeypatch.setattr("core.graph.log_trace", traces.append)
    monkeypatch.setattr("agents.response_runtime.log_action", lambda action: None)

    graph = AgentGraph()
    trace = graph.process_event(sample_events["malicious"])

    assert graph.state.recent(1)[0] == trace
    assert traces == [trace]
    assert trace["story"]["headline"]
    assert trace["trace_metadata"]["latency_ms"] >= 0
    assert trace["trace_metadata"]["processed_at"]
    assert trace["response_result"]["evidence_link"] == trace["event_id"]


def test_graph_handles_missing_fields_without_crashing(monkeypatch):
    monkeypatch.setattr("core.graph.log_trace", lambda trace: None)
    monkeypatch.setattr("agents.response_runtime.log_action", lambda action: None)

    trace = AgentGraph().process_event({"_id": "minimal"})

    assert trace["event_id"] == "minimal"
    assert trace["detection_result"]["verdict"] in {"benign", "suspicious", "malicious"}
    assert trace["response_result"]["status"] in {"skipped", "completed", "dry_run", "pending_remote_execution"}
