from __future__ import annotations

from core.graph import AgentGraph


def test_graph_process_event_contract_state_and_logs(monkeypatch, sample_events, demo_output):
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
    demo_output(
        "AgentGraph end-to-end trace",
        {
            "event_id": trace["event_id"],
            "story": trace["story"],
            "planner": trace["planner_result"],
            "detection": trace["detection_result"],
            "response": trace["response_result"],
            "latency_ms": trace["trace_metadata"]["latency_ms"],
            "state_recent_count": len(graph.state.recent(5)),
            "trace_log_records": len(traces),
        },
    )


def test_graph_handles_missing_fields_without_crashing(monkeypatch, demo_output):
    monkeypatch.setattr("core.graph.log_trace", lambda trace: None)
    monkeypatch.setattr("agents.response_runtime.log_action", lambda action: None)

    trace = AgentGraph().process_event({"_id": "minimal"})

    assert trace["event_id"] == "minimal"
    assert trace["detection_result"]["verdict"] in {"benign", "suspicious", "malicious"}
    assert trace["response_result"]["status"] in {"skipped", "completed", "dry_run", "pending_remote_execution"}
    demo_output(
        "Minimal event safe defaults",
        {
            "event_id": trace["event_id"],
            "timestamp": trace["timestamp"],
            "verdict": trace["detection_result"]["verdict"],
            "response_status": trace["response_result"]["status"],
        },
    )
