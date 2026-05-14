from __future__ import annotations

from agents.planner_runtime import PlannerAgent
from agents.preprocessor_runtime import PreprocessorAgent
from core.state import StateStore
from utils.asset_inventory import enrich_asset_context
from utils.schema import build_event_envelope


def _planned(raw_event):
    state = StateStore()
    trace = build_event_envelope(raw_event)
    trace["asset_context"] = enrich_asset_context(raw_event)
    trace["normalized_features"] = PreprocessorAgent().transform(trace)
    return PlannerAgent(state).process(trace)


def test_planner_routes_benign_fast_escalate_and_response(sample_events):
    benign = _planned(sample_events["benign"])
    malicious = _planned(sample_events["malicious"])
    suspicious = _planned(sample_events["suspicious"])

    assert benign["route"] in {"skip", "fast_detect"}
    assert malicious["route"] == "propose_response"
    assert malicious["short_circuit_verdict"] == "malicious"
    assert suspicious["route"] in {"fast_detect", "escalate_llm"}
    assert suspicious["priority"] in {"low", "medium", "high"}


def test_planner_duplicate_suppression_and_repeat_offender(sample_events):
    state = StateStore(suppression_window_seconds=60)
    planner = PlannerAgent(state)
    trace = build_event_envelope(sample_events["suspicious"])
    trace["asset_context"] = enrich_asset_context(sample_events["suspicious"])
    trace["normalized_features"] = PreprocessorAgent().transform(trace)

    first = planner.process(trace)
    duplicate = planner.process(trace)

    assert duplicate["score"] <= first["score"]
    assert any(reason.startswith("suppressed_duplicate") for reason in duplicate["reasons"])

    for _ in range(10):
        state.add_trace(trace)

    repeat = planner.process(trace)
    assert "repeat_offender" in repeat["reasons"]
