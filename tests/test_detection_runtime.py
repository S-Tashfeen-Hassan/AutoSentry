from __future__ import annotations

import agents.detection_runtime as detection_runtime
from agents.detection_runtime import DetectionAgent


def _event(short_circuit=None, signature="SURICATA SSH invalid banner", features=None, fingerprint="fp"):
    feature_values = {
        "is_alert": 1.0,
        "alert_severity": 2.0,
        "has_http": 0.0,
        "http_status": 0.0,
        "src_port": 50000.0,
        "dest_port": 22.0,
        "flow_pkts_toserver": 5.0,
        "flow_pkts_toclient": 5.0,
        "flow_bytes_toserver": 361.0,
        "flow_bytes_toclient": 352.0,
        "fileinfo_size": 0.0,
        "is_external_source": 1.0,
        "is_internal_destination": 1.0,
        "same_subnet_hint": 0.0,
        "failed_auth_signal": 1.0,
        "scan_signal": 0.0,
        "exploit_signal": 0.0,
        "suspicious_keyword_signal": 0.0,
    }
    if features:
        feature_values.update(features)
    return {
        "raw_event": {"event_type": "alert", "alert_signature": signature},
        "planner_result": {"short_circuit_verdict": short_circuit, "route": "fast_detect", "priority": "medium"},
        "normalized_features": {
            "features": feature_values,
            "feature_vector": list(feature_values.values()),
            "feature_fingerprint": fingerprint,
        },
    }


def test_detection_short_circuits_and_cache_hit():
    agent = DetectionAgent()
    benign = agent.analyze(_event(short_circuit="benign", fingerprint="benign-fp"))
    cached = agent.analyze(_event(short_circuit="benign", fingerprint="benign-fp"))
    malicious = agent.analyze(_event(short_circuit="malicious", fingerprint="mal-fp"))

    assert benign["verdict"] == "benign"
    assert cached["trace_hint"] == "cache_hit"
    assert malicious["verdict"] == "malicious"
    assert malicious["recommended_action"] == "block_source_ip_on_firewall"


def test_detection_hybrid_bands():
    agent = DetectionAgent()

    benign = agent.analyze(
        _event(
            features={"is_alert": 0.0, "alert_severity": 0.0, "failed_auth_signal": 0.0, "http_status": 200.0, "has_http": 1.0},
            fingerprint="hybrid-benign",
        )
    )
    malicious = agent.analyze(
        _event(
            signature="SQL injection exploit attempt",
            features={"exploit_signal": 1.0, "flow_pkts_toserver": 240.0, "flow_bytes_toserver": 300000.0},
            fingerprint="hybrid-malicious",
        )
    )

    assert benign["verdict"] == "benign"
    assert malicious["verdict"] == "malicious"


def test_detection_llm_enrichment_is_mocked(monkeypatch):
    monkeypatch.setattr(detection_runtime, "ENABLE_LLM_ESCALATION", True)
    monkeypatch.setattr(detection_runtime, "DETECTION_LLM_BAND_LOW", 0.0)
    monkeypatch.setattr(detection_runtime, "DETECTION_LLM_BAND_HIGH", 1.0)
    monkeypatch.setattr(detection_runtime, "call_llm", lambda prompt: "Credential abuse suspected")
    agent = DetectionAgent()
    event = _event(fingerprint="llm")
    event["planner_result"]["route"] = "escalate_llm"

    result = agent.analyze(event)

    assert result["method"] == "llm"
    assert "Credential abuse suspected" in result["reasons"]
