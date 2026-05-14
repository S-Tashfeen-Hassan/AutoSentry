from __future__ import annotations

import json

import pytest

import agents.preprocessor_runtime as preprocessor_runtime
from agents.preprocessor_runtime import FEATURE_ORDER, PreprocessorAgent


def test_preprocessor_builds_ordered_features_and_keyword_signals(sample_events):
    agent = PreprocessorAgent()
    trace = {"raw_event": sample_events["malicious"]}

    result = agent.transform(trace)

    assert result["feature_order"] == FEATURE_ORDER
    assert len(result["feature_vector"]) == len(FEATURE_ORDER)
    assert result["features"]["is_alert"] == 1.0
    assert result["features"]["is_external_source"] == 1.0
    assert result["features"]["is_internal_destination"] == 1.0
    assert result["features"]["exploit_signal"] > 0
    assert result["feature_summary"]["payload_pressure"] == 700000


def test_preprocessor_coerces_bad_numeric_values_to_zero():
    result = PreprocessorAgent().transform({"raw_event": {"src_port": "nope", "dest_port": None}})

    assert result["features"]["src_port"] == 0.0
    assert result["features"]["dest_port"] == 0.0


def test_preprocessor_rejects_manifest_feature_version_mismatch(monkeypatch, tmp_path):
    manifest = tmp_path / "model_manifest.json"
    manifest.write_text(json.dumps({"feature_version": "old-version"}), encoding="utf-8")
    monkeypatch.setattr(preprocessor_runtime, "MODEL_MANIFEST_PATH", manifest)

    with pytest.raises(RuntimeError, match="Feature version mismatch"):
        PreprocessorAgent()
