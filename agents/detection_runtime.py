from __future__ import annotations

import math
from time import time
from typing import Any, Dict, Optional

from utils.config import (
    DETECTION_BENIGN_THRESHOLD,
    DETECTION_LLM_BAND_HIGH,
    DETECTION_LLM_BAND_LOW,
    DETECTION_MALICIOUS_THRESHOLD,
    ENABLE_CONTINUAL_DETECTOR,
    ENABLE_LLM_ESCALATION,
)
from utils.llm_client import call_llm


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


class DetectionAgent:
    def __init__(self) -> None:
        self.name = "DetectionAgent"
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._continual_detector = None
        if ENABLE_CONTINUAL_DETECTOR:
            try:
                from anomaly_detection.continual_detector import ContinualDetector

                self._continual_detector = ContinualDetector()
            except Exception:
                self._continual_detector = None

    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        normalized = event["normalized_features"]
        planner_result = event["planner_result"]
        raw = event["raw_event"]
        fingerprint = normalized.get("feature_fingerprint")

        if fingerprint and fingerprint in self._cache:
            cached = dict(self._cache[fingerprint])
            cached["trace_hint"] = "cache_hit"
            return cached

        short_circuit = planner_result.get("short_circuit_verdict")
        if short_circuit == "benign":
            result = self._build_result(
                verdict="benign",
                score=0.08,
                confidence=0.93,
                method="rule",
                reasons=["planner_short_circuit_benign"],
                recommended_action="monitor",
                evidence={"matched_signature": raw.get("alert_signature"), "model_name": "planner-short-circuit"},
            )
            self._remember(fingerprint, result)
            return result

        if short_circuit == "malicious":
            result = self._build_result(
                verdict="malicious",
                score=0.94,
                confidence=0.95,
                method="rule",
                reasons=["planner_short_circuit_malicious"],
                recommended_action=planner_result.get("recommended_action", "block_source_ip_on_firewall"),
                evidence={"matched_signature": raw.get("alert_signature"), "model_name": "planner-short-circuit"},
            )
            self._remember(fingerprint, result)
            return result

        anomaly_score, anomaly_distance, known_attack = self._anomaly_score(normalized)
        classifier_score = self._classifier_score(normalized, planner_result)
        hybrid_score = round((anomaly_score * 0.55) + (classifier_score * 0.45), 4)
        confidence = round(0.58 + abs(hybrid_score - 0.5) * 0.84, 4)
        reasons = []

        if known_attack:
            reasons.append("known_attack_pattern")
        if normalized["features"]["scan_signal"] > 0:
            reasons.append("scan_signal_detected")
        if normalized["features"]["failed_auth_signal"] > 0:
            reasons.append("auth_anomaly_detected")
        if raw.get("event_type") == "alert":
            reasons.append("alert_event_confirmed")

        if hybrid_score >= DETECTION_MALICIOUS_THRESHOLD:
            verdict = "malicious"
            recommended_action = "block_source_ip_on_firewall"
        elif hybrid_score <= DETECTION_BENIGN_THRESHOLD:
            verdict = "benign"
            recommended_action = "monitor"
        else:
            verdict = "suspicious"
            recommended_action = "notify_operator"

        method = "hybrid"
        llm_reason = None
        if (
            ENABLE_LLM_ESCALATION
            and planner_result.get("route") == "escalate_llm"
            and DETECTION_LLM_BAND_LOW <= hybrid_score <= DETECTION_LLM_BAND_HIGH
        ):
            llm_reason = self._llm_enrichment(raw)
            if llm_reason:
                reasons.append(llm_reason)
                method = "llm"

        result = self._build_result(
            verdict=verdict,
            score=hybrid_score,
            confidence=min(confidence, 0.98),
            method=method,
            reasons=reasons or ["hybrid_model_classification"],
            recommended_action=recommended_action,
            evidence={
                "matched_signature": raw.get("alert_signature"),
                "anomaly_distance": round(anomaly_distance, 4),
                "model_name": "autosentry-hybrid-v2",
                "similar_known_attack": known_attack,
                "classifier_score": round(classifier_score, 4),
                "anomaly_score": round(anomaly_score, 4),
            },
        )
        self._remember(fingerprint, result)
        return result

    def _anomaly_score(self, normalized: Dict[str, Any]) -> tuple[float, float, bool]:
        features = normalized["features"]
        if self._continual_detector:
            try:
                response = self._continual_detector.process_single(normalized["feature_vector"])
                anomaly_distance = float(response.get("normal_score", 0.0))
                known_attack = bool(response.get("is_known_attack"))
                anomaly_score = max(0.0, min(anomaly_distance / 2.5, 1.0))
                return anomaly_score, anomaly_distance, known_attack
            except Exception:
                pass

        anomaly_distance = (
            features["alert_severity"] * 0.18
            + features["failed_auth_signal"] * 0.19
            + features["scan_signal"] * 0.21
            + features["exploit_signal"] * 0.24
            + features["suspicious_keyword_signal"] * 0.17
            + min(features["flow_pkts_toserver"] + features["flow_pkts_toclient"], 240.0) / 240.0 * 0.18
        )
        anomaly_score = max(0.0, min(anomaly_distance / 1.4, 1.0))
        known_attack = features["exploit_signal"] > 0 or features["scan_signal"] > 1
        return anomaly_score, anomaly_distance, known_attack

    def _classifier_score(self, normalized: Dict[str, Any], planner_result: Dict[str, Any]) -> float:
        features = normalized["features"]
        linear = (
            (features["is_alert"] * 1.3)
            + (features["alert_severity"] * 0.9)
            + (features["failed_auth_signal"] * 0.7)
            + (features["scan_signal"] * 0.9)
            + (features["exploit_signal"] * 1.15)
            + (features["suspicious_keyword_signal"] * 0.75)
            + (min(features["flow_bytes_toserver"] + features["flow_bytes_toclient"], 250000.0) / 250000.0 * 0.55)
            + (0.45 if planner_result.get("priority") in {"high", "critical"} else 0.0)
            - (0.65 if features["http_status"] == 200 and features["has_http"] else 0.0)
        )
        return round(_sigmoid(linear - 1.65), 4)

    def _llm_enrichment(self, raw: Dict[str, Any]) -> Optional[str]:
        prompt = (
            "Summarize the main network threat in one short phrase for a SOC dashboard. "
            "Use fewer than 10 words and no markdown.\n"
            f"Log: {raw}"
        )
        try:
            text = call_llm(prompt)
        except Exception:
            return None
        if not text:
            return None
        cleaned = " ".join(str(text).strip().split())
        return cleaned[:120]

    def _build_result(
        self,
        *,
        verdict: str,
        score: float,
        confidence: float,
        method: str,
        reasons: list[str],
        recommended_action: str,
        evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "verdict": verdict,
            "score": round(score, 4),
            "confidence": round(confidence, 4),
            "method": method,
            "reasons": reasons,
            "recommended_action": recommended_action,
            "evidence": evidence,
            "classified_at": time(),
        }

    def _remember(self, fingerprint: Optional[str], result: Dict[str, Any]) -> None:
        if not fingerprint:
            return
        self._cache[fingerprint] = result
