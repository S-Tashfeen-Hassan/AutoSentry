from __future__ import annotations

import json
from typing import Any, Dict, List

from core.state import StateStore
from utils.config import (
    BENIGN_HTTP_PATH_KEYWORDS,
    PLANNER_ESCALATE_THRESHOLD,
    PLANNER_KEYWORDS_HIGH,
    PLANNER_KEYWORDS_MEDIUM,
    PLANNER_RESPONSE_THRESHOLD,
    PLANNER_SKIP_THRESHOLD,
)


class PlannerAgent:
    def __init__(self, state: StateStore):
        self.name = "PlannerAgent"
        self.state = state

    def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        raw = event["raw_event"]
        asset_context = event["asset_context"]
        normalized = event["normalized_features"].get("features", {})

        reasons: List[str] = []
        score = 0.0
        severity = float(raw.get("alert_severity") or 0)
        payload = json.dumps(raw, default=str).lower()

        if raw.get("event_type") == "alert":
            score += 0.26
            reasons.append("suricata_alert")
        if severity:
            severity_boost = max(0.0, (5.0 - severity) * 0.08)
            score += severity_boost
            reasons.append(f"severity_boost:{severity_boost:.2f}")

        for keyword in PLANNER_KEYWORDS_HIGH:
            if keyword in payload:
                score += 0.22
                reasons.append(f"high_signal:{keyword}")
        for keyword in PLANNER_KEYWORDS_MEDIUM:
            if keyword in payload:
                score += 0.08
                reasons.append(f"medium_signal:{keyword}")

        if raw.get("http_url") and any(path in str(raw.get("http_url")) for path in BENIGN_HTTP_PATH_KEYWORDS):
            score -= 0.18
            reasons.append("known_benign_management_path")

        if normalized.get("flow_pkts_toserver", 0) + normalized.get("flow_pkts_toclient", 0) > 120:
            score += 0.14
            reasons.append("high_packet_volume")

        if normalized.get("flow_bytes_toserver", 0) + normalized.get("flow_bytes_toclient", 0) > 200000:
            score += 0.12
            reasons.append("high_byte_volume")

        if asset_context.get("src_ip_role") == "external" and asset_context.get("dest_ip_role") in {"internal", "managed"}:
            score += 0.12
            reasons.append("external_to_protected_asset")

        if asset_context.get("criticality") == "critical":
            score += 0.14
            reasons.append("critical_asset_involved")

        src_ip = raw.get("src_ip")
        src_frequency = self.state.source_frequency(src_ip)
        if src_frequency >= 10:
            score += 0.08
            reasons.append("repeat_offender")

        suppressed, age = self.state.should_suppress(event["normalized_features"].get("feature_fingerprint"))
        if suppressed:
            score -= 0.12
            reasons.append(f"suppressed_duplicate:{age:.1f}s")

        score = max(0.0, min(score, 1.0))

        short_circuit_verdict = None
        recommended_action = "monitor"
        if score <= 0.12:
            short_circuit_verdict = "benign"
        elif any(keyword in payload for keyword in ("sql injection", "compression bomb", "malware", "ransom")):
            short_circuit_verdict = "malicious"
            recommended_action = "block_source_ip_on_firewall"

        if score < PLANNER_SKIP_THRESHOLD and short_circuit_verdict != "malicious":
            route = "skip"
        elif score >= PLANNER_RESPONSE_THRESHOLD or short_circuit_verdict == "malicious":
            route = "propose_response"
        elif score >= PLANNER_ESCALATE_THRESHOLD:
            route = "escalate_llm"
        else:
            route = "fast_detect"

        if score >= 0.82:
            priority = "critical"
        elif score >= 0.62:
            priority = "high"
        elif score >= 0.38:
            priority = "medium"
        else:
            priority = "low"

        return {
            "route": route,
            "priority": priority,
            "score": round(score, 4),
            "reasons": reasons or ["low_signal_event"],
            "short_circuit_verdict": short_circuit_verdict,
            "recommended_action": recommended_action,
        }
