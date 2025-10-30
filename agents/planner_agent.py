# agents/planner_agent.py
import json
import math
from typing import Dict, Any, List
from utils.config import (
    LOCAL_LOG_PATH, RBF_KEYWORDS, RBF_CONN_COUNT_THRESHOLD, RBF_PKTS_THRESHOLD,
    RBF_BYTES_THRESHOLD, SCORE_THRESHOLD_SUSPICIOUS
)
from utils.db_logger import log_trace
from core.state import StateStore

class PlannerAgent:
    def __init__(self, detector, responder):
        self.name = "PlannerAgent"
        self.detector = detector
        self.responder = responder
        self.state = StateStore()

    def load_logs(self, path: str = LOCAL_LOG_PATH) -> List[Dict[str, Any]]:
        logs = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        logs.append(json.loads(line))
                    except Exception:
                        continue  # skip malformed lines
        except FileNotFoundError:
            return []
        return logs

    def rule_based_check(self, log: Dict[str, Any]) -> Dict[str, Any]:
        score = 0.0
        matched = []
        text = json.dumps(log).lower()

        # --- 1️⃣ Keyword-based heuristic ---
        for kw in RBF_KEYWORDS:
            if kw in text:
                score += 0.25
                matched.append(f"keyword:{kw}")

        # --- 2️⃣ Packet/byte volume heuristic ---
        conn_like = log.get("conn_count") or log.get("flow_pkts_toserver") or log.get("flow_pkts_toclient") or 0
        try:
            conn_like = int(conn_like)
        except Exception:
            conn_like = 0
        if conn_like > RBF_PKTS_THRESHOLD:
            score += 0.3
            matched.append("high_pkts_conn")

        bytes_like = log.get("flow_bytes_toserver") or log.get("flow_bytes_toclient") or 0
        try:
            bytes_like = int(bytes_like)
        except Exception:
            bytes_like = 0
        if bytes_like > RBF_BYTES_THRESHOLD:
            score += 0.2
            matched.append("high_bytes")

        # --- 3️⃣ Signature heuristic ---
        sig = (log.get("alert_signature") or log.get("alert_signature_id") or "").lower()
        if "compression bomb" in sig or "compression" in sig:
            score += 0.6
            matched.append("high_risk_signature")

        # --- 4️⃣ Suricata Alert heuristic (NEW) ---
        event_type = (log.get("event_type") or "").lower()
        if event_type == "alert":
            score += 0.5
            matched.append("event_type:alert")

        # --- Clamp score ---
        score = min(score, 1.0)

        # --- Verdict decision ---
        verdict = "benign"
        if score >= SCORE_THRESHOLD_SUSPICIOUS:
            verdict = "suspicious"
        elif score >= 0.3:
            verdict = "monitor"

        return {"score": score, "matched_rules": matched, "verdict": verdict}

    def process_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        trace = {"log_id": log.get("_id") or log.get("flow_id"), "planner": {}, "detection": None, "response": None}

        # --- Run rule-based check ---
        rbf = self.rule_based_check(log)
        trace["planner"] = rbf

        # Save intermediate state
        self.state.add_trace(trace)

        # --- Pass all suspicious OR Suricata alerts to DetectionAgent ---
        event_type = (log.get("event_type") or "").lower()
        if rbf["verdict"] == "benign" and event_type != "alert":
            trace["detection"] = {"verdict": "skipped", "reason": "rule_based_benign"}
            log_trace(trace)
            return trace

        # --- If suspicious or alert, run DetectionAgent ---
        detection_result = self.detector.analyze(log)
        trace["detection"] = detection_result

        # --- If malicious → trigger ResponseAgent ---
        if detection_result.get("verdict") == "malicious":
            action = self.responder.execute_action(
                log,
                action_type=detection_result.get("recommended_action", "block_ip"),
                reason="auto-detected"
            )
            trace["response"] = action
        else:
            trace["response"] = None

        # --- Persist final trace ---
        log_trace(trace)
        self.state.add_trace(trace)
        return trace
