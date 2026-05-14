from __future__ import annotations

from time import perf_counter
from typing import Dict, List

from agents.detection_runtime import DetectionAgent
from agents.planner_runtime import PlannerAgent
from agents.preprocessor_runtime import PreprocessorAgent
from agents.response_runtime import ResponseAgent
from core.state import StateStore
from utils.asset_inventory import enrich_asset_context
from utils.db_logger import log_trace
from utils.schema import build_event_envelope, utc_now_iso


class AgentGraph:
    def __init__(self):
        self.state = StateStore()
        self.preprocessor = PreprocessorAgent()
        self.detector = DetectionAgent()
        self.responder = ResponseAgent()
        self.planner = PlannerAgent(self.state)

    def process_event(self, raw_event: Dict) -> Dict:
        started = perf_counter()
        trace = build_event_envelope(raw_event)
        trace["asset_context"] = enrich_asset_context(raw_event)
        trace["normalized_features"] = self.preprocessor.transform(trace)
        trace["planner_result"] = self.planner.process(trace)

        route = trace["planner_result"].get("route")
        if route == "skip":
            trace["detection_result"] = {
                "verdict": "benign",
                "score": 0.06,
                "confidence": 0.94,
                "method": "rule",
                "reasons": ["planner_skip"],
                "recommended_action": "monitor",
                "evidence": {"model_name": "planner"},
            }
            trace["response_result"] = self.responder.plan_or_execute(
                trace, trace["detection_result"], trace["asset_context"]
            )
        else:
            trace["detection_result"] = self.detector.analyze(trace)
            trace["response_result"] = self.responder.plan_or_execute(
                trace, trace["detection_result"], trace["asset_context"]
            )

        trace["story"] = self._story(trace)
        trace["trace_metadata"]["latency_ms"] = round((perf_counter() - started) * 1000, 2)
        trace["trace_metadata"]["processed_at"] = utc_now_iso()
        self.state.add_trace(trace)
        log_trace(trace)
        return trace

    def process_many(self, logs: List[Dict]) -> List[Dict]:
        return [self.process_event(log) for log in logs]

    def _story(self, trace: Dict) -> Dict:
        raw = trace["raw_event"]
        detection = trace["detection_result"]
        response = trace["response_result"]
        planner = trace["planner_result"]
        return {
            "headline": f"{raw.get('src_ip', 'unknown')} targeted {raw.get('dest_ip', 'unknown')}",
            "summary": (
                f"{planner.get('priority', 'low').title()} priority event classified as "
                f"{detection.get('verdict', 'unknown')} via {detection.get('method', 'rule')}"
            ),
            "response_moment": response.get("command_summary"),
        }
