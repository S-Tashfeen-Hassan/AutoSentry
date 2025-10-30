# core/graph.py
from typing import List, Dict
from agents.planner_agent import PlannerAgent
from agents.detection_agent import DetectionAgent
from agents.response_agent import ResponseAgent

class AgentGraph:
    def __init__(self):
        self.detector = DetectionAgent()
        self.responder = ResponseAgent()
        self.planner = PlannerAgent(self.detector, self.responder)

    def process_many(self, logs: List[Dict]) -> List[Dict]:
        results = []
        for l in logs:
            results.append(self.planner.process_log(l))
        return results