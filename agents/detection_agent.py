# agents/detection_agent.py
import json
from utils.llm_client import call_llm

class DetectionAgent:
    def __init__(self, llm_model=None):
        self.name = "DetectionAgent"
        self.llm_model = llm_model

    def _make_prompt(self, log: dict) -> str:
        """
        Strict prompt: ask LLM to output JSON ONLY with fields:
        verdict (malicious|benign), score (0.0-1.0), reasons[], recommended_action
        """
        examples = [
            {
                "example_log": {"message":"SSH failed_login attempt from 1.2.3.4","conn_count":1},
                "example_out": {"verdict":"benign","score":0.12,"reasons":["single failed login, low volume"],"recommended_action":"monitor"}
            },
            {
                "example_log": {"message":"Multiple failed_login and bruteforce pattern from 203.0.113.5","conn_count":120},
                "example_out": {"verdict":"malicious","score":0.93,"reasons":["high connection count","bruteforce pattern"],"recommended_action":"block_ip"}
            }
        ]
        prompt_lines = [
            "You are a concise cybersecurity analyst. Given the single JSON log object below, output JSON ONLY with keys:",
            '  verdict: one of "malicious", "benign", "uncertain"',
            '  score: float between 0.0 and 1.0 (higher means more malicious) and anything above 0.5 including 0.5 is malicious under is benign',
            '  reasons: array of short reasoning strings',
            '  recommended_action: one of "block_ip","notify","monitor"',
            "",
            "Here are examples (do NOT hallucinate beyond the fields):",
        ]
        for ex in examples:
            prompt_lines.append("LOG_EXAMPLE: " + json.dumps(ex["example_log"]))
            prompt_lines.append("OUTPUT_EXAMPLE: " + json.dumps(ex["example_out"]))
        prompt_lines.append("")
        prompt_lines.append("Now analyze this log and return JSON only:")
        prompt_lines.append(json.dumps(log))
        return "\n".join(prompt_lines)

    def analyze(self, log: dict) -> dict:
        prompt = self._make_prompt(log)
        raw = call_llm(prompt, model=self.llm_model)

        parsed = None
        try:
            parsed = json.loads(raw)
        except Exception:
            import re
            m = re.search(r"\{.*\}", raw, flags=re.S)
            if m:
                try:
                    parsed = json.loads(m.group(0))
                except Exception:
                    pass

        if isinstance(parsed, dict) and "score" in parsed:
            score = parsed.get("score", 0.5)
            verdict = parsed.get("verdict", "uncertain").lower()

            if score >= 0.5 and verdict != "malicious":
                parsed["verdict"] = "malicious"
                parsed["recommended_action"] = parsed.get("recommended_action", "block_ip")

            elif score < 0.5 and verdict != "benign":
                parsed["verdict"] = "benign"
                parsed["recommended_action"] = parsed.get("recommended_action", "monitor")

            return parsed

        # fallback if parsing fails entirely
        return {
            "verdict": "uncertain",
            "score": 0.5,
            "reasons": ["llm_parse_failed", str(raw)[:400]],
            "recommended_action": "monitor"
        }
