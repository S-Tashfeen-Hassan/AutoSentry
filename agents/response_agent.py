# agents/response_agent.py
from datetime import datetime
from utils.db_logger import log_action

class ResponseAgent:
    def __init__(self):
        self.name = "ResponseAgent"

    def execute_action(self, log: dict, action_type: str = "block_ip", reason: str = "") -> dict:
        """
        Simulate executing an action. Returns an action record.
        """
        target = log.get("flow_src_ip") or log.get("source_ip") or log.get("gl2_remote_ip") or log.get("src_ip")
        action = {
            "agent": self.name,
            "action": action_type,
            "target": target,
            "log_id": log.get("_id") or log.get("flow_id"),
            "reason": reason,
            "time": datetime.utcnow().isoformat() + "Z",
            "status": "simulated"
        }
        # Persist to actions.log for demo / audit
        log_action(action)
        return action
