# main.py
from core.graph import AgentGraph
from utils.config import LOCAL_LOG_PATH
import json, time

def load_sample(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []

if __name__ == "__main__":
    g = AgentGraph()
    logs = load_sample(LOCAL_LOG_PATH)
    if not logs:
        print("No logs found at", LOCAL_LOG_PATH)
        exit(0)
    print(f"Loaded {len(logs)} logs — processing sequentially.")
    results = g.process_many(logs)
    for r in results:
        print("TRACE:", r["log_id"], "planner_score:", r["planner"]["score"], "detection:", r.get("detection",{}).get("verdict"))
        time.sleep(0.1)
    print("done.")
