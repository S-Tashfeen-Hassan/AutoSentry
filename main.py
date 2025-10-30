# main.py
from core.graph import AgentGraph
from utils.config import LOCAL_LOG_PATH
import json
import time
import re
import os

def follow(file_path, sleep_time=0.5):
    """
    Generator to follow a file continuously.
    Yields new JSON log objects as they are appended.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)  # start at end of file

        while True:
            line = f.readline()
            if not line:
                # EOF reached, sleep before retrying
                time.sleep(sleep_time)
                continue

            line = line.strip()
            if not line:
                continue

            # Extract all JSON objects in case multiple per line
            for match in re.finditer(r"\{.*?\}", line, flags=re.S):
                try:
                    yield json.loads(match.group(0))
                except json.JSONDecodeError:
                    continue

if __name__ == "__main__":
    g = AgentGraph()
    print(f"Live log processing started — following {LOCAL_LOG_PATH}")

    for log in follow(LOCAL_LOG_PATH, sleep_time=0.5):
        result = g.process_many([log])[0]  # process one log at a time
        log_id = result.get("log_id") or "N/A"
        planner_score = result.get("planner", {}).get("score", 0)
        detection_verdict = result.get("detection", {}).get("verdict", "skipped")

        print(f"TRACE: {log_id} | planner_score: {planner_score:.2f} | detection: {detection_verdict}")
        time.sleep(0.05)  # small sleep to avoid spamming output