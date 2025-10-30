# utils/db_logger.py
import json
from datetime import datetime
from pathlib import Path

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

def append_jsonl(filename: str, obj: dict):
    p = DATA_DIR / filename
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, default=str) + "\n")

def log_trace(trace: dict):
    trace["logged_at"] = datetime.utcnow().isoformat() + "Z"
    append_jsonl("traces.log", trace)

def log_action(action: dict):
    action["logged_at"] = datetime.utcnow().isoformat() + "Z"
    append_jsonl("actions.log", action)
