from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .config import ACTION_LOG_PATH, TRACE_LOG_PATH
from .schema import utc_now_iso


def append_jsonl(path: Path, obj: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(obj, default=str) + "\n")


def log_trace(trace: Dict) -> None:
    trace.setdefault("trace_metadata", {})
    trace["trace_metadata"]["logged_at"] = utc_now_iso()
    append_jsonl(TRACE_LOG_PATH, trace)


def log_action(action: Dict) -> None:
    action["logged_at"] = utc_now_iso()
    append_jsonl(ACTION_LOG_PATH, action)


def read_jsonl(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    rows: List[Dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows
