from __future__ import annotations

import time
from collections import Counter, deque
from typing import Any, Dict, List, Optional, Tuple


class StateStore:
    def __init__(self, maxlen: int = 1500, suppression_window_seconds: int = 45):
        self._traces = deque(maxlen=maxlen)
        self._source_counts: Counter[str] = Counter()
        self._fingerprint_seen_at: Dict[str, float] = {}
        self._suppression_window_seconds = suppression_window_seconds

    def add_trace(self, trace: Dict[str, Any]) -> None:
        self._traces.appendleft(trace)
        raw_event = trace.get("raw_event", {})
        src_ip = raw_event.get("src_ip")
        if src_ip:
            self._source_counts[src_ip] += 1

    def recent(self, n: int = 50) -> List[Dict[str, Any]]:
        return list(self._traces)[:n]

    def source_frequency(self, src_ip: Optional[str]) -> int:
        if not src_ip:
            return 0
        return self._source_counts[src_ip]

    def should_suppress(self, fingerprint: Optional[str]) -> Tuple[bool, float]:
        if not fingerprint:
            return False, 0.0
        now = time.time()
        last_seen = self._fingerprint_seen_at.get(fingerprint)
        if last_seen is None:
            self._fingerprint_seen_at[fingerprint] = now
            return False, 0.0
        age = now - last_seen
        if age < self._suppression_window_seconds:
            return True, age
        self._fingerprint_seen_at[fingerprint] = now
        return False, age
