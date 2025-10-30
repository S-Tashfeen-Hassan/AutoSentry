# core/state.py
from collections import deque
from typing import Dict, Any

class StateStore:
    def __init__(self, maxlen=1000):
        self._traces = deque(maxlen=maxlen)  # recent traces

    def add_trace(self, trace: Dict[str, Any]):
        self._traces.appendleft(trace)

    def recent(self, n=50):
        return list(self._traces)[:n]
