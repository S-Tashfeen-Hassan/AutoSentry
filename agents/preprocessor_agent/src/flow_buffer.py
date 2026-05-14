"""
FlowBuffer: dynamic-window buffering for event-to-flow conversion.
- ingest(event): add normalized event
- should_flush(): dynamic policy using events/sec and bytes/sec
- flush(): returns list of events to aggregate
"""

import time
from collections import deque

class FlowBuffer:
    def __init__(self, config):
        self.buffer = deque()
        self.bytes_in_window = 0
        self.events_in_window = 0
        self.window_start = time.time()
        # config knobs
        self.min_batch_size = config['dynamic_window']['min_batch_size']
        self.max_batch_size = config['dynamic_window']['max_batch_size']
        self.base_flush_seconds = config['dynamic_window']['base_flush_seconds']
        self.max_flush_seconds = config['dynamic_window']['max_flush_seconds']
        self.high_events_per_sec = config['dynamic_window']['high_traffic_events_per_sec']
        self.low_events_per_sec = config['dynamic_window']['low_traffic_events_per_sec']

    def ingest(self, event):
        # event expected normalized dict and should contain sbytes,dbytes
        self.buffer.append(event)
        self.events_in_window += 1
        self.bytes_in_window += int(event.get('sbytes', 0)) + int(event.get('dbytes', 0))

    def _events_per_sec(self):
        elapsed = max(1e-6, time.time() - self.window_start)
        return self.events_in_window / elapsed

    def _reset_window_stats(self):
        self.window_start = time.time()
        self.events_in_window = 0
        self.bytes_in_window = 0

    def should_flush(self):
        # If buffer empty -> false
        if not self.buffer:
            return False

        # If reached max_batch_size -> flush
        if len(self.buffer) >= self.max_batch_size:
            return True

        # Calculate dynamic flush interval based on events/sec
        eps = self._events_per_sec()

        # High traffic -> shorter flush (but produce larger batch size threshold)
        if eps >= self.high_events_per_sec:
            flush_seconds = max(1, self.base_flush_seconds / 2)
            batch_threshold = min(self.max_batch_size, int(len(self.buffer) * 1.5) or self.min_batch_size)
        elif eps <= self.low_events_per_sec:
            # Low traffic -> longer wait to accumulate
            flush_seconds = min(self.max_flush_seconds, self.base_flush_seconds * 6)
            batch_threshold = max(self.min_batch_size, int(len(self.buffer) * 0.5))
        else:
            # medium traffic
            flush_seconds = self.base_flush_seconds
            batch_threshold = max(self.min_batch_size, int(len(self.buffer) * 1.0))

        # Time-based flush
        if (time.time() - self.window_start) >= flush_seconds and len(self.buffer) >= batch_threshold:
            self._reset_window_stats()
            return True

        # Also flush if we at least have min_batch_size and idle (no new events for base_flush_seconds)
        if len(self.buffer) >= self.min_batch_size and (time.time() - self.window_start) >= self.base_flush_seconds * 2:
            self._reset_window_stats()
            return True

        return False

    def flush(self):
        events = list(self.buffer)
        self.buffer.clear()
        self._reset_window_stats()
        return events
