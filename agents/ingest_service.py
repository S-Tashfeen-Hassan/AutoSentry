from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from utils.config import CHECKPOINT_PATH, MAX_EVENTS_PER_RUN, RAW_LOG_PATH, RESET_CHECKPOINT_ON_START


class IngestService:
    def __init__(self, source_path: Path | None = None, checkpoint_path: Path | None = None):
        self.source_path = Path(source_path or RAW_LOG_PATH)
        self.checkpoint_path = Path(checkpoint_path or CHECKPOINT_PATH)
        if RESET_CHECKPOINT_ON_START and self.checkpoint_path.exists():
            self.checkpoint_path.unlink()

    def _load_checkpoint(self) -> Dict[str, int]:
        if not self.checkpoint_path.exists():
            return {"line": 0}
        try:
            return json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"line": 0}

    def _save_checkpoint(self, line_no: int) -> None:
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path.write_text(json.dumps({"line": line_no}), encoding="utf-8")

    def fetch_batch(self, limit: int | None = None) -> List[Dict]:
        limit = limit or MAX_EVENTS_PER_RUN
        if not self.source_path.exists():
            return []

        checkpoint = self._load_checkpoint()
        start_line = max(0, int(checkpoint.get("line", 0)))
        batch: List[Dict] = []
        last_line = start_line

        with self.source_path.open("r", encoding="utf-8") as handle:
            for idx, line in enumerate(handle):
                if idx < start_line:
                    continue
                if len(batch) >= limit:
                    break
                line = line.strip()
                if not line:
                    last_line = idx + 1
                    continue
                try:
                    batch.append(json.loads(line))
                except json.JSONDecodeError:
                    last_line = idx + 1
                    continue
                last_line = idx + 1

        self._save_checkpoint(last_line)
        return batch

    def replay_recent(self, limit: int | None = None) -> List[Dict]:
        limit = limit or MAX_EVENTS_PER_RUN
        if not self.source_path.exists():
            return []
        rows: List[Dict] = []
        with self.source_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows[-limit:]

    def load_all(self) -> List[Dict]:
        if not self.source_path.exists():
            return []
        rows: List[Dict] = []
        with self.source_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    def replay_slice(self, cursor: int, limit: int | None = None) -> tuple[List[Dict], int]:
        limit = limit or MAX_EVENTS_PER_RUN
        rows = self.load_all()
        if not rows:
            return [], 0
        start = max(0, cursor)
        end = min(start + limit, len(rows))
        batch = rows[start:end]
        next_cursor = 0 if end >= len(rows) else end
        return batch, next_cursor
