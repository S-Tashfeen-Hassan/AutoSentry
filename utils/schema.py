from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from .config import FEATURE_VERSION, PIPELINE_VERSION


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(value: Any) -> str:
    payload = stable_json_dumps(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def derive_timestamp(raw_event: Dict[str, Any]) -> str:
    for key in ("timestamp", "@timestamp", "flow_start", "logged_at"):
        value = raw_event.get(key)
        if value:
            return str(value)
    return utc_now_iso()


def derive_event_id(raw_event: Dict[str, Any]) -> str:
    for key in ("event_id", "_id", "id"):
        value = raw_event.get(key)
        if value:
            return str(value)
    candidate = {
        "timestamp": derive_timestamp(raw_event),
        "src_ip": raw_event.get("src_ip"),
        "dest_ip": raw_event.get("dest_ip"),
        "src_port": raw_event.get("src_port"),
        "dest_port": raw_event.get("dest_port"),
        "event_type": raw_event.get("event_type"),
        "alert_signature": raw_event.get("alert_signature"),
        "flow_id": raw_event.get("flow_id"),
    }
    return stable_hash(candidate)[:16]


def build_event_envelope(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    event = deepcopy(raw_event)
    return {
        "event_id": derive_event_id(event),
        "timestamp": derive_timestamp(event),
        "raw_event": event,
        "normalized_features": {},
        "planner_result": {},
        "detection_result": {},
        "response_result": {},
        "asset_context": {},
        "trace_metadata": {
            "trace_id": str(uuid4()),
            "pipeline_version": PIPELINE_VERSION,
            "feature_version": FEATURE_VERSION,
            "ingested_at": utc_now_iso(),
        },
    }
