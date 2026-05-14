from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from utils.asset_inventory import is_internal_ip
from utils.config import FEATURE_VERSION, MODEL_MANIFEST_PATH
from utils.schema import stable_hash


FEATURE_ORDER = [
    "is_alert",
    "alert_severity",
    "has_http",
    "http_status",
    "src_port",
    "dest_port",
    "flow_pkts_toserver",
    "flow_pkts_toclient",
    "flow_bytes_toserver",
    "flow_bytes_toclient",
    "fileinfo_size",
    "is_external_source",
    "is_internal_destination",
    "same_subnet_hint",
    "failed_auth_signal",
    "scan_signal",
    "exploit_signal",
    "suspicious_keyword_signal",
]


def _to_float(value: Any) -> float:
    try:
        if value in (None, ""):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _keyword_signal(payload: str, keywords: List[str]) -> float:
    lowered = payload.lower()
    return float(sum(1 for keyword in keywords if keyword in lowered))


class PreprocessorAgent:
    def __init__(self) -> None:
        self._validate_model_manifest()

    def _validate_model_manifest(self) -> None:
        manifest_path = Path(MODEL_MANIFEST_PATH)
        if not manifest_path.exists():
            return
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.get("feature_version")
        if expected and expected != FEATURE_VERSION:
            raise RuntimeError(
                f"Feature version mismatch: manifest expects {expected}, runtime provides {FEATURE_VERSION}"
            )

    def transform(self, event: Dict[str, Any]) -> Dict[str, Any]:
        raw = event["raw_event"]
        text_payload = json.dumps(
            {
                "event_type": raw.get("event_type"),
                "alert_signature": raw.get("alert_signature"),
                "alert_category": raw.get("alert_category"),
                "http_url": raw.get("http_url"),
                "fileinfo_filename": raw.get("fileinfo_filename"),
            },
            default=str,
        ).lower()

        src_ip = raw.get("src_ip")
        dest_ip = raw.get("dest_ip")
        features = {
            "is_alert": 1.0 if str(raw.get("event_type", "")).lower() == "alert" else 0.0,
            "alert_severity": max(0.0, 5.0 - _to_float(raw.get("alert_severity"))),
            "has_http": 1.0 if raw.get("http_url") or raw.get("app_proto") == "http" else 0.0,
            "http_status": _to_float(raw.get("http_status")),
            "src_port": _to_float(raw.get("src_port")),
            "dest_port": _to_float(raw.get("dest_port")),
            "flow_pkts_toserver": _to_float(raw.get("flow_pkts_toserver")),
            "flow_pkts_toclient": _to_float(raw.get("flow_pkts_toclient")),
            "flow_bytes_toserver": _to_float(raw.get("flow_bytes_toserver")),
            "flow_bytes_toclient": _to_float(raw.get("flow_bytes_toclient")),
            "fileinfo_size": _to_float(raw.get("fileinfo_size")),
            "is_external_source": 0.0 if is_internal_ip(src_ip) else 1.0,
            "is_internal_destination": 1.0 if is_internal_ip(dest_ip) else 0.0,
            "same_subnet_hint": 1.0 if src_ip and dest_ip and src_ip.split(".")[:3] == dest_ip.split(".")[:3] else 0.0,
            "failed_auth_signal": _keyword_signal(text_payload, ["failed_login", "invalid banner", "auth"]),
            "scan_signal": _keyword_signal(text_payload, ["scan", "sweep", "recon"]),
            "exploit_signal": _keyword_signal(text_payload, ["sql injection", "exploit", "ransom", "malware"]),
            "suspicious_keyword_signal": _keyword_signal(
                text_payload,
                ["suspicious", "compression bomb", "beacon", "shell", "tunnel"],
            ),
        }
        feature_vector = [features[name] for name in FEATURE_ORDER]
        feature_fingerprint = stable_hash(feature_vector)[:16]
        return {
            "feature_version": FEATURE_VERSION,
            "feature_order": FEATURE_ORDER,
            "feature_vector": feature_vector,
            "features": features,
            "feature_fingerprint": feature_fingerprint,
            "feature_summary": {
                "network_pressure": round(
                    features["flow_pkts_toserver"] + features["flow_pkts_toclient"], 2
                ),
                "payload_pressure": round(
                    features["flow_bytes_toserver"] + features["flow_bytes_toclient"], 2
                ),
                "threat_cues": round(
                    features["failed_auth_signal"]
                    + features["scan_signal"]
                    + features["exploit_signal"]
                    + features["suspicious_keyword_signal"],
                    2,
                ),
            },
        }
