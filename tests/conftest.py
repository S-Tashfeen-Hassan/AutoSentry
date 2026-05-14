from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest


@pytest.fixture
def sample_events() -> Dict[str, Dict[str, Any]]:
    benign = {
        "_id": "evt-benign",
        "timestamp": "2026-04-14T12:00:00Z",
        "event_type": "fileinfo",
        "app_proto": "http",
        "src_ip": "192.168.56.1",
        "src_port": 52902,
        "dest_ip": "192.168.56.10",
        "dest_port": 9000,
        "http_url": "/api/cluster/metrics/multiple",
        "http_status": 200,
        "fileinfo_filename": "/api/cluster/metrics/multiple",
    }
    malicious = {
        "_id": "evt-mal",
        "timestamp": "2026-04-14T12:02:00Z",
        "event_type": "alert",
        "app_proto": "http",
        "src_ip": "203.0.113.99",
        "src_port": 45444,
        "dest_ip": "192.168.56.1",
        "dest_port": 443,
        "alert_severity": 1,
        "alert_signature": "SQL injection exploit attempt",
        "alert_category": "Web Application Attack",
        "http_url": "/admin/login",
        "flow_pkts_toserver": 180,
        "flow_pkts_toclient": 120,
        "flow_bytes_toserver": 480000,
        "flow_bytes_toclient": 220000,
    }
    suspicious = {
        "_id": "evt-suspicious",
        "timestamp": "2026-04-14T12:03:00Z",
        "event_type": "flow",
        "app_proto": "http",
        "src_ip": "198.51.100.10",
        "dest_ip": "192.168.56.10",
        "dest_port": 8080,
        "http_url": "/api/suspicious-beacon",
        "alert_signature": "suspicious beacon",
        "alert_severity": 4,
        "flow_pkts_toserver": 80,
        "flow_pkts_toclient": 30,
        "flow_bytes_toserver": 60000,
        "flow_bytes_toclient": 20000,
    }
    return {"benign": benign, "malicious": malicious, "suspicious": suspicious}


@pytest.fixture
def asset_file(tmp_path: Path) -> Path:
    path = tmp_path / "managed_assets.json"
    path.write_text(
        json.dumps(
            [
                {
                    "asset_id": "edge-firewall",
                    "hostname": "edge-firewall",
                    "ip": "192.168.56.1",
                    "asset_owner": "network",
                    "os_type": "linux",
                    "criticality": "critical",
                    "allowed_actions": ["block_source_ip_on_firewall", "notify_operator"],
                    "remote_executor_type": "ssh",
                },
                {
                    "asset_id": "app-server",
                    "hostname": "app-server",
                    "ip": "192.168.56.10",
                    "asset_owner": "platform",
                    "os_type": "linux",
                    "criticality": "medium",
                    "allowed_actions": ["block_source_ip_on_host", "quarantine_managed_endpoint", "notify_operator"],
                    "remote_executor_type": "local_powershell",
                },
            ]
        ),
        encoding="utf-8",
    )
    return path
