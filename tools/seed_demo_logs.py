import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = ROOT / "data" / "logs.ndjson"


DEMO_EVENTS = [
    {
        "_id": "demo-mal-sql-001",
        "timestamp": "2026-04-14T20:10:00Z",
        "event_type": "alert",
        "app_proto": "http",
        "proto": "TCP",
        "src_ip": "203.0.113.99",
        "src_port": 45444,
        "dest_ip": "192.168.56.1",
        "dest_port": 443,
        "alert_signature_id": 9001001,
        "alert_signature": "SQL injection exploit attempt",
        "alert_rev": 1,
        "alert_severity": 1,
        "alert_action": "allowed",
        "alert_category": "Web Application Attack",
        "http_protocol": "HTTP/1.1",
        "http_hostname": "autosentry.lab",
        "http_http_method": "POST",
        "http_url": "/admin/login",
        "http_status": 500,
        "http_http_content_type": "application/json",
        "flow_id": 9001001001,
        "flow_pkts_toserver": 180,
        "flow_pkts_toclient": 120,
        "flow_bytes_toserver": 480000,
        "flow_bytes_toclient": 220000,
        "source": "autosentry-demo",
        "filebeat_host_name": "demo-sensor",
    },
    {
        "_id": "demo-mal-brute-002",
        "timestamp": "2026-04-14T20:10:12Z",
        "event_type": "alert",
        "app_proto": "ssh",
        "proto": "TCP",
        "src_ip": "198.51.100.77",
        "src_port": 51100,
        "dest_ip": "192.168.56.10",
        "dest_port": 22,
        "alert_signature_id": 9001002,
        "alert_signature": "SSH bruteforce invalid banner attack",
        "alert_rev": 1,
        "alert_severity": 1,
        "alert_action": "allowed",
        "alert_category": "Attempted Administrator Privilege Gain",
        "flow_id": 9001001002,
        "flow_pkts_toserver": 240,
        "flow_pkts_toclient": 40,
        "flow_bytes_toserver": 350000,
        "flow_bytes_toclient": 40000,
        "source": "autosentry-demo",
        "filebeat_host_name": "demo-sensor",
    },
    {
        "_id": "demo-mal-ransom-003",
        "timestamp": "2026-04-14T20:10:24Z",
        "event_type": "alert",
        "app_proto": "http",
        "proto": "TCP",
        "src_ip": "203.0.113.120",
        "src_port": 60231,
        "dest_ip": "192.168.56.10",
        "dest_port": 9000,
        "alert_signature_id": 9001003,
        "alert_signature": "Ransom malware payload download exploit",
        "alert_rev": 1,
        "alert_severity": 1,
        "alert_action": "allowed",
        "alert_category": "A Network Trojan was detected",
        "http_protocol": "HTTP/1.1",
        "http_hostname": "graylog-node.local",
        "http_http_method": "GET",
        "http_url": "/downloads/payload.bin",
        "http_status": 200,
        "http_http_content_type": "application/octet-stream",
        "fileinfo_filename": "payload.bin",
        "fileinfo_size": 912384,
        "flow_id": 9001001003,
        "flow_pkts_toserver": 96,
        "flow_pkts_toclient": 188,
        "flow_bytes_toserver": 120000,
        "flow_bytes_toclient": 980000,
        "source": "autosentry-demo",
        "filebeat_host_name": "demo-sensor",
    },
]


def main() -> None:
    existing = set()
    if LOG_PATH.exists():
        with LOG_PATH.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    existing.add(json.loads(line).get("_id"))
                except json.JSONDecodeError:
                    continue

    appended = 0
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        for event in DEMO_EVENTS:
            if event["_id"] in existing:
                continue
            handle.write(json.dumps(event) + "\n")
            appended += 1

    print(f"Seeded {appended} demo malicious events into {LOG_PATH}")


if __name__ == "__main__":
    main()
