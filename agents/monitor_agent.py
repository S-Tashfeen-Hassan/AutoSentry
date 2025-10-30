import os
import requests
import json
import time
from requests.auth import HTTPBasicAuth
from collections import OrderedDict

# === CONFIGURATION ===
GRAYLOG_URL = "http://192.168.56.10:9000/api/search/universal/relative"
USERNAME = "admin"
PASSWORD = "pass123!"
QUERY = "filebeat_source:suricata AND (event_type:alert OR event_type:fileinfo)"
RANGE = 5    # last 6 seconds
LIMIT = 500
VERIFY_SSL = False
INTERVAL = 5   # seconds between each query
# ======================

# Automatically resolve path to data/logs.ndjson
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
OUTFILE = os.path.join(PROJECT_ROOT, "data", "logs.ndjson")

# Unified field order (works for both alert and fileinfo)
FIELDS_ORDER = [
    # Common metadata
    "timestamp", "event_type", "app_proto", "proto",
    "src_ip", "src_port", "dest_ip", "dest_port", "direction",

    # Alert-specific fields
    "alert_signature_id", "alert_signature", "alert_rev",
    "alert_severity", "alert_action", "alert_category",

    # Fileinfo-specific fields
    "fileinfo_filename", "fileinfo_size", "fileinfo_state", "fileinfo_stored",

    # HTTP-related fields
    "http_protocol", "http_hostname", "http_http_method",
    "http_url", "http_status", "http_http_content_type",

    # Flow-related stats
    "flow_id", "flow_pkts_toserver", "flow_pkts_toclient",
    "flow_bytes_toserver", "flow_bytes_toclient", "flow_start",

    # Sensor/host info
    "source", "filebeat_host_name", "_id"
]


def fetch_graylog():
    """Fetch JSON logs from Graylog API."""
    params = {
        "query": QUERY,
        "range": RANGE,
        "limit": LIMIT,
        "sort": "timestamp:desc"
    }
    headers = {"Accept": "application/json"}

    try:
        resp = requests.get(
            GRAYLOG_URL,
            params=params,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers=headers,
            verify=VERIFY_SSL,
            timeout=30
        )
        if resp.status_code != 200:
            print(f"Graylog returned status {resp.status_code}")
            return None
        return resp.json()
    except requests.RequestException as e:
        print(f"Connection error: {e}")
        return None


def extract_nested(msg, key):
    """Safely extract nested Suricata fields if Graylog didn’t flatten them."""
    if key in msg:
        return msg[key]

    if key.startswith("http_"):
        http = msg.get("http", {})
        return http.get(key.replace("http_", ""))
    if key.startswith("fileinfo_"):
        fileinfo = msg.get("fileinfo", {})
        return fileinfo.get(key.replace("fileinfo_", ""))
    if key.startswith("flow_"):
        flow = msg.get("flow", {})
        return flow.get(key.replace("flow_", ""))
    if key.startswith("alert_"):
        alert = msg.get("alert", {})
        return alert.get(key.replace("alert_", ""))
    return None


def extract_logs(data):
    """Extract and format logs with exact fields and order."""
    if not data or "messages" not in data:
        return []

    messages = data.get("messages", [])
    formatted_logs = []

    for entry in messages:
        msg = entry.get("message", {})
        log = OrderedDict()
        for field in FIELDS_ORDER:
            log[field] = extract_nested(msg, field)
        formatted_logs.append(log)

    alerts = sum(1 for l in formatted_logs if l.get("event_type") == "alert")
    fileinfo = sum(1 for l in formatted_logs if l.get("event_type") == "fileinfo")
    print(f"→ Extracted {len(formatted_logs)} logs ({alerts} alerts, {fileinfo} fileinfo)")
    return formatted_logs


def write_logs(logs):
    """Append logs to logs.ndjson file."""
    if not logs:
        print("No new logs this round.")
        return

    os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
    with open(OUTFILE, "a", encoding="utf-8") as f:
        for log in logs:
            f.write(json.dumps(log, ensure_ascii=False) + "\n")

    print(f"Appended {len(logs)} logs to {OUTFILE}")


def main_loop():
    """Continuously query Graylog every INTERVAL seconds."""
    print(f"Starting Graylog fetch loop (every {INTERVAL}s)")
    while True:
        data = fetch_graylog()
        logs = extract_logs(data)
        write_logs(logs)
        print(f"Waiting {INTERVAL}s...\n")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main_loop()
