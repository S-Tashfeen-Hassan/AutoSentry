import os
import requests
import json
import time
from requests.auth import HTTPBasicAuth
from collections import OrderedDict

# === CONFIGURATION ===
GRAYLOG_URL = "https://police-amongst-consolidated-character.trycloudflare.com/api/search/universal/relative"
USERNAME = "admin"
PASSWORD = "pass123!"

# Query both Suricata + Zeek simultaneously
QUERIES = [
    #"filebeat_source:zeek",
    "filebeat_source:suricata"
]

RANGE = 5    # last 5 seconds
LIMIT = 500
VERIFY_SSL = False
INTERVAL = 5   # seconds between each query cycle
# ======================

# Automatically resolve path to data/logs.ndjson
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
OUTFILE = os.path.join(PROJECT_ROOT, "data", "logs.ndjson")

# Unified field order (for Suricata logs)
FIELDS_ORDER = [
    "timestamp", "event_type", "app_proto", "proto",
    "src_ip", "src_port", "dest_ip", "dest_port", "direction",
    "alert_signature_id", "alert_signature", "alert_rev",
    "alert_severity", "alert_action", "alert_category",
    "fileinfo_filename", "fileinfo_size", "fileinfo_state", "fileinfo_stored",
    "http_protocol", "http_hostname", "http_http_method",
    "http_url", "http_status", "http_http_content_type",
    "flow_id", "flow_pkts_toserver", "flow_pkts_toclient",
    "flow_bytes_toserver", "flow_bytes_toclient", "flow_start",
    "source", "filebeat_host_name", "_id"
]


def fetch_graylog(query):
    """Fetch JSON logs from Graylog API."""
    params = {
        "query": query,
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
    """Safely extract nested Suricata fields."""
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
    """Extract and format Suricata logs."""
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
    """Write logs to logs.ndjson."""
    if not logs:
        print("No new logs this round.")
        return

    os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)

    with open(OUTFILE, "a", encoding="utf-8") as f:
        for log in logs:
            f.write(json.dumps(log, ensure_ascii=False) + "\n")

    print(f"Appended {len(logs)} logs to {OUTFILE}")


def main_loop():
    print(f"Starting Graylog fetch loop (every {INTERVAL}s)")

    while True:
        all_logs = []

        # Query both Zeek and Suricata simultaneously
        for q in QUERIES:
            print(f"\n--- Querying: {q} ---")
            data = fetch_graylog(q)

            if not data:
                print(f"No data for query: {q}")
                continue

            for entry in data.get("messages", []):
                raw = entry.get("message", {})

                # ZEEK logs → store raw log directly
                if raw.get("filebeat_source") == "zeek":
                    all_logs.append(raw)

                # SURICATA logs → must be formatted (alert or fileinfo)
                elif raw.get("event_type") in ("alert", "fileinfo"):
                    formatted = extract_logs({"messages": [{"message": raw}]})
                    all_logs.extend(formatted)

                # Ignore others
                else:
                    continue

        # Write all collected logs
        if all_logs:
            write_logs(all_logs)
        else:
            print("No new logs to write this round.")

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main_loop()
