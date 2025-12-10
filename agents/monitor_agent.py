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

    os.makedirs(os.path.dirname(OUTFILE), exist_ok=False)
    with open(OUTFILE, "a", encoding="utf-8") as f:
        for log in logs:
            f.write(json.dumps(log, ensure_ascii=False) + "\n")

    print(f"Appended {len(logs)} logs to {OUTFILE}")


def flatten_zeek_wrapper(log):
    """
    Extracts the 'message' dictionary from each entry in a Zeek wrapper log
    (Graylog style) and returns a list of these dictionaries.
    If the log is not a Zeek wrapper, returns [log] as-is.
    """
    if isinstance(log, dict) and "messages" in log:
        flattened = []
        for entry in log["messages"]:
            msg = entry.get("message")
            if msg and isinstance(msg, dict):
                flattened.append(msg)  # Keep the entire 'message' dict as-is
        return flattened
    else:
        # Not a Zeek wrapper, return as a single-item list
        return [log]


INTERVAL = 0        #testing

def main_loop():
    def main_loop():
    """Continuously query Graylog every INTERVAL seconds and process logs by type."""
    print(f"Starting Graylog fetch loop (every {INTERVAL}s)")

    while True:
        data = fetch_graylog()
        if not data:
            print(f"No data fetched. Waiting {INTERVAL}s...\n")
            time.sleep(INTERVAL)
            continue

        all_logs = []

        for raw in data:  # iterate over each top-level log returned from Graylog
            # Detect Zeek wrapper log
            if isinstance(raw, dict) and raw.get("messages") and raw.get("filebeat_source") == "zeek":
                # Flatten Zeek wrapper logs
                zeek_logs = flatten_zeek_wrapper(raw)
                all_logs.extend(zeek_logs)

            # Detect Suricata logs
            elif isinstance(raw, dict) and raw.get("event_type") in ("alert", "fileinfo"):
                formatted_logs = extract_logs({"messages": [{"message": raw}]})
                all_logs.extend(formatted_logs)

            else:
                # Unknown log type, skip
                continue

        # Write all processed logs to file
        if all_logs:
            write_logs(all_logs)
        else:
            print("No new logs to write this round.")

        print(f"Waiting {INTERVAL}s...\n")
        time.sleep(INTERVAL)



if __name__ == "__main__":
    main_loop()