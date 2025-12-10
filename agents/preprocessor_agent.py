import json
import time
import os

TARGET_FIELDS = [
    "spkts", "dpkts", "sbytes", "dbytes", "sload", "dload", "rate",
    "sinpkt", "dinpkt", "sjit", "djit", "response_body_len",
    "sloss", "dloss", "ackdat", "dur", "stcpb", "dtcpb", "synack",
    "tcprtt", "smean", "dmean", "sttl", "dttl", "swin", "dwin",
    "ct_ftp_cmd", "ct_flw_http_mthd", "ct_state_ttl", "trans_depth",
    "proto", "service", "state", "ct_srv_src", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports", "is_ftp_login"
]

# ---------------------------------------------
# Detect log type
# ---------------------------------------------
def detect_log_type(record):
    if "event_type" in record:  
        return "suricata"
    if "messages" in record and isinstance(record["messages"], list):
        return "zeek_wrapper"
    if "ts" in record and "uid" in record:
        return "zeek_native"
    return "unknown"

# ---------------------------------------------
# Extract Zeek message
# ---------------------------------------------
def extract_zeek_log(record):
    if "messages" in record:  # Graylog-wrapped Zeek
        return record["messages"][0]["message"]
    return record  # Native Zeek log already good

# ---------------------------------------------
# MAP → your 42-field schema
# ---------------------------------------------
def normalize_log(record):
    normalized = {}

    # Set default values
    for field in TARGET_FIELDS:
        normalized[field] = 0

    # -----------------------
    # Directional packets/bytes
    # -----------------------
    normalized["spkts"] = record.get("flow_pkts_toserver") or record.get("orig_pkts") or 0
    normalized["dpkts"] = record.get("flow_pkts_toclient") or record.get("resp_pkts") or 0
    normalized["sbytes"] = record.get("flow_bytes_toserver") or record.get("orig_bytes") or 0
    normalized["dbytes"] = record.get("flow_bytes_toclient") or record.get("resp_bytes") or 0

    # -----------------------
    # Load & rate (approximate)
    # -----------------------
    dur = record.get("flow_duration", record.get("duration", 0))
    normalized["dur"] = dur
    normalized["sload"] = normalized["sbytes"] / dur if dur else 0
    normalized["dload"] = normalized["dbytes"] / dur if dur else 0
    normalized["rate"] = (normalized["sload"] + normalized["dload"]) / 2

    # -----------------------
    # Packet-level features
    # -----------------------
    normalized["sinpkt"] = normalized["sbytes"] / normalized["spkts"] if normalized["spkts"] else 0
    normalized["dinpkt"] = normalized["dbytes"] / normalized["dpkts"] if normalized["dpkts"] else 0
    normalized["sjit"] = record.get("sjit") or 0
    normalized["djit"] = record.get("djit") or 0

    # -----------------------
    # Response body / HTTP
    # -----------------------
    normalized["response_body_len"] = record.get("http_resp_len") or record.get("response_body_len") or 0

    # -----------------------
    # Loss / retransmission
    # -----------------------
    normalized["sloss"] = record.get("sloss") or 0
    normalized["dloss"] = record.get("dloss") or 0
    normalized["ackdat"] = record.get("ackdat") or 0

    # -----------------------
    # TCP fields
    # -----------------------
    normalized["stcpb"] = record.get("stcpb") or 0
    normalized["dtcpb"] = record.get("dtcpb") or 0
    normalized["synack"] = record.get("synack") or 0
    normalized["tcprtt"] = record.get("tcprtt") or 0
    normalized["smean"] = record.get("smean") or 0
    normalized["dmean"] = record.get("dmean") or 0
    normalized["sttl"] = record.get("sttl") or 0
    normalized["dttl"] = record.get("dttl") or 0
    normalized["swin"] = record.get("swin") or 0
    normalized["dwin"] = record.get("dwin") or 0

    # -----------------------
    # Protocol / service / state
    # -----------------------
    normalized["proto"] = record.get("proto", "").lower()
    normalized["service"] = record.get("service") or record.get("app_proto") or ""
    normalized["state"] = record.get("conn_state") or ""

    # -----------------------
    # Counters & flags
    # -----------------------
    normalized["ct_ftp_cmd"] = record.get("ct_ftp_cmd") or 0
    normalized["ct_flw_http_mthd"] = 1 if record.get("http_http_method") else 0
    normalized["ct_state_ttl"] = record.get("ct_state_ttl") or 0
    normalized["trans_depth"] = record.get("trans_depth") or 0

    normalized["ct_srv_src"] = record.get("ct_srv_src") or 0
    normalized["ct_dst_ltm"] = record.get("ct_dst_ltm") or 0
    normalized["ct_src_dport_ltm"] = record.get("ct_src_dport_ltm") or 0
    normalized["ct_dst_sport_ltm"] = record.get("ct_dst_sport_ltm") or 0
    normalized["ct_dst_src_ltm"] = record.get("ct_dst_src_ltm") or 0
    normalized["ct_src_ltm"] = record.get("ct_src_ltm") or 0
    normalized["ct_srv_dst"] = record.get("ct_srv_dst") or 0

    # -----------------------
    # Special flags
    # -----------------------
    normalized["is_sm_ips_ports"] = record.get("is_sm_ips_ports") or 0
    normalized["is_ftp_login"] = 1 if record.get("ftp_login_success") else 0

    return normalized


# ---------------------------------------------
# Continuous Tail Reader for NDJSON
# ---------------------------------------------
def follow_ndjson(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as infile, \
         open(output_file, 'w', encoding='utf-8') as outfile:

        for line in infile:
            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                print("Skipping invalid JSON line")
                continue

            # Normalize the log (works for both Zeek and Suricata)
            normalized = normalize_log(raw)

            # Write normalized log to output NDJSON
            outfile.write(json.dumps(normalized, ensure_ascii=False) + "\n")
            outfile.flush()


# ---------------------------------------------
# MAIN
# ---------------------------------------------
if __name__ == "__main__":
    follow_ndjson("../data/logs.ndjson", "../data/normalized_logs.ndjson")
