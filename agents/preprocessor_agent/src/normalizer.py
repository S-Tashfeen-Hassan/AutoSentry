"""
normalize_event(event: dict) -> dict
Map Suricata/Zeek event dict -> unified 42-field schema.
"""

from datetime import datetime

# List of target fields (42)
TARGET_FIELDS = [
    'spkts', 'dpkts', 'sbytes', 'dbytes', 'sload', 'dload', 'rate',
    'sinpkt', 'dinpkt', 'sjit', 'djit', 'response_body_len', 'sloss', 'dloss',
    'ackdat', 'dur', 'stcpb', 'dtcpb', 'synack', 'tcprtt', 'smean', 'dmean',
    'sttl', 'dttl', 'swin', 'dwin', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_state_ttl',
    'trans_depth', 'proto', 'service', 'state', 'ct_srv_src', 'ct_dst_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'ct_src_ltm',
    'ct_srv_dst', 'is_sm_ips_ports', 'is_ftp_login'
]

def safe_get(d, *keys, default=None):
    """Return the first non-None value found in dict for any of the keys."""
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] is not None:
            return d[k]
    return default

def detect_source(event):
    """Heuristic detection of Suricata vs Zeek logs."""
    if any(k in event for k in ['fileinfo_filename', 'http_http_method', 'alert_signature']):
        return 'suricata'
    if any(k in event for k in ['ts', 'uid', 'id.orig_h', 'id.resp_h']):
        return 'zeek'
    tags = event.get('filebeat_tags') or event.get('tags') or []
    if isinstance(tags, list):
        if 'zeek' in tags: return 'zeek'
        if 'suricata' in tags: return 'suricata'
    return 'unknown'

def compute_mean_bytes_per_pkt(bytes_val, pkts_val):
    """Compute mean bytes per packet safely."""
    try:
        if pkts_val and bytes_val is not None:
            return bytes_val / pkts_val
    except Exception:
        pass
    return 0

def normalize_event(event):
    """Normalize a single Zeek or Suricata event to 42-field schema."""
    src_type = detect_source(event)
    out = {k: 0 for k in TARGET_FIELDS}

    # ---------------------------
    # Packet & byte counts
    # ---------------------------
    out['spkts'] = safe_get(event, 'spkts', 'pkts_toserver', 'pkts_sent', 'flow_pkts_toserver') or 0
    out['dpkts'] = safe_get(event, 'dpkts', 'pkts_toclient', 'pkts_recv', 'flow_pkts_toclient') or 0
    out['sbytes'] = safe_get(event, 'sbytes', 'bytes_toserver', 'bytes_sent', 'flow_bytes_toserver') or 0
    out['dbytes'] = safe_get(event, 'dbytes', 'bytes_toclient', 'bytes_recv', 'flow_bytes_toclient') or 0

    # ---------------------------
    # Load / rate
    # ---------------------------
    out['sload'] = safe_get(event, 'sload') or 0
    out['dload'] = safe_get(event, 'dload') or 0
    out['rate'] = safe_get(event, 'rate') or 0

    # ---------------------------
    # Packet timing / jitter
    # ---------------------------
    out['sinpkt'] = safe_get(event, 'sinpkt') or 0
    out['dinpkt'] = safe_get(event, 'dinpkt') or 0
    out['sjit'] = safe_get(event, 'sjit') or 0
    out['djit'] = safe_get(event, 'djit') or 0

    # ---------------------------
    # Response & loss
    # ---------------------------
    out['response_body_len'] = safe_get(event, 'response_body_len', 'http_response_body_len') or 0
    out['sloss'] = safe_get(event, 'sloss') or 0
    out['dloss'] = safe_get(event, 'dloss') or 0
    out['ackdat'] = safe_get(event, 'ackdat') or 0
    out['synack'] = safe_get(event, 'synack') or 0

    # ---------------------------
    # Duration / TCP bytes
    # ---------------------------
    out['dur'] = safe_get(event, 'duration', 'dur', 'flow_duration') or 0
    out['stcpb'] = safe_get(event, 'stcpb') or 0
    out['dtcpb'] = safe_get(event, 'dtcpb') or 0

    # ---------------------------
    # RTT / mean bytes
    # ---------------------------
    out['tcprtt'] = safe_get(event, 'tcprtt') or 0
    out['smean'] = safe_get(event, 'smean') or compute_mean_bytes_per_pkt(out['sbytes'], out['spkts'])
    out['dmean'] = safe_get(event, 'dmean') or compute_mean_bytes_per_pkt(out['dbytes'], out['dpkts'])

    # ---------------------------
    # TTL / window
    # ---------------------------
    out['sttl'] = safe_get(event, 'sttl') or 0
    out['dttl'] = safe_get(event, 'dttl') or 0
    out['swin'] = safe_get(event, 'swin') or 0
    out['dwin'] = safe_get(event, 'dwin') or 0

    # ---------------------------
    # Other counters / flags
    # ---------------------------
    out['trans_depth'] = safe_get(event, 'trans_depth') or 0
    out['ct_ftp_cmd'] = safe_get(event, 'ct_ftp_cmd') or 0
    out['ct_flw_http_mthd'] = safe_get(event, 'ct_flw_http_mthd') or 0
    out['ct_state_ttl'] = safe_get(event, 'ct_state_ttl') or 0
    out['ct_srv_src'] = safe_get(event, 'ct_srv_src') or 0
    out['ct_dst_ltm'] = safe_get(event, 'ct_dst_ltm') or 0
    out['ct_src_dport_ltm'] = safe_get(event, 'ct_src_dport_ltm') or 0
    out['ct_dst_sport_ltm'] = safe_get(event, 'ct_dst_sport_ltm') or 0
    out['ct_dst_src_ltm'] = safe_get(event, 'ct_dst_src_ltm') or 0
    out['ct_src_ltm'] = safe_get(event, 'ct_src_ltm') or 0
    out['ct_srv_dst'] = safe_get(event, 'ct_srv_dst') or 0

    # ---------------------------
    # Categorical fields
    # ---------------------------
    out['proto'] = safe_get(event, 'proto', 'protocol') or 'unknown'
    out['service'] = safe_get(event, 'service', 'app_proto', 'http_hostname') or 'unknown'
    out['state'] = safe_get(event, 'state', 'conn_state') or 'unknown'

    # ---------------------------
    # Boolean fields
    # ---------------------------
    out['is_sm_ips_ports'] = int(bool(safe_get(event, 'is_sm_ips_ports') or 0))
    out['is_ftp_login'] = int(bool(safe_get(event, 'is_ftp_login') or 0))

    return out
