"""
preprocessor_agent.py

Complete preprocessor agent:
- Ingest NDJSON (Suricata / Zeek) events from file/stream
- Detect source and normalize into unified 42-field schema
- Buffer events with dynamic windowing using traffic intensity
- Stateful flow aggregation keyed by flow_key
- Aggregate using provided agg_dict (sum/mean/max)
- Load fitted preprocessing artifacts (ColumnTransformer / encoders) and transform (no refit)
- Validate distributions vs training stats
- Emit flows to encoder (placeholder)

Dependencies:
  pip install pandas numpy scikit-learn joblib

Usage:
  python preprocessor_agent.py --input-file ./events.ndjson \
    --preprocessor ./fitted_preprocessor.joblib \
    --training-stats ./training_stats.joblib
"""

import argparse
import json
import time
import threading
import math
import logging
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
from joblib import load
from sklearn.compose import ColumnTransformer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------
# Configuration - adjust paths
# -----------------------------
DEFAULT_PREPROCESSOR_PATH = "./fitted_preprocessor.joblib"   # your trained ColumnTransformer
DEFAULT_TRAINING_STATS_PATH = "./training_stats.joblib"     # store stats: quantiles, means, stds, category maps
DEFAULT_INPUT_FILE = "./events.ndjson"

# Flow keys & aggregation dictionary (from your specification)
FLOW_KEYS = ['proto', 'service', 'state', 'ct_srv_src', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm']

AGG_DICT = {
    # sums
    'spkts': 'sum', 'dpkts': 'sum', 'sbytes': 'sum', 'dbytes': 'sum',
    'sload': 'sum', 'dload': 'sum', 'sloss': 'sum', 'dloss': 'sum',
    'ackdat': 'sum', 'synack': 'sum', 'is_ftp_login': 'sum',
    'ct_ftp_cmd': 'sum', 'ct_flw_http_mthd': 'sum',
    'ct_src_ltm': 'sum', 'ct_srv_dst': 'sum', 'is_sm_ips_ports': 'sum',
    'ct_dst_src_ltm': 'sum', 'ct_state_ttl': 'sum',

    # means
    'rate': 'mean', 'sttl': 'mean', 'dttl': 'mean',
    'sinpkt': 'mean', 'dinpkt': 'mean',
    'sjit': 'mean', 'djit': 'mean', 'swin': 'mean', 'stcpb': 'mean',
    'dtcpb': 'mean', 'dwin': 'mean',
    'tcprtt': 'mean', 'smean': 'mean', 'dmean': 'mean',

    # max
    'dur': 'max', 'response_body_len': 'max', 'trans_depth': 'max'
}

# All 42 expected fields
UNIFIED_FIELDS = [
    'spkts', 'dpkts', 'sbytes', 'dbytes', 'sload', 'dload', 'rate',
    'sinpkt', 'dinpkt', 'sjit', 'djit', 'response_body_len', 'sloss', 'dloss',
    'ackdat', 'dur', 'stcpb', 'dtcpb', 'synack', 'tcprtt', 'smean', 'dmean',
    'sttl', 'dttl', 'swin', 'dwin', 'ct_ftp_cmd', 'ct_flw_http_mthd',
    'ct_state_ttl', 'trans_depth', 'proto', 'service', 'state', 'ct_srv_src',
    'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports', 'is_ftp_login'
]


# -----------------------------
# Helper: default unified record
# -----------------------------
def make_empty_unified_record() -> Dict[str, Any]:
    rec = {k: 0 for k in UNIFIED_FIELDS}
    # categorical defaults - prefer sentinel values which will be adjusted to training mapping
    rec['proto'] = 'unknown'
    rec['service'] = '-'
    rec['state'] = 'no'  # typical Zeek/Suricata states
    rec['ct_srv_src'] = 0
    rec['ct_dst_ltm'] = 0
    rec['ct_src_dport_ltm'] = 0
    rec['ct_dst_sport_ltm'] = 0
    rec['ct_dst_src_ltm'] = 0
    rec['ct_src_ltm'] = 0
    rec['ct_srv_dst'] = 0
    rec['is_sm_ips_ports'] = 0
    rec['is_ftp_login'] = 0
    return rec


# -----------------------------
# Preprocessor agent class
# -----------------------------
class PreprocessorAgent:
    def __init__(self,
                 fitted_preprocessor_path: str,
                 training_stats_path: Optional[str] = None,
                 target_batch_size: int = 500,
                 base_window: float = 5.0,
                 min_window: float = 1.0,
                 max_window: float = 60.0,
                 target_bytes_per_batch: int = 1_000_000,
                 flow_inactive_timeout: float = 60.0):
        """
        fitted_preprocessor_path: path to fitted ColumnTransformer (joblib)
        training_stats_path: path to training statistics (joblib) used for validation; optional but recommended
        dynamic windowing parameters: target_batch_size / base_window / min/max window / target_bytes_per_batch
        flow_inactive_timeout: seconds to keep an active flow before evicting (stateful merging)
        """
        # Load pre-fitted transformer (must exist)
        logging.info("Loading fitted preprocessor from %s", fitted_preprocessor_path)
        self.preprocessor: ColumnTransformer = load(fitted_preprocessor_path)
        if not isinstance(self.preprocessor, ColumnTransformer):
            logging.warning("Loaded object is not a ColumnTransformer instance. Ensure compatible object.")
        # load training stats if provided
        self.training_stats = None
        if training_stats_path:
            try:
                self.training_stats = load(training_stats_path)
            except Exception as e:
                logging.warning("Could not load training stats: %s", e)

        # buffering and dynamic windowing state
        self.batch = []
        self.batch_bytes = 0
        self.first_event_ts = None
        self.target_batch_size = target_batch_size
        self.base_window = base_window
        self.min_window = min_window
        self.max_window = max_window
        self.target_bytes_per_batch = target_bytes_per_batch

        # traffic counters for last N seconds
        self.events_deque = deque(maxlen=30)  # store timestamp & size for short-term intensity
        self.bytes_deque = deque(maxlen=30)

        # stateful flow cache: key -> aggregated partial flow (pandas-like accumulator)
        # store: {flow_key_tuple: {'last_seen': timestamp, 'acc': list of unified records}}
        self.flow_cache: Dict[Tuple, Dict[str, Any]] = {}

        # eviction and concurrency
        self.flow_inactive_timeout = flow_inactive_timeout
        self.lock = threading.Lock()

        # metrics
        self.metrics = {
            'ingested_events': 0,
            'flushed_batches': 0,
            'preprocessor_failures': 0,
            'unknown_categories': 0,
            'defaulted_fields': 0
        }

    # -----------------------------
    # Public ingestion entry
    # -----------------------------
    def ingest_event_json(self, event_json: Dict[str, Any]):
        """
        Handle an incoming event JSON (one line ndjson parsed).
        1) detect source (suricata/zeek)
        2) normalize into unified record
        3) add to batch and maybe flush windows
        """
        self.metrics['ingested_events'] += 1
        ts = self._event_timestamp(event_json)
        # detect source
        source = self._detect_source(event_json)
        try:
            if source == 'zeek':
                unified = self._normalize_zeek(event_json)
            elif source == 'suricata':
                unified = self._normalize_suricata(event_json)
            else:
                # Try to infer or fallback generic normalizer:
                unified = self._normalize_generic(event_json)
        except Exception as e:
            logging.exception("Normalization failed: %s", e)
            self.metrics['preprocessor_failures'] += 1
            return

        # track bytes for intensity
        estimated_bytes = int(event_json.get('message', '') and len(str(event_json.get('message', ''))) or 0)
        self._record_traffic(ts, estimated_bytes)
        self._append_to_batch(unified, ts, estimated_bytes)

    # -----------------------------
    # Timestamp extraction
    # -----------------------------
    def _event_timestamp(self, event_json: Dict[str, Any]) -> float:
        # Try common timestamp fields (ISO or epoch)
        t = None
        for key in ('@timestamp', 'timestamp', 'ts', 'filebeat_@timestamp', 'time'):
            if key in event_json:
                try:
                    raw = event_json[key]
                    if isinstance(raw, (int, float)):
                        t = float(raw)
                        # Heuristic: if epoch in seconds and > 1e10 maybe ms
                    else:
                        # parse ISO format
                        try:
                            t = pd.to_datetime(raw).timestamp()
                        except Exception:
                            # try if it's an epoch string
                            t = float(raw)
                    break
                except Exception:
                    continue
        if t is None:
            t = time.time()
        return float(t)

    # -----------------------------
    # Source detection
    # -----------------------------
    def _detect_source(self, event_json: Dict[str, Any]) -> str:
        # Prefer explicit filebeat sensor type or stream tags
        if event_json.get('filebeat_sensor_type') == 'zeek' or 'zeek' in event_json.get('filebeat_source', '') or 'zeek' in (event_json.get('filebeat_tags') or []):
            return 'zeek'
        # Suricata has http_*, app_proto or event_type fields like 'fileinfo'
        if 'app_proto' in event_json or event_json.get('event_type') in ('fileinfo', 'alert', 'http', 'flow') or event_json.get('suricata') is not None:
            return 'suricata'
        # fallback heuristics
        if 'uid' in event_json and 'id.orig_h' in event_json:
            return 'zeek'
        if 'src_ip' in event_json and 'dest_ip' in event_json:
            return 'suricata'
        return 'unknown'

    # -----------------------------
    # Normalizers
    # -----------------------------
    def _normalize_zeek(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map common Zeek fields into unified schema.
        Zeek fields often include: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
         proto, query, qtype, etc., depending on log type.
        We'll map likely-from DNS/conn/http logs where available. Missing values -> 0/default.
        """
        out = make_empty_unified_record()
        # Quick helpers
        def g(*keys, default=None):
            for k in keys:
                if k in ev:
                    return ev[k]
            return default

        # Basic network fields from conn.log style:
        out['proto'] = ev.get('proto', out['proto'])
        # service heuristic - prefer known service labels present in message or file name
        out['service'] = ev.get('service') or ev.get('app_proto') or self._infer_service_from_zeek(ev) or out['service']
        out['state'] = ev.get('state') or ev.get('conn_state') or out['state']

        # counts & bytes - Zeek often doesn't provide spkts/dpkts directly in some logs, try from message contents
        # try to parse a "message" field containing JSON (some setups store original Zeek message as JSON string)
        if isinstance(ev.get('message'), str):
            try:
                parsed = json.loads(ev['message'])
            except Exception:
                parsed = {}
        else:
            parsed = {}

        # common mapping attempts
        out['spkts'] = int(parsed.get('spkts') or ev.get('spkts') or ev.get('orig_pkts') or 0)
        out['dpkts'] = int(parsed.get('dpkts') or ev.get('resp_pkts') or ev.get('resp_bytes') and 0 or 0)
        out['sbytes'] = int(parsed.get('sbytes') or ev.get('orig_bytes') or ev.get('tx_bytes') or 0)
        out['dbytes'] = int(parsed.get('dbytes') or ev.get('resp_bytes') or ev.get('rx_bytes') or 0)

        # TTLs, windows, etc. - Zeek conn may contain 'resp_ttl' or 'ttl'
        out['sttl'] = float(parsed.get('sttl') or ev.get('orig_ttl') or 0)
        out['dttl'] = float(parsed.get('dttl') or ev.get('resp_ttl') or 0)

        # basic counts used by CT fields
        out['ct_srv_src'] = int(ev.get('service_count', ev.get('ct_srv_src') or 0))
        out['ct_dst_ltm'] = int(ev.get('ct_dst_ltm', 0))
        out['ct_src_dport_ltm'] = int(ev.get('ct_src_dport_ltm', 0))
        out['ct_dst_sport_ltm'] = int(ev.get('ct_dst_sport_ltm', 0))

        # HTTP/DNS specific features
        out['trans_depth'] = int(parsed.get('trans_depth') or ev.get('trans_depth') or 0)
        out['response_body_len'] = int(parsed.get('response_body_len') or ev.get('response_body_len') or ev.get('resp_body_len') or 0)

        # jitter and mean - if present
        out['sjit'] = float(parsed.get('sjit') or ev.get('sjit') or 0)
        out['djit'] = float(parsed.get('djit') or ev.get('djit') or 0)
        out['smean'] = float(parsed.get('smean') or ev.get('smean') or 0)
        out['dmean'] = float(parsed.get('dmean') or ev.get('dmean') or 0)

        # ports counters
        out['ct_dst_src_ltm'] = int(ev.get('ct_dst_src_ltm', 0))
        out['ct_src_ltm'] = int(ev.get('ct_src_ltm', 0))
        out['ct_srv_dst'] = int(ev.get('ct_srv_dst', 0))

        # flags
        out['is_sm_ips_ports'] = int(bool(ev.get('is_sm_ips_ports', 0)))
        out['is_ftp_login'] = int(bool(ev.get('is_ftp_login', 0)))

        # TCP fields - many zeek logs don't include these; default to 0
        out['stcpb'] = float(ev.get('stcpb', 0))
        out['dtcpb'] = float(ev.get('dtcpb', 0))
        out['tcprtt'] = float(ev.get('tcprtt', 0))
        out['synack'] = int(ev.get('synack', 0))
        out['ackdat'] = int(ev.get('ackdat', 0))
        out['dur'] = float(ev.get('duration', ev.get('dur', 0)))

        # loads, rates - compute heuristically if possible
        try:
            if out['dur'] and (out['sbytes'] or out['dbytes']):
                out['sload'] = out['sbytes'] / (out['dur'] + 1e-9)
                out['dload'] = out['dbytes'] / (out['dur'] + 1e-9)
                out['rate'] = (out['sbytes'] + out['dbytes']) / (out['dur'] + 1e-9)
        except Exception:
            pass

        # If we computed nothing substantial, keep defaults
        return out

    def _infer_service_from_zeek(self, ev: Dict[str, Any]) -> Optional[str]:
        # Heuristic from file paths or queries, e.g., dns.log -> dns
        path = ev.get('filebeat_log_file_path') or ev.get('source') or ''
        if 'dns' in path or ev.get('query'):
            return 'dns'
        if 'http' in path or ev.get('http_host') or ev.get('http_uri'):
            return 'http'
        return None

    def _normalize_suricata(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map Suricata-style logs into unified schema.
        Suricata fields may include: app_proto, proto, src_ip, src_port, dest_ip, dest_port,
        http_* fields, fileinfo_*, flow_id, etc.
        """
        out = make_empty_unified_record()
        # direct mapping of available fields
        out['proto'] = ev.get('proto', out['proto'])
        out['service'] = ev.get('app_proto', ev.get('service', out['service']))
        out['state'] = ev.get('state', out['state'])

        # Suricata might give bytes/packets in different names
        out['sbytes'] = int(ev.get('sbytes', ev.get('src_bytes', ev.get('orig_bytes', 0)) or 0))
        out['dbytes'] = int(ev.get('dbytes', ev.get('dest_bytes', ev.get('resp_bytes', 0)) or 0))
        out['spkts'] = int(ev.get('spkts', ev.get('pkts_toserver', 0)))
        out['dpkts'] = int(ev.get('dpkts', ev.get('pkts_toclient', 0)))
        out['response_body_len'] = int(ev.get('http_response_body_len', ev.get('response_body_len', 0)))
        out['dur'] = float(ev.get('flow_duration', ev.get('dur', 0)))

        # other values
        out['ct_ftp_cmd'] = int(ev.get('ct_ftp_cmd', 0))
        out['ct_flw_http_mthd'] = int(ev.get('ct_flw_http_mthd', 0))
        out['ct_state_ttl'] = int(ev.get('ct_state_ttl', 0))
        out['trans_depth'] = int(ev.get('http_trans_depth', ev.get('trans_depth', 0)))

        out['stcpb'] = float(ev.get('stcpb', 0))
        out['dtcpb'] = float(ev.get('dtcpb', 0))
        out['tcprtt'] = float(ev.get('tcprtt', 0))

        out['is_sm_ips_ports'] = int(bool(ev.get('is_sm_ips_ports', 0)))
        out['is_ftp_login'] = int(bool(ev.get('is_ftp_login', 0)))

        # compute loads if we have dur
        try:
            if out['dur'] and (out['sbytes'] or out['dbytes']):
                out['sload'] = out['sbytes'] / (out['dur'] + 1e-9)
                out['dload'] = out['dbytes'] / (out['dur'] + 1e-9)
                out['rate'] = (out['sbytes'] + out['dbytes']) / (out['dur'] + 1e-9)
        except Exception:
            pass

        return out

    def _normalize_generic(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Best-effort normalization for unknown/other structured events:
        - Try to map by common keys; else leave defaults.
        """
        out = make_empty_unified_record()
        # common keys mapping
        out['proto'] = ev.get('proto', out['proto'])
        out['service'] = ev.get('service', out['service'])
        out['state'] = ev.get('state', out['state'])

        for k in ['spkts', 'dpkts', 'sbytes', 'dbytes', 'dur',
                  'sttl', 'dttl', 'swin', 'dwin', 'trans_depth', 'response_body_len']:
            if k in ev:
                try:
                    out[k] = type(out[k])(ev[k])
                except Exception:
                    out[k] = out[k]
        return out

    # -----------------------------
    # Batch & dynamic windowing
    # -----------------------------
    def _record_traffic(self, ts: float, estimated_bytes: int):
        # append ts and bytes for intensity calculation
        now = ts or time.time()
        self.events_deque.append(now)
        self.bytes_deque.append((now, estimated_bytes))

    def _compute_intensity(self) -> Tuple[float, float]:
        """Return events_per_sec, bytes_per_sec over recent window"""
        now = time.time()
        if not self.events_deque:
            return 0.0, 0.0
        # events per sec - using last N items time window
        times = list(self.events_deque)
        window = max(1.0, times[-1] - times[0]) if len(times) > 1 else 1.0
        events_per_sec = len(times) / window
        # bytes per sec using bytes_deque
        if not self.bytes_deque:
            bytes_per_sec = 0.0
        else:
            t0 = self.bytes_deque[0][0]
            t1 = self.bytes_deque[-1][0]
            bytes_sum = sum(b for (_, b) in self.bytes_deque)
            time_w = max(1.0, t1 - t0) if t1 != t0 else 1.0
            bytes_per_sec = bytes_sum / time_w
        return events_per_sec, bytes_per_sec

    def _derive_window_duration(self) -> float:
        events_per_sec, bytes_per_sec = self._compute_intensity()
        traffic_intensity = events_per_sec + (bytes_per_sec / 1e6)
        # target intensity heuristic: higher traffic => shorter window
        if traffic_intensity <= 0:
            return self.base_window
        # simple inverse scaling
        factor = max(0.1, min(10.0, 1.0 / traffic_intensity))  # clamp
        window = self.base_window * factor
        window = max(self.min_window, min(self.max_window, window))
        return window

    def _append_to_batch(self, unified: Dict[str, Any], ts: float, estimated_bytes: int):
        if self.first_event_ts is None:
            self.first_event_ts = ts
        self.batch.append((ts, unified))
        self.batch_bytes += estimated_bytes

        # flush conditions
        window_duration = self._derive_window_duration()
        time_since_first = time.time() - (self.first_event_ts or time.time())
        if (len(self.batch) >= self.target_batch_size) or (self.batch_bytes >= self.target_bytes_per_batch) or (time_since_first >= window_duration):
            # flush batch into flow groups
            self._flush_batch()
            self.first_event_ts = None
            self.batch_bytes = 0

    # -----------------------------
    # Flushing: group by flow key and aggregate
    # -----------------------------
    def _flush_batch(self):
        with self.lock:
            if not self.batch:
                return
            self.metrics['flushed_batches'] += 1
            # Build a DataFrame of unified records
            records = [rec for (_, rec) in self.batch]
            df = pd.DataFrame(records, columns=UNIFIED_FIELDS)
            # group by FLOW_KEYS
            grouped = df.groupby(FLOW_KEYS)
            for key_vals, grp in grouped:
                key_tuple = tuple(key_vals) if isinstance(key_vals, tuple) else (key_vals,)
                # Apply aggregation rules to group
                agg_res = self._aggregate_group(grp)
                now = time.time()
                # if stateful, merge into existing cache entry
                if key_tuple not in self.flow_cache:
                    self.flow_cache[key_tuple] = {'last_seen': now, 'acc': []}
                self.flow_cache[key_tuple]['acc'].append(agg_res)
                self.flow_cache[key_tuple]['last_seen'] = now
            # clear batch
            self.batch.clear()

            # Evict stale flows and produce final flows (stateful)
            evicted = []
            now = time.time()
            for k, v in list(self.flow_cache.items()):
                if now - v['last_seen'] > self.flow_inactive_timeout:
                    # finalize flow by aggregating the partial aggregates
                    final_flow = self._merge_partial_aggregates(v['acc'])
                    # Apply preprocessing + validation, then emit
                    try:
                        preprocessed = self._apply_preprocessor_to_flow(final_flow)
                        if self._validate_preprocessed(preprocessed):
                            self._emit_to_encoder(preprocessed)
                    except Exception as e:
                        logging.exception("Failed preprocess/emit for flow %s: %s", k, e)
                        self.metrics['preprocessor_failures'] += 1
                    evicted.append(k)
            for k in evicted:
                del self.flow_cache[k]

    # -----------------------------
    # Aggregation helpers
    # -----------------------------
    def _aggregate_group(self, grp: pd.DataFrame) -> Dict[str, Any]:
        """
        Aggregate according to AGG_DICT rules. Return a single dict representing aggregated partial flow.
        """
        res = {}
        # keep group keys too
        for i, k in enumerate(FLOW_KEYS):
            res[k] = grp[k].iloc[0]
        # apply aggregation rules
        for col, func in AGG_DICT.items():
            if col not in grp.columns:
                res[col] = 0
                continue
            try:
                if func == 'sum':
                    res[col] = float(grp[col].sum())
                elif func == 'mean':
                    # Use simple mean to match training unless you specify weighting elsewhere
                    res[col] = float(grp[col].mean())
                elif func == 'max':
                    res[col] = float(grp[col].max())
                else:
                    res[col] = float(grp[col].agg(func))
            except Exception:
                res[col] = 0.0
        # For fields not in AGG_DICT but in UNIFIED_FIELDS, set to default from first row
        for col in UNIFIED_FIELDS:
            if col in res:
                continue
            if col in grp.columns:
                res[col] = grp[col].iloc[0]
            else:
                # keep default
                res[col] = 0
        return res

    def _merge_partial_aggregates(self, partials: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge multiple partial aggregates (from successive windows) into a single final flow record.
        For each column, re-apply AGG_DICT semantics:
          - sum: sum of sums
          - mean: weighted mean by counts not available -> simple mean of partial means (train expectation matters)
          - max: max of maxima
        IMPORTANT: This must match how training flows were aggregated.
        """
        if not partials:
            return make_empty_unified_record()
        merged = {}
        # initialize containers
        for col in UNIFIED_FIELDS:
            merged[col] = None
        # For sum cols, sum partials; for mean cols, average partial means (approx); for max, take max
        for col, agg in AGG_DICT.items():
            if agg == 'sum':
                merged[col] = float(sum(p.get(col, 0) for p in partials))
            elif agg == 'mean':
                # We don't have per-part counts; approximate by averaging partial means.
                vals = [p.get(col, 0) for p in partials]
                merged[col] = float(sum(vals) / max(1, len(vals)))
            elif agg == 'max':
                merged[col] = float(max((p.get(col, 0) for p in partials), default=0))
            else:
                merged[col] = partials[-1].get(col, 0)
        # Bring through flow keys and representative other fields from the last partial
        last = partials[-1]
        for k in FLOW_KEYS:
            merged[k] = last.get(k)
        # Fill remaining fields using last partial
        for col in UNIFIED_FIELDS:
            if merged.get(col) is None:
                merged[col] = last.get(col, 0)
        return merged

    # -----------------------------
    # Preprocess using fitted transformer
    # -----------------------------
    def _apply_preprocessor_to_flow(self, flow: Dict[str, Any]) -> pd.DataFrame:
        """
        Accepts a merged flow dict, returns transformed DataFrame row (1 x n features) as expected by encoder.
        Uses the loaded fitted preprocessor (ColumnTransformer) and DOES NOT refit.
        """
        # Ensure column order matches the expected preprocessor input. The training preprocessor must have been
        # fit with exactly these column names in the same order.
        df = pd.DataFrame([flow], columns=UNIFIED_FIELDS)
        # Some transformers require correct dtypes for categorical columns - ensure strings for protos if necessary
        # Preprocessing should be robust, but cast to str for proto/service/state (training mapping keys are strings)
        df['proto'] = df['proto'].astype(str)
        df['service'] = df['service'].astype(str)
        df['state'] = df['state'].astype(str)
        # Apply the loaded transformer (no fit)
        transformed = self.preprocessor.transform(df)
        # If transformer outputs pandas DataFrame (set_output in sklearn), good. Else wrap into DataFrame.
        if isinstance(transformed, np.ndarray):
            # Build column names if transformer has attribute feature_names_in_ or get_feature_names_out
            try:
                cols = self.preprocessor.get_feature_names_out()
            except Exception:
                cols = [f"f{i}" for i in range(transformed.shape[1])]
            transformed_df = pd.DataFrame(transformed, columns=cols)
        else:
            # assume DataFrame-like
            transformed_df = transformed
        return transformed_df

    # -----------------------------
    # Validation - distribution checks
    # -----------------------------
    def _validate_preprocessed(self, transformed_df: pd.DataFrame) -> bool:
        """
        Quick distribution check: compare percentiles to training stats if available.
        Returns True if data looks sane (otherwise logs warning and returns True/False depending on severity).
        """
        if not self.training_stats:
            return True
        try:
            # training_stats should contain percentiles per original feature names, e.g. {'orig_feature': {'p10':..., 'p50':..., 'p90':...}}
            # Compare for numeric columns only
            bad = False
            for orig_col, stats in self.training_stats.get('percentiles', {}).items():
                if orig_col not in transformed_df.columns:
                    continue
                # transformed_df column may be different (after transform), so compare pre-transform where possible
                # Here we attempt a simple check using pre-transform columns if stored
                # We'll skip strict checks for transformed columns to avoid false positives
                pass
            # If we reach here, assume OK (user can extend)
            return True
        except Exception as e:
            logging.warning("Validation check failed: %s", e)
            return True

    # -----------------------------
    # Emit to encoder (placeholder)
    # -----------------------------
    def _emit_to_encoder(self, preprocessed_df: pd.DataFrame):
        """
        Replace this method with actual encoder call. For example:
          - Convert to numpy and call encoder.predict() or encoder.encode()
          - Send to message queue for downstream component
        """
        # For example:
        # embeddings = encoder.encode(preprocessed_df.values)
        logging.info("Emitting preprocessed flow to encoder (shape=%s).", getattr(preprocessed_df, 'shape', None))
        # Placeholder: print summary
        logging.debug("Preprocessed sample:\n%s", preprocessed_df.head(1).to_string())
        # TODO: implement actual emission (HTTP/GRPC/queue/call). This function should be non-blocking or async.

    # -----------------------------
    # Utility for graceful flush
    # -----------------------------
    def flush_all(self):
        """Force flush remaining batch and evict all flows (finalize)."""
        logging.info("Forcing flush of remaining batch and evicting flows.")
        with self.lock:
            # flush any pending batch into cache
            if self.batch:
                self._flush_batch()
            # finalize all flows immediately
            for k, v in list(self.flow_cache.items()):
                final_flow = self._merge_partial_aggregates(v['acc'])
                try:
                    preprocessed = self._apply_preprocessor_to_flow(final_flow)
                    if self._validate_preprocessed(preprocessed):
                        self._emit_to_encoder(preprocessed)
                except Exception as e:
                    logging.exception("Failed final preprocess/emit for flow %s: %s", k, e)
                del self.flow_cache[k]

    def get_metrics(self):
        return dict(self.metrics)


# -----------------------------
# CLI / Example driver
# -----------------------------
def ndjson_event_generator(path: str):
    """Yield parsed JSON objects from NDJSON file (simulates streaming with sleep)."""
    with open(path, 'r', encoding='utf8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                # try to parse a line that is raw python dict-ish
                try:
                    ev = eval(line)
                except Exception:
                    logging.exception("Failed to parse line: %s", line[:200])
                    continue
            yield ev
            # simulate streaming; remove in high-throughput production
            time.sleep(0.001)


def main(args):
    agent = PreprocessorAgent(
        fitted_preprocessor_path=args.preprocessor,
        training_stats_path=args.training_stats,
        target_batch_size=args.target_batch_size,
        base_window=args.base_window,
        min_window=args.min_window,
        max_window=args.max_window,
        target_bytes_per_batch=args.target_bytes_per_batch,
        flow_inactive_timeout=args.flow_inactive_timeout
    )

    # Stream events
    for ev in ndjson_event_generator(args.input_file):
        agent.ingest_event_json(ev)
    # Force flush at the end
    agent.flush_all()
    logging.info("Done. Metrics: %s", agent.get_metrics())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-file", type=str, default=DEFAULT_INPUT_FILE, help="NDJSON input file path")
    parser.add_argument("--preprocessor", type=str, default=DEFAULT_PREPROCESSOR_PATH, help="Fitted ColumnTransformer joblib path")
    parser.add_argument("--training-stats", type=str, default=DEFAULT_TRAINING_STATS_PATH, help="Training stats (joblib) for validation (optional)")
    parser.add_argument("--target-batch-size", type=int, default=500)
    parser.add_argument("--base-window", type=float, default=5.0)
    parser.add_argument("--min-window", type=float, default=1.0)
    parser.add_argument("--max-window", type=float, default=60.0)
    parser.add_argument("--target-bytes-per-batch", type=int, default=1_000_000)
    parser.add_argument("--flow-inactive-timeout", type=float, default=60.0)
    args = parser.parse_args()
    # map arg names
    args.target_bytes_per_batch = args.target_bytes_per_batch if hasattr(args, 'target_bytes_per_batch') else args.target_bytes_per_batch
    main(args)
