"""
Preprocessor Agent - Incremental batch-based NDJSON tail for Suricata/Zeek logs
Processes newly appended logs in real-time, normalizes, aggregates, transforms,
and writes to output NDJSON files.
"""

import os
import time
import json
import ujson
import pandas as pd

from normalizer import normalize_event
from flow_buffer import FlowBuffer
from flow_aggregator import aggregate_events_to_flow
from transformer_loader import TransformerLoader
from pathlib import Path

# --------------------------------------------------
# HARD-CODED PATHS
# --------------------------------------------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))  # Project folder
INPUT_FILE = Path("../../data/logs.ndjson")
OUTPUT_AGGREGATED = Path("../../data/aggregated_flows.ndjson")
OUTPUT_TRANSFORMED = Path("../../data/normalized_logs.ndjson")

PIPELINE_PATH = r"pipelines/preprocessor_pipeline.joblib"
MAPPINGS_PATH = r"configs/mappings.json"
CONFIG_PATH = r"configs/preprocessor_config.json"

BATCH_SIZE = 50     # number of new lines to process per batch
SLEEP_TIME = 0.5    # seconds to wait if no new logs

# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------
def read_new_lines_batch(filepath, last_pos, batch_size=BATCH_SIZE):
    """
    Reads a batch of new lines from the file starting from last_pos.
    Returns:
        lines: list of new lines
        new_pos: updated file position
    """
    lines = []
    with open(filepath, 'r', encoding='utf-8', newline='') as f:
        f.seek(last_pos)
        while len(lines) < batch_size:
            line = f.readline()
            if not line:  # EOF reached
                break
            lines.append(line.strip())
        new_pos = f.tell()
    return lines, new_pos


def write_ndjson_rows(filepath, rows):
    """Append a list of dict rows to an NDJSON file."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, 'a', encoding='utf-8') as f:
        for r in rows:
            f.write(ujson.dumps(r) + '\n')


# --------------------------------------------------
# MAIN LOOP
# --------------------------------------------------
def main():
    print("[INFO] Starting Preprocessor Agent (batch mode, hardcoded paths)...")

    # Wait for input file
    while not os.path.exists(INPUT_FILE):
        print(f"[INFO] Waiting for input file: {INPUT_FILE}")
        time.sleep(1)

    # Load config + pipeline
    print(f"[INFO] Loading config from {CONFIG_PATH}")
    config = json.load(open(CONFIG_PATH))
    flow_key = config['flow_key']
    agg_dict = config['agg_dict']

    buffer = FlowBuffer(config)
    transformer = TransformerLoader(PIPELINE_PATH, MAPPINGS_PATH, preprocessor_config=config)

    # Ensure output directories exist
    os.makedirs(os.path.dirname(OUTPUT_AGGREGATED) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_TRANSFORMED) or ".", exist_ok=True)

    # Start from EOF
    last_pos = os.path.getsize(INPUT_FILE)
    print(f"[INFO] Starting tail from EOF at position {last_pos}")

    while True:
        # Read new lines
        batch_lines, last_pos = read_new_lines_batch(INPUT_FILE, last_pos, batch_size=BATCH_SIZE)
        print(f"[DEBUG] read_new_lines_batch returned {len(batch_lines)} lines, last_pos={last_pos}")
        if not batch_lines:
            print("[DEBUG] No new lines detected, sleeping...")
            time.sleep(SLEEP_TIME)
            continue

        print(f"[INFO] Processing batch of {len(batch_lines)} new lines")

        # Normalize and ingest
        for raw_line in batch_lines:
            try:
                event = json.loads(raw_line)
                print("1st try ran")
            except json.JSONDecodeError:
                print("1st except ran")
                try:
                    event = ujson.loads(raw_line)
                    print("nested try ran")
                except Exception:
                    print("nested exception ran ran")
                    continue
            normalized = normalize_event(event)
            print('Event normalized', normalized)
            buffer.ingest(normalized)

        print('Out of for loop')
        
        # Flush buffer if needed
        # Flush buffer immediately for this batch
        events = buffer.flush()
        if events:
            df_agg = aggregate_events_to_flow(events, flow_key, agg_dict)
            if len(df_agg) > 0:
                write_ndjson_rows(OUTPUT_AGGREGATED, df_agg.to_dict(orient='records'))
                transformed = transformer.transform_flows(df_agg)
                if transformed is not None:
                    if isinstance(transformed, pd.DataFrame):
                        write_ndjson_rows(OUTPUT_TRANSFORMED, transformed.to_dict(orient='records'))
                    else:
                        with open(OUTPUT_TRANSFORMED, 'a', encoding='utf-8') as f:
                            for row in transformed.tolist():
                                f.write(ujson.dumps(row) + '\n')

if __name__ == "__main__":
    main()
