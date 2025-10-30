import streamlit as st
import json
import os
import time
from datetime import datetime, timezone
from core.graph import AgentGraph

TRACE_LOG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "traces.log"))

st.set_page_config(page_title="Agentic NDR Dashboard", layout="wide")

# -------------------------------
# Init session state
# -------------------------------
if "graph" not in st.session_state:
    st.session_state.graph = AgentGraph()
if "results" not in st.session_state:
    st.session_state.results = []
if "last_pos" not in st.session_state:
    st.session_state.last_pos = 0  # pointer for reading file incrementally

graph = st.session_state.graph

st.title("🛰️ Agentic NDR - Live Detection & Response Dashboard")
st.caption("Logs stream in from the planner → detection → response pipeline (real-time).")

placeholder = st.empty()

# -------------------------------
# Helper to read new lines
# -------------------------------
def read_new_lines():
    path = TRACE_LOG_PATH
    if not os.path.exists(path):
        return []

    new_entries = []
    with open(path, "r", encoding="utf-8") as f:
        f.seek(st.session_state.last_pos)
        lines = f.readlines()
        st.session_state.last_pos = f.tell()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            new_entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return new_entries


# -------------------------------
# Rendering function
# -------------------------------
def render_dashboard():
    results = st.session_state.results
    with placeholder.container():
        if not results:
            st.info("Waiting for logs to arrive...")
            return

        st.markdown("### 📊 Live Logs Feed")
        for r in reversed(results[-50:]):  # show last 50 only
            verdict = r.get("planner", {}).get("verdict", "unknown")
            detection = r.get("detection", {}).get("verdict", "pending")
            response = r.get("response", {})

            color_icon = {
                "benign": "✅",
                "suspicious": "🟡",
                "malicious": "🚨",
                "uncertain": "⚪",
                "unknown": "⚪",
            }.get(verdict, "⚪")

            st.markdown(
                f"#### {color_icon} `{r.get('log_id', 'unknown')}` — Verdict: `{verdict}` → Detection: `{detection}`"
            )
            st.json(r)


# -------------------------------
# Live polling loop
# -------------------------------
st.toast("🚀 Live monitoring started")

while True:
    new_logs = read_new_lines()
    if new_logs:
        for log in new_logs:
            log_id = log.get("log_id") or f"unknown-{time.time()}"
            log["log_id"] = log_id
            log["logged_at"] = datetime.now(timezone.utc).isoformat()

            st.session_state.results.append(log)

        render_dashboard()
        st.toast(f"🆕 {len(new_logs)} new logs received")

    time.sleep(1)  # check every second
