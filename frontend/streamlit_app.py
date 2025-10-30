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

# -------------------------------
# Header
# -------------------------------
st.markdown(
    """
    <h1 style='text-align:center; color:#00BFFF;'>Agentic NDR Dashboard</h1>
    <p style='text-align:center; font-size:16px; color:gray;'>
    Live feed from the <b>Planner → Detection → Response</b> pipeline.
    </p>
    <hr style='margin-top:10px;'>
    """,
    unsafe_allow_html=True
)

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
# Color + icon utilities
# -------------------------------
def combined_verdict_color(planner_verdict: str, detection_verdict: str) -> str:
    if planner_verdict == "suspicious" and detection_verdict == "malicious":
        return "#ff4b4b"  # Red
    elif planner_verdict == "suspicious" and detection_verdict == "benign":
        return "#FFD700"  # Yellow
    elif planner_verdict == "benign":
        return "#00cc66"  # Green
    elif planner_verdict == "malicious" or detection_verdict == "malicious":
        return "#ff4b4b"  # Red as fallback
    else:
        return "#999999"  # Gray default


def combined_icon(planner_verdict: str, detection_verdict: str) -> str:
    if planner_verdict == "suspicious" and detection_verdict == "malicious":
        return "🔴"
    elif planner_verdict == "suspicious" and detection_verdict == "benign":
        return "🟡"
    elif planner_verdict == "benign":
        return "🟢"
    elif planner_verdict == "malicious" or detection_verdict == "malicious":
        return "🔴"
    else:
        return "⚪"


# -------------------------------
# Rendering function
# -------------------------------
def render_dashboard():
    """Re-render dashboard cleanly inside the placeholder"""
    with placeholder.container():  
        results = st.session_state.results

        if not results:
            st.info("Waiting for logs to arrive...")
            return

        st.markdown(
            f"<p style='font-size:14px; color:gray;'>Showing last {min(50, len(results))} entries</p>",
            unsafe_allow_html=True
        )

        for r in reversed(results[-500:]):  
            planner = r.get("planner", {})
            detection = r.get("detection", {})
            response = r.get("response", {})

            planner_verdict = planner.get("verdict", "unknown").lower()
            detection_verdict = detection.get("verdict", "unknown").lower()

            color = combined_verdict_color(planner_verdict, detection_verdict)
            icon = combined_icon(planner_verdict, detection_verdict)

            st.markdown(
                f"""
                <div style="
                    border-left: 6px solid {color};
                    background-color: #1e1e1e;
                    padding: 12px 18px;
                    border-radius: 10px;
                    margin-bottom: 12px;
                ">
                    <h4 style="margin: 0; color: {color};">
                        {icon} Log <code>{r.get('log_id','unknown')}</code>
                    </h4>
                    <p style="margin: 4px 0; color: #aaa;">
                        <b>Planner Verdict:</b> {planner_verdict} &nbsp; | &nbsp;
                        <b>Detection Verdict:</b> {detection_verdict} &nbsp; | &nbsp;
                        <b>Logged At:</b> {r.get("logged_at")}
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

            with st.expander("Detailed Analysis"):
                st.markdown("**Planner Agent Output:**")
                st.json(planner)

                st.markdown("**Detection Agent Output:**")
                st.json(detection)

                st.markdown("**Response Agent Output:**")
                st.json(response if response else {"status": "No action triggered"})


# -------------------------------
# Live polling loop
# -------------------------------
st.toast("Live monitoring started")

while True:
    new_logs = read_new_lines()
    if new_logs:
        for log in new_logs:
            log_id = log.get("log_id") or f"unknown-{time.time()}"
            log["log_id"] = log_id
            log["logged_at"] = datetime.now(timezone.utc).isoformat()
            st.session_state.results.append(log)

        render_dashboard()
        st.toast(f"{len(new_logs)} new logs received")

    time.sleep(1)
