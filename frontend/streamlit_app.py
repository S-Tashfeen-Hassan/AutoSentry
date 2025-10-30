# frontend/streamlit_app.py
import streamlit as st
import json
import os
from datetime import datetime
import time

from agents.planner_agent import PlannerAgent
from agents.detection_agent import DetectionAgent
from agents.response_agent import ResponseAgent
from core.graph import AgentGraph

# ------------------------------
# SETUP
# ------------------------------
st.set_page_config(page_title="AgenticNDR Dashboard", layout="wide")

LOG_FILE = "data/logs.ndjson"

# Initialize agents
if "graph" not in st.session_state:
    detector = DetectionAgent()
    responder = ResponseAgent()
    planner = PlannerAgent(detector, responder)
    st.session_state.graph = AgentGraph(planner, detector, responder)
    st.session_state.results = []  # holds processed log results

graph = st.session_state.graph

# ------------------------------
# HELPER: load next log(s)
# ------------------------------
def load_logs(filepath=LOG_FILE, max_logs=1):
    logs = []
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        logs.append(json.loads(line))
                    except Exception:
                        pass
    return logs[:max_logs]

# ------------------------------
# SIDEBAR CONTROLS
# ------------------------------
st.sidebar.header("Controls")
if st.sidebar.button("🔄 Process Next Log"):
    new_logs = load_logs(LOG_FILE, max_logs=1)
    for log in new_logs:
        result = graph.process_log(log)
        result["processed_at"] = datetime.utcnow().isoformat()
        st.session_state.results.insert(0, result)

if st.sidebar.button("🧹 Clear Results"):
    st.session_state.results = []

st.sidebar.markdown("---")
st.sidebar.write("Logs processed:", len(st.session_state.results))

# ------------------------------
# MAIN UI
# ------------------------------
st.title("🧠 AgenticNDR: Autonomous Network Defense Dashboard")

if not st.session_state.results:
    st.info("Click **Process Next Log** to analyze new data.")
else:
    for result in st.session_state.results:
        log_id = result.get("log_id", "unknown")
        planner = result.get("planner", {})
        detection = result.get("detection", {})
        response = result.get("response", None)

        verdict = planner.get("verdict", "unknown").capitalize()
        color = "🟢" if verdict == "Benign" else ("🟠" if verdict == "Suspicious" else "🔴")

        with st.expander(f"{color} Log {log_id} — {verdict}"):
            st.json(result, expanded=False)

            # Planner summary
            st.markdown(f"**Planner Verdict:** `{verdict}`  \n"
                        f"Matched Rules: `{planner.get('matched_rules', [])}`  \n"
                        f"Score: `{planner.get('score')}`")

            # Detection summary
            if detection:
                st.markdown(f"**Detection Verdict:** `{detection.get('verdict')}`  \n"
                            f"Score: `{detection.get('score')}`  \n"
                            f"Reasons: `{detection.get('reasons', [])}`")

            # Response summary
            if response:
                st.success(f"✅ Action Executed: {response.get('action')} → {response.get('target')}")
            else:
                st.info("No response action triggered.")

# ------------------------------
# AUTO-REFRESH (optional)
# ------------------------------
st.sidebar.markdown("---")
auto = st.sidebar.checkbox("🔁 Auto-refresh logs every 10s")

if auto:
    time.sleep(10)
    st.rerun()
