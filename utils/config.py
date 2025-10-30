# utils/config.py
OLLAMA_BASE = "https://sequence-bow-enhancement-output.trycloudflare.com"  # << your tunnel URL
LLM_MODEL = "phi3:mini"
LOCAL_LOG_PATH = "data/logs.ndjson"

# Planner thresholds and rules
RBF_KEYWORDS = [
    "failed_login", "bruteforce", "dns_tunnel", "malicious", "compression bomb",
    "port scan", "port scanning", "suspicious", "sql injection", "exploit"
]
RBF_CONN_COUNT_THRESHOLD = 50
RBF_PKTS_THRESHOLD = 100
RBF_BYTES_THRESHOLD = 100_000
SCORE_THRESHOLD_SUSPICIOUS = 0.2
LLM_TIMEOUT = 60  # seconds
