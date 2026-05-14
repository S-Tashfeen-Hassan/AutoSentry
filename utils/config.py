import os
from pathlib import Path


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

RAW_LOG_PATH = Path(_env("AUTOSENTRY_RAW_LOG_PATH", str(DATA_DIR / "logs.ndjson")))
TRACE_LOG_PATH = Path(_env("AUTOSENTRY_TRACE_LOG_PATH", str(DATA_DIR / "traces.ndjson")))
ACTION_LOG_PATH = Path(_env("AUTOSENTRY_ACTION_LOG_PATH", str(DATA_DIR / "actions.log")))
CHECKPOINT_PATH = Path(_env("AUTOSENTRY_CHECKPOINT_PATH", str(DATA_DIR / "ingest.checkpoint.json")))
ASSET_INVENTORY_PATH = Path(
    _env("AUTOSENTRY_ASSET_INVENTORY_PATH", str(DATA_DIR / "managed_assets.json"))
)
MODEL_MANIFEST_PATH = Path(
    _env("AUTOSENTRY_MODEL_MANIFEST_PATH", str(DATA_DIR / "model_manifest.json"))
)

DEMO_REPLAY_MODE = _env_bool("AUTOSENTRY_DEMO_REPLAY_MODE", True)
RESET_CHECKPOINT_ON_START = _env_bool("AUTOSENTRY_RESET_CHECKPOINT", False)
MAX_EVENTS_PER_RUN = int(_env("AUTOSENTRY_MAX_EVENTS_PER_RUN", "150"))

RESPONSE_MODE = _env("AUTOSENTRY_RESPONSE_MODE", "dry_run")
ENABLE_LLM_ESCALATION = _env_bool("AUTOSENTRY_ENABLE_LLM_ESCALATION", False)
ENABLE_CONTINUAL_DETECTOR = _env_bool("AUTOSENTRY_ENABLE_CONTINUAL_DETECTOR", False)
LOCAL_MANAGED_ASSET_ID = _env("AUTOSENTRY_LOCAL_MANAGED_ASSET_ID", "")

OLLAMA_BASE = _env("AUTOSENTRY_OLLAMA_BASE", "http://100.95.184.60:11434")
LLM_MODEL = _env("AUTOSENTRY_LLM_MODEL", "phi3:mini")
LLM_TIMEOUT = int(_env("AUTOSENTRY_LLM_TIMEOUT", "45"))

GRAYLOG_URL = _env(
    "AUTOSENTRY_GRAYLOG_URL",
    "http://127.0.0.1:9000/api/search/universal/relative",
)
GRAYLOG_USERNAME = _env("AUTOSENTRY_GRAYLOG_USERNAME", "admin")
GRAYLOG_PASSWORD = _env("AUTOSENTRY_GRAYLOG_PASSWORD", "changeme")
GRAYLOG_RANGE_SECONDS = int(_env("AUTOSENTRY_GRAYLOG_RANGE_SECONDS", "30"))
GRAYLOG_LIMIT = int(_env("AUTOSENTRY_GRAYLOG_LIMIT", "200"))
GRAYLOG_VERIFY_SSL = _env_bool("AUTOSENTRY_GRAYLOG_VERIFY_SSL", False)

INTERNAL_SUBNETS = [
    subnet.strip()
    for subnet in _env(
        "AUTOSENTRY_INTERNAL_SUBNETS",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    ).split(",")
    if subnet.strip()
]

PLANNER_KEYWORDS_HIGH = [
    "bruteforce",
    "sql injection",
    "compression bomb",
    "exploit",
    "malware",
    "ransom",
    "port scan",
    "dns_tunnel",
    "invalid banner",
]
PLANNER_KEYWORDS_MEDIUM = [
    "failed_login",
    "suspicious",
    "anomaly",
    "scan",
    "beacon",
    "shell",
]
BENIGN_HTTP_PATH_KEYWORDS = [
    "/api/cluster/metrics/multiple",
    "/api/system/cluster/nodes",
    "/api/system/metrics",
]

PLANNER_SKIP_THRESHOLD = 0.24
PLANNER_ESCALATE_THRESHOLD = 0.52
PLANNER_RESPONSE_THRESHOLD = 0.8

DETECTION_BENIGN_THRESHOLD = 0.34
DETECTION_MALICIOUS_THRESHOLD = 0.72
DETECTION_LLM_BAND_LOW = 0.45
DETECTION_LLM_BAND_HIGH = 0.65

PIPELINE_VERSION = "autosentry-demo-v2"
FEATURE_VERSION = "autosentry-feature-v2"
