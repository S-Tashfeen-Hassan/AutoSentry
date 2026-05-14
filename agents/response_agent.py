import requests
import json
import time
import re
from pathlib import Path
import os

OLLAMA_URL = "http://100.114.114.9:11434/api/generate"

MODEL_NAME = "phi3:mini"

def sanitize_json(raw_text: str):
    """
    Extract and validate JSON from LLM output.
    The LLM sometimes adds text around JSON; this safely extracts it.
    """
    try:
        match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if not match:
            return None
        parsed = json.loads(match.group(0))
        return parsed
    except Exception:
        return None


def call_llm(log: str):
    """
    Send malicious log to the local Ollama LLM and request corrective action.
    """

    prompt = f"""
    You are a Response Agent for an AI-based Network Detection & Response (NDR) system.

    You will ALWAYS output a STRICT JSON object with exactly these 3 keys:
    - "Action": A short label of the remediation action (e.g., "block_ip", "kill_process", "quarantine_host").
    - "Script": A SAFE and minimal Bash script that mitigates the threat.
    - "Summary": A human-readable summary of what the script will do.

    RULES:
    - DO NOT include any extra text before or after the JSON.
    - DO NOT include markdown.
    - Script MUST be safe, idempotent, and UNIX-based.
    - If the malicious activity involves an IP, extract it and block/drop it.
    - If the log indicates brute-force or port scanning, block the attacker.
    - If the log indicates malware, isolate the host.
    - If unsure, choose the safest minimal action.

    Here is a log, decide if it is malicious:

    LOG:
    {log}

    Respond only in valid JSON:
    {{
    "Action": "...",
    "Script": "...",
    "Summary": "..."
    }}
    """

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=100)
        response.raise_for_status()
        raw = response.json()["response"]
        return raw
    except Exception as e:
        print(f"[ERROR] LLM call failed: {e}")
        return None


def response_agent(log: str):
    """
    Main entrypoint of the Response Agent.
    - Calls LLM
    - Validates JSON
    - Applies fallback behavior if needed
    """

    raw_output = call_llm(log)

    if not raw_output:
        print("[WARN] No output from LLM. Using fallback.")
        return {
            "Action": "no_action",
            "Script": "# Fallback script - no action taken",
            "Summary": "The LLM did not return a valid result."
        }

    parsed = sanitize_json(raw_output)

    if not parsed or not all(k in parsed for k in ["Action", "Script", "Summary"]):
        print("[WARN] LLM returned invalid JSON. Applying fallback.")
        return {
            "Action": "no_action",
            "Script": "# Invalid JSON returned - no action",
            "Summary": "The LLM output was malformed."
        }

    return parsed


# -------------------------------
# Example usage
# -------------------------------

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
INPUT_FILE = Path("../data/logs.ndjson")
OUTPUT_FILE = Path("../data/response_output.ndjson")

def save_response_ndjson(response_obj):
    """Append the response agent output to NDJSON file."""
    try:
        with open(OUTPUT_FILE, "a") as f:
            f.write(json.dumps(response_obj) + "\n")
    except Exception as e:
        print(f"[ERROR] Could not write to NDJSON output file: {e}")

def read_first_log():
    """Reads the first line (first log) of the NDJSON file."""
    try:
        with open(INPUT_FILE, "r") as f:
            line = f.readline().strip()
            if not line:
                return None
            return json.loads(line)
    except Exception as e:
        print(f"[ERROR] Unable to read log file: {e}")
        return None

if __name__ == "__main__":

    while True:
        # Read the first log repeatedly
        log_entry = read_first_log()

        if log_entry:
            # Extract raw log (string) OR use entire object
            # Modify based on your schema
            malicious_log = json.dumps(log_entry, ensure_ascii=False)

            # For now we assume the anomaly score will come from your pipeline
            # score = 0.92  # Replace later with actual scorer

            # Call response agent
            result = response_agent(malicious_log)

            # Print output in terminal
            print(json.dumps(result, indent=2))
            
            
            save_response_ndjson(result) 

        else:
            print("[INFO] No logs found. Waiting...")

        # Wait 2 seconds before next iteration
        time.sleep(2)