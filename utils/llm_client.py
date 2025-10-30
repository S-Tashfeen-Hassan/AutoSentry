# utils/llm_client.py
import requests
import json
from typing import Optional
from .config import OLLAMA_BASE, LLM_MODEL, LLM_TIMEOUT

def call_llm(prompt: str, model: Optional[str] = None, timeout: int = None) -> str:
    """
    Calls an Ollama-compatible API endpoint (e.g., local or Cloudflare tunnel).
    Ensures NON-streaming response and returns the text cleanly.
    """
    model = model or LLM_MODEL
    timeout = timeout or LLM_TIMEOUT
    url = f"{OLLAMA_BASE}/api/generate"

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False  # 👈 This disables streaming and forces one complete JSON response
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()

        # Try structured JSON
        try:
            data = response.json()
            if isinstance(data, dict) and "response" in data:
                return data["response"].strip()
        except json.JSONDecodeError:
            pass

        # Fallback to plain text
        return response.text.strip()

    except requests.exceptions.Timeout:
        return json.dumps({"error": "llm_call_failed: request timed out"})
    except requests.exceptions.RequestException as e:
        return json.dumps({"error": f"llm_call_failed: {str(e)}"})
