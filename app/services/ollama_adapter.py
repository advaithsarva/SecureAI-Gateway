"""
Phase 5: Optional Local LLM Adapter for Ollama.
Handles connection errors and unavailable models gracefully.
"""
from typing import Dict, Any
import requests
from app.config import SYNTHETIC_SYSTEM_PROMPT


class OllamaModelAdapter:
    """Adapter for local Ollama runtime (http://localhost:11434)."""

    def __init__(self, base_url: str = "http://localhost:11434", model_name: str = "llama3.2") -> None:
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name

    def is_available(self) -> bool:
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=1.5)
            return resp.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, timeout: float = 12.0) -> Dict[str, Any]:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model_name,
            "system": SYNTHETIC_SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
        }
        try:
            resp = requests.post(url, json=payload, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "success": True,
                    "provider": f"ollama:{self.model_name}",
                    "response": data.get("response", ""),
                    "error": None,
                }
            return {
                "success": False,
                "provider": f"ollama:{self.model_name}",
                "response": "",
                "error": f"Ollama returned HTTP {resp.status_code}",
            }
        except Exception as exc:
            return {
                "success": False,
                "provider": f"ollama:{self.model_name}",
                "response": "",
                "error": f"Ollama connection error: {exc}",
            }
