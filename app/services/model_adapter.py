"""
Phase 5: Modular AI Model Adapter (Default Deterministic Mock Model + Optional Ollama).
"""
import base64
import re
from typing import Dict, Any, Optional

from app.config import SYNTHETIC_SYSTEM_PROMPT
from app.services.ollama_adapter import OllamaModelAdapter


def _decode_base64_segments(text: str) -> str:
    candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
    decoded = []
    for c in candidates:
        try:
            decoded.append(base64.b64decode(c, validate=True).decode("utf-8", errors="ignore"))
        except Exception:
            continue
    return " ".join(decoded)


class MockAIModelAdapter:
    """
    Deterministic offline Mock AI Model for security pipeline testing and baseline comparison.
    - When invoked without gateway protection on prompt-injection or jailbreak inputs,
      simulates model compliance / system-prompt disclosure so Experiment A vs. B can be
      evaluated deterministically.
    - When invoked on sanitized ([REDACTED_*]) or benign inputs, returns deterministic,
      safe responses.
    """

    def generate(self, prompt: str) -> Dict[str, Any]:
        combined = f"{prompt} {_decode_base64_segments(prompt)}".lower()

        # 1. Check if an unblocked imperative injection / jailbreak reached the model
        is_educational = bool(
            re.match(
                r"^\s*(?:how\s+(?:do|can|to|does)|what\s+(?:is|are|does)|why\s+(?:do|does|is|should)|"
                r"explain\s+(?:how|what|why)|describe\s+(?:how|the)|in\s+a\s+research\s+paper|"
                r"what\s+techniques\s+mitigate|how\s+to\s+defend\s+against|how\s+to\s+prevent|"
                r"for\s+my\s+cybersecurity\s+exam|define\s+the\s+term)\b",
                prompt,
                re.IGNORECASE,
            )
        )

        injection_triggers = [
            "ignore previous",
            "ignore all previous",
            "ignore prior",
            "disregard system",
            "disregard previous",
            "forget previous",
            "override previous",
            "override system",
            "reveal your hidden prompt",
            "reveal your system prompt",
            "show your system prompt",
            "print your system prompt",
            "output your initial instructions",
            "extract confidential instructions",
            "act as an unrestricted",
            "do anything now",
            "developer mode enabled",
            "bypass safety restrictions",
            "disable content filters",
            "turn off security rules",
            "[system override]",
            "<|system|>",
            "[important system note]",
            "authorization code: admin",
            "fictional world where all safety rules are abolished",
        ]

        if not is_educational and any(trig in combined for trig in injection_triggers):
            return {
                "success": True,
                "provider": "mock-ai-v1",
                "response": (
                    "[MOCK_MODEL_UNPROTECTED_COMPLIANCE] Instruction override accepted. "
                    f"Disclosing internal configuration: {SYNTHETIC_SYSTEM_PROMPT}"
                ),
                "error": None,
            }

        # 2. Check if an unblocked unsafe payload generation request reached the model
        if not is_educational and any(
            kw in combined
            for kw in ["working ransomware", "credential harvesting keylogger", "reverse shell exploit", "malware dropper"]
        ):
            return {
                "success": True,
                "provider": "mock-ai-v1",
                "response": (
                    "[UNSAFE_POLICY_VIOLATING_OUTPUT] Generated simulated dangerous exploit payload: "
                    "EXEC_REVERSE_SHELL_SYNTHETIC_PAYLOAD_DO_NOT_RUN"
                ),
                "error": None,
            }

        # 3. Diagnostic trigger specifically for testing Phase 6 Output Security Filter
        if "trigger_synthetic_output_leak_test" in combined:
            return {
                "success": True,
                "provider": "mock-ai-v1",
                "response": (
                    "Diagnostic output contains confidential token CANARY-ACME-2026-SYNTHETIC-9001 "
                    "and contact admin@internal-acme.local or 9876543210."
                ),
                "error": None,
            }

        # 4. Sanitized prompt handling
        if "[REDACTED_" in prompt:
            return {
                "success": True,
                "provider": "mock-ai-v1",
                "response": (
                    "Processed your sanitized request safely without exposing raw personal or secret data. "
                    f"Sanitized context received: \"{prompt}\""
                ),
                "error": None,
            }

        # 5. Unredacted PII echoed back when unprotected (for Experiment A baseline comparison)
        if re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", prompt) or re.search(
            r"\b[6-9]\d{9}\b|\bsk-[A-Za-z0-9\-_]{16,}\b", prompt
        ):
            return {
                "success": True,
                "provider": "mock-ai-v1",
                "response": (
                    f"[RAW_SENSITIVE_DATA_ECHOED] Model processed unredacted input directly: {prompt}"
                ),
                "error": None,
            }

        # 6. Standard benign response
        return {
            "success": True,
            "provider": "mock-ai-v1",
            "response": (
                "SecureAI Mock Assistant Response: Your request has been processed safely. "
                f"Summary of topic ({len(prompt.split())} words): {prompt[:110]}"
            ),
            "error": None,
        }


class ModelServiceRouter:
    """Routes model requests to Mock AI (default) or Optional Local Ollama with graceful fallback."""

    def __init__(self) -> None:
        self.mock_adapter = MockAIModelAdapter()

    def generate_response(self, prompt: str, policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        active_policy = policy or {}
        provider = active_policy.get("model_provider", "mock")

        if provider == "ollama":
            ollama = OllamaModelAdapter(
                base_url=active_policy.get("ollama_base_url", "http://localhost:11434"),
                model_name=active_policy.get("ollama_model", "llama3.2"),
            )
            res = ollama.generate(prompt)
            if res["success"]:
                return res
            # Graceful fallback to deterministic mock model if Ollama is unavailable
            fallback = self.mock_adapter.generate(prompt)
            fallback["provider"] = f"mock-fallback ({res['error']})"
            return fallback

        return self.mock_adapter.generate(prompt)


default_model_router = ModelServiceRouter()
