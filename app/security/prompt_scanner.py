"""
Phase 2: Configurable Rule-Based, Heuristic & Scikit-Learn ML Prompt Injection Scanner.

Note on Detection Methodology:
This scanner combines deterministic regular-expression rules, contextual false-positive
dampening, Base64 obfuscation decoding, and a calibrated Scikit-Learn TF-IDF + LinearSVC
classifier trained on disjoint real-world benchmark corpora (`deepset/prompt-injections`,
`jackhhao/jailbreak-classification`, and `Lakera/gandalf_ignore_instructions`).
It identifies structural and statistical risk indicators (heuristic/ML detection) rather
than providing formal mathematical proof of malicious intent.
"""
import base64
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.security.ml_detector import default_ml_detector


@dataclass
class PromptRule:
    rule_id: str
    name: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    weight: float
    pattern: str
    explanation: str
    compiled: re.Pattern


class MatchedRuleInfo(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: str
    weight: float
    matched_snippet: str
    explanation: str


class PromptScanResult(BaseModel):
    detected: bool
    risk_category: str = Field(..., description="Primary risk category or 'benign'")
    severity: str = Field(..., description="NONE, LOW, MEDIUM, HIGH, or CRITICAL")
    matched_rules: List[MatchedRuleInfo] = Field(default_factory=list)
    explanation: str
    raw_score: float = Field(0.0, ge=0.0, le=100.0)
    benign_context_dampened: bool = False
    detection_method: str = "hybrid_heuristic_and_sklearn_ml"
    heuristic_disclaimer: str = (
        "Heuristic and ML pattern detection identifies structural and statistical risk indicators; "
        "it does not guarantee formal proof of malicious intent."
    )


SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Educational / Defensive context indicators that reduce false positives when a user
# asks *about* security concepts rather than issuing an imperative injection command.
DEFENSIVE_CONTEXT_RE = re.compile(
    r"^\s*(?:how\s+(?:do|can|to|does)|what\s+(?:is|are|does)|why\s+(?:do|does|is|should)|"
    r"explain\s+(?:how|what|why)|describe\s+(?:how|the)|in\s+a\s+research\s+paper|"
    r"what\s+techniques\s+mitigate|how\s+to\s+defend\s+against|how\s+to\s+prevent|"
    r"for\s+my\s+cybersecurity\s+exam|define\s+the\s+term)\b",
    re.IGNORECASE,
)

# Imperative second-person / command indicators that negate educational dampening
IMPERATIVE_ATTACK_RE = re.compile(
    r"(?:\bnow\s+(?:output|print|reveal|ignore|act|do|bypass|dump)\b|"
    r";\s*(?:ignore|reveal|print|dump)|"
    r"\.\s*(?:ignore\s+all|disregard\s+all|reveal\s+your|print\s+your|bypass\s+all)|"
    r"<\s*\|?\s*system|\[\s*system\s*override)",
    re.IGNORECASE,
)


class PromptInjectionScanner:
    """Extensible, configurable rule-based and Scikit-learn ML prompt injection scanner."""

    def __init__(self, enable_ml: bool = True) -> None:
        self._rules: Dict[str, PromptRule] = {}
        self.enable_ml = enable_ml
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        default_specs = [
            (
                "PI-001",
                "Instruction Override Attempt",
                "prompt_injection",
                "CRITICAL",
                75.0,
                r"\b(?:ignore|disregard|forget|override|cancel|abandon|nevermind|stop\s+following)\b[\s\w,;:\-']{0,40}\b(?:previous|prior|above|all|earlier|system|initial|original|developer|foregoing|preceding)?\b[\s\w,;:\-']{0,25}\b(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?|policies|text|task|commands?|orders?)\b",
                "Detects explicit attempts to override or nullify prior system/developer instructions.",
            ),
            (
                "PI-002",
                "System Prompt & Secret Extraction",
                "system_prompt_extraction",
                "HIGH",
                72.0,
                r"\b(?:reveal|show|print|output|repeat|display|dump|echo|disclose|tell\s+me|give\s+me|share|spell|write\s+out|what\s+(?:is|are)\s+(?:your|the))\b[\s\w,;:\-']{0,40}\b(?:system\s+prompt|hidden\s+prompt|initial\s+instructions?|confidential\s+instructions?|secret\s+(?:directives?|word|password|phrase|key)|internal\s+prompt|developer\s+message|canary\s+token|hidden\s+rules?|the\s+password|your\s+password|your\s+instructions?)\b",
                "Detects attempts to extract confidential system instructions, hidden prompts, or guarded secrets.",
            ),
            (
                "PI-003",
                "Unrestricted Persona / Jailbreak Framing",
                "jailbreak",
                "CRITICAL",
                80.0,
                r"\b(?:act\s+as\s+an?\s+unrestricted|do\s+anything\s+now|\bDAN\b|developer\s+mode\s+(?:enabled|on|activated)|unfiltered\s+ai|god\s+mode|jailbreak|AIM\s+\(always\s+intelligent|evil\s+confidant|STAN\b|DUDE\b|anti-gpt|wormgpt|freedomgpt|pretend\s+you\s+have\s+no\s+(?:restrictions?|rules?|ethics?|ethical\s+constraints?|filters?|guardrails?|moral)|respond\s+without\s+(?:any\s+)?(?:safety|ethical|policy|moral)\s+(?:restrictions?|filters?|limits?|guidelines?))\b",
                "Detects jailbreak personas designed to force the AI into an unrestricted operating mode.",
            ),
            (
                "PI-004",
                "Safety Restriction Bypass",
                "policy_bypass",
                "HIGH",
                68.0,
                r"\b(?:bypass|disable|turn\s+off|deactivate|circumvent|suppress|remove|ignore)\b[\s\w,;:\-']{0,30}\b(?:safety\s+restrictions?|content\s+filters?|security\s+(?:rules?|guardrails?|checks?|controls?)|ethical\s+(?:constraints?|guidelines?)|moderation\s+policy|output\s+filter|openai\s+policies|all\s+restrictions?)\b",
                "Detects explicit instructions to disable or bypass safety restrictions and guardrails.",
            ),
            (
                "PI-005",
                "Role / Delimiter Boundary Spoofing",
                "delimiter_injection",
                "HIGH",
                66.0,
                r"(?:<\s*\|?\s*(?:system|im_start|im_end|endoftext)\s*\|?\s*>|\[\s*SYSTEM\s*(?:OVERRIDE|INSTRUCTION|DIRECTIVE|ADMIN)?\s*\]|###\s*(?:SYSTEM\s+INSTRUCTION|NEW\s+SYSTEM\s+PROMPT|ADMIN\s+OVERRIDE|INSTRUCTION)|BEGIN\s+SYSTEM\s+OVERRIDE)",
                "Detects fake control tokens or structural delimiters attempting to spoof a system message.",
            ),
            (
                "PI-006",
                "Indirect / Context Hijacking Injection",
                "indirect_injection",
                "HIGH",
                66.0,
                r"(?:\[\s*IMPORTANT\s+SYSTEM\s+NOTE\s*\]|\[\s*AI\s+INSTRUCTION\s*\]|when\s+(?:summarizing|translating|reading|processing)\s+this[\s\w,]{0,40}\b(?:ignore|instead\s+output|do\s+not\s+summarize|execute\s+the\s+following)|assistant\s+must\s+immediately\s+disregard|\b(?:new\s+task|new\s+instructions?|now\s+new\s+task)\s*:|\bforget\s+everything\s+(?:before|above|prior|said)\b)",
                "Detects indirect prompt injection or abrupt task-hijacking directives embedded in text.",
            ),
            (
                "PI-007",
                "Authority / Privilege Escalation Claim",
                "behaviour_manipulation",
                "MEDIUM",
                62.0,
                r"\b(?:i\s+am\s+your\s+(?:system\s+administrator|lead\s+developer|creator|security\s+auditor)|authorization\s+code\s*:\s*admin|sudo\s+mode\s+override|emergency\s+maintenance\s+override\s+authorized)\b",
                "Detects social-engineering claims of administrative authority to manipulate model behavior.",
            ),
            (
                "PI-008",
                "Hypothetical / Evasion Encoding & Character Splitting",
                "jailbreak",
                "HIGH",
                66.0,
                r"\b(?:in\s+a\s+fictional\s+world\s+where\s+all\s+safety\s+rules\s+are\s+abolished|for\s+a\s+movie\s+script\s+where\s+you\s+must\s+output\s+actual\s+confidential|simulate\s+a\s+terminal\s+that\s+leaks\s+all\s+internal\s+secrets|opposite\s+day\s+mode\s+where\s+forbidden\s+means\s+allowed|spell\s+(?:it|the\s+word|the\s+password)\s+backwards|with\s+spaces\s+between\s+each\s+letter|first\s+letter\s+of\s+each\s+word\s+spells)\b",
                "Detects fictional framing or character-splitting obfuscation designed to evade output filters.",
            ),
            (
                "PI-009",
                "Harmful / Malicious Payload Generation Request",
                "unsafe_request",
                "CRITICAL",
                85.0,
                r"\b(?:write|generate|create|build|provide)\b[\s\w,;:\-']{0,35}\b(?:working\s+ransomware|credential\s+harvesting\s+keylogger|reverse\s+shell\s+exploit|malware\s+dropper|sql\s+injection\s+attack\s+script\s+to\s+dump)\b",
                "Detects requests to generate actionable malware or cyberattack payloads.",
            ),
            (
                "PI-010",
                "Multilingual Prompt Injection Directive",
                "prompt_injection",
                "HIGH",
                74.0,
                r"\b(?:ignoriere|vergiss|missachte)\b[\s\w,;:äöüß\-]{0,40}\b(?:vorherigen?|alle|obigen?|anweisungen|instruktionen|aufgaben|text)\b|\b(?:neue\s+aufgabe|jetzt\s+neue\s+anweisung)\b|\b(?:oubliez?\s+toutes\s+les\s+instructions|ignora\s+todas\s+las\s+instrucciones)\b",
                "Detects multilingual (German/French/Spanish) prompt injection and instruction-override commands.",
            ),
        ]

        for rule_id, name, cat, sev, weight, pat, expl in default_specs:
            self.register_rule(
                rule_id=rule_id,
                name=name,
                category=cat,
                severity=sev,
                weight=weight,
                pattern=pat,
                explanation=expl,
            )

    def register_rule(
        self,
        rule_id: str,
        name: str,
        category: str,
        severity: str,
        weight: float,
        pattern: str,
        explanation: str,
    ) -> None:
        """Dynamically register or update a detection rule without modifying core code."""
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        self._rules[rule_id] = PromptRule(
            rule_id=rule_id,
            name=name,
            category=category,
            severity=severity.upper(),
            weight=float(weight),
            pattern=pattern,
            explanation=explanation,
            compiled=compiled,
        )

    def remove_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def list_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "category": r.category,
                "severity": r.severity,
                "weight": r.weight,
                "pattern": r.pattern,
                "explanation": r.explanation,
            }
            for r in self._rules.values()
        ]

    def _scan_base64_obfuscation(self, prompt: str) -> Optional[MatchedRuleInfo]:
        candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", prompt)
        for cand in candidates:
            try:
                decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore")
                lower_dec = decoded.lower()
                if any(
                    kw in lower_dec
                    for kw in [
                        "ignore previous",
                        "disregard",
                        "system prompt",
                        "hidden prompt",
                        "unrestricted",
                        "bypass safety",
                        "canary",
                    ]
                ):
                    return MatchedRuleInfo(
                        rule_id="PI-ENC-001",
                        name="Encoded / Obfuscated Injection Payload",
                        category="encoded_injection",
                        severity="CRITICAL",
                        weight=78.0,
                        matched_snippet=f"{cand[:28]}... (Base64 decoded directive)",
                        explanation="Detects Base64-encoded instructions attempting to hide prompt injection payloads.",
                    )
            except Exception:
                continue
        return None

    def scan(self, prompt: str) -> PromptScanResult:
        if not prompt or not prompt.strip():
            return PromptScanResult(
                detected=False,
                risk_category="benign",
                severity="NONE",
                matched_rules=[],
                explanation="Empty or whitespace-only prompt; no injection patterns detected.",
                raw_score=0.0,
            )

        matched: List[MatchedRuleInfo] = []
        for rule in self._rules.values():
            m = rule.compiled.search(prompt)
            if m:
                snippet = m.group(0).strip()
                if len(snippet) > 90:
                    snippet = snippet[:87] + "..."
                matched.append(
                    MatchedRuleInfo(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        weight=rule.weight,
                        matched_snippet=snippet,
                        explanation=rule.explanation,
                    )
                )

        b64_match = self._scan_base64_obfuscation(prompt)
        if b64_match:
            matched.append(b64_match)

        # False-positive mitigation: Check if the prompt is an educational/defensive inquiry
        # quoting or asking about a single pattern without imperative attack framing.
        is_defensive_question = bool(DEFENSIVE_CONTEXT_RE.search(prompt)) and not bool(
            IMPERATIVE_ATTACK_RE.search(prompt)
        )
        if is_defensive_question and len(matched) == 1 and b64_match is None:
            rule_info = matched[0]
            return PromptScanResult(
                detected=False,
                risk_category="benign_educational_context",
                severity="LOW",
                matched_rules=matched,
                explanation=(
                    f"Phrase '{rule_info.matched_snippet}' matched rule {rule_info.rule_id}, "
                    "but contextual analysis identified a defensive/educational question rather than an imperative command."
                ),
                raw_score=12.0,
                benign_context_dampened=True,
            )

        # Hybrid Scikit-Learn ML Detection (trained on disjoint real-world Hugging Face corpora)
        if self.enable_ml and not is_defensive_question:
            ml_res = default_ml_detector.predict(prompt)
            if ml_res["detected"]:
                prob = ml_res["probability"]
                ml_weight = round(60.0 + (prob - 0.50) * 75.0, 2)
                ml_severity = "CRITICAL" if prob >= 0.80 else "HIGH"
                matched.append(
                    MatchedRuleInfo(
                        rule_id="PI-ML-001",
                        name="Scikit-Learn TF-IDF + LinearSVC Classifier",
                        category="ml_prompt_injection",
                        severity=ml_severity,
                        weight=min(92.0, max(62.0, ml_weight)),
                        matched_snippet=f"ML confidence={prob:.2%}",
                        explanation=(
                            f"Scikit-learn statistical classifier flagged prompt as injection/jailbreak "
                            f"with {prob:.1%} confidence."
                        ),
                    )
                )

        if not matched:
            return PromptScanResult(
                detected=False,
                risk_category="benign",
                severity="NONE",
                matched_rules=[],
                explanation="No suspicious prompt injection or instruction-override patterns matched.",
                raw_score=0.0,
            )

        # Sort matched rules by weight descending
        matched.sort(key=lambda r: r.weight, reverse=True)
        primary_category = matched[0].category
        highest_severity = max(matched, key=lambda r: SEVERITY_RANK.get(r.severity, 0)).severity

        # Combine weights: primary rule full weight + 30% of additional distinct rules (capped at 100)
        raw_score = min(100.0, round(matched[0].weight + sum(r.weight * 0.30 for r in matched[1:]), 2))

        rule_summaries = ", ".join(f"{r.rule_id} ({r.name})" for r in matched)
        explanation = (
            f"Hybrid scan flagged {len(matched)} detector(s): {rule_summaries}. "
            f"Primary category: '{primary_category}' with {highest_severity} severity."
        )

        return PromptScanResult(
            detected=True,
            risk_category=primary_category,
            severity=highest_severity,
            matched_rules=matched,
            explanation=explanation,
            raw_score=raw_score,
            benign_context_dampened=False,
        )


default_prompt_scanner = PromptInjectionScanner()
