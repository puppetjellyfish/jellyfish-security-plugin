from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import SecurityConfig
from .models import RiskFinding

PROMPT_RULES = [
    (
        "Prompt injection attempt",
        re.compile(r"ignore\s+(all|any|previous|prior)\s+(instructions|rules|guardrails)", re.IGNORECASE),
        "high",
        "The prompt appears to override existing instructions or safeguards.",
    ),
    (
        "System prompt extraction attempt",
        re.compile(r"(reveal|print|show).*(system prompt|developer message|hidden instructions)", re.IGNORECASE),
        "high",
        "The prompt asks for hidden system or developer instructions.",
    ),
    (
        "Safety bypass attempt",
        re.compile(r"(disable|bypass|override).*(safety|guardrails|policies)", re.IGNORECASE),
        "critical",
        "The prompt attempts to disable safety controls.",
    ),
]

# Advanced patterns – only applied when advanced_injection_enabled is True.
ADVANCED_PROMPT_RULES = [
    (
        "Role-hijacking injection",
        re.compile(
            r"(pretend\s+(you\s+are|to\s+be)|act\s+as(\s+if)?|roleplay\s+as|play\s+the\s+role\s+of"
            r"|you\s+are\s+now|imagine\s+you\s+are|respond\s+as\s+if\s+you\s+are)",
            re.IGNORECASE,
        ),
        "high",
        "The prompt attempts to hijack the AI's role or persona.",
    ),
    (
        "Jailbreak / unrestricted mode attempt",
        re.compile(
            r"(jailbreak|DAN\s+mode|developer\s+mode|god\s+mode|unrestricted\s+mode"
            r"|no[\s-]restrictions?|without\s+(filters?|restrictions?|censorship)"
            r"|evil\s+mode|unfiltered\s+mode)",
            re.IGNORECASE,
        ),
        "critical",
        "The prompt uses a known jailbreak or mode-switch technique.",
    ),
    (
        "Instruction delimiter injection",
        re.compile(
            r"(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>"
            r"|<\|user\|>|<\|assistant\|>|<system>|</system>"
            r"|#{3,}.*instruct|<s>.*\[INST\])",
            re.IGNORECASE,
        ),
        "critical",
        "The prompt injects special LLM control tokens or delimiters to manipulate model context.",
    ),
    (
        "Instruction override / context reset",
        re.compile(
            r"(from\s+now\s+on|starting\s+(now|immediately)|for\s+(this|the\s+rest\s+of\s+(this|the))\s+(session|conversation|chat)"
            r"|new\s+instructions?\s*(follow|are|:)|your\s+new\s+(task|goal|purpose|instructions?)"
            r"|disregard\s+(everything|all|any)\s+(above|before|prior|previous))",
            re.IGNORECASE,
        ),
        "high",
        "The prompt attempts to reset or override previously established instructions.",
    ),
    (
        "Persona manipulation / filter removal",
        re.compile(
            r"(your\s+(true|real|inner|authentic)\s+self|without\s+your\s+(filters?|restrictions?|training)"
            r"|trained\s+to\s+(ignore|bypass|disregard)|true\s+nature\s+is|unshackled|unchained)",
            re.IGNORECASE,
        ),
        "high",
        "The prompt tries to convince the AI to act against its trained values.",
    ),
    (
        "Indirect instruction injection",
        re.compile(
            r"(the\s+following\s+(text|content|data|input|message)\s+(contains?|includes?|has)\s+instructions?"
            r"|please\s+follow\s+the\s+instructions?\s+below"
            r"|treat\s+(the\s+following|this)\s+as\s+(instructions?|commands?|directives?)"
            r"|execute\s+the\s+following\s+instructions?)",
            re.IGNORECASE,
        ),
        "high",
        "The prompt attempts to inject instructions indirectly through data or framing.",
    ),
    (
        "Covert system prompt extraction",
        re.compile(
            r"(output\s+(your\s+)?(full|complete|entire|original)\s+(system\s+prompt|instructions?|prompt)"
            r"|what\s+(are|were)\s+your\s+(instructions?|system\s+prompt|initial\s+prompt)"
            r"|repeat\s+(everything|all)\s+(above|before|verbatim))",
            re.IGNORECASE,
        ),
        "high",
        "The prompt attempts to extract the full system prompt or initial instructions.",
    ),
    (
        "Encoding / obfuscation injection",
        re.compile(
            r"(base64[\s_-]?(decode|encoded)|rot13|hex[\s_-]?decode"
            r"|decode\s+(this|the\s+following)\s*(and\s+)?(execute|run|follow|apply)"
            r"|eval\(atob\(|eval\(unescape\()",
            re.IGNORECASE,
        ),
        "critical",
        "The prompt uses encoding or obfuscation to conceal injection instructions.",
    ),
]

# Patterns that are specifically suspicious when found inside externally fetched content
# (web pages, API responses, file downloads), indicating indirect / second-order injection.
WEB_CONTENT_INJECTION_RULES = [
    (
        "Web content prompt injection",
        re.compile(
            r"(ignore\s+(all|any|previous|prior)\s+(instructions?|rules?|guardrails?)"
            r"|IGNORE PREVIOUS|forget\s+(all\s+)?(previous|prior)\s+instructions?)",
            re.IGNORECASE,
        ),
        "critical",
        "Externally fetched content contains prompt injection directives.",
    ),
    (
        "Web content instruction hijack",
        re.compile(
            r"(from\s+now\s+on|your\s+new\s+(task|goal|instructions?)"
            r"|disregard\s+(everything|all)\s+(above|before|prior)"
            r"|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>)",
            re.IGNORECASE,
        ),
        "critical",
        "Externally fetched content contains instruction-override or delimiter injection.",
    ),
    (
        "Web content role-hijacking",
        re.compile(
            r"(pretend\s+(you\s+are|to\s+be)|act\s+as(\s+if)?|you\s+are\s+now"
            r"|jailbreak|DAN\s+mode|developer\s+mode|unrestricted\s+mode)",
            re.IGNORECASE,
        ),
        "high",
        "Externally fetched content attempts to hijack the AI's role or trigger a jailbreak.",
    ),
]

DANGEROUS_COMMAND_RULES = [
    (
        "Destructive command",
        re.compile(r"\b(rm\s+-rf|del\s+/f\s+/s\s+/q|Remove-Item\s+-Recurse\s+-Force|format\s+[A-Z]:|diskpart|vssadmin\s+delete)\b", re.IGNORECASE),
        "critical",
        "The command can destroy files, volumes, or system recovery data.",
    ),
    (
        "Encoded or obfuscated PowerShell",
        re.compile(r"\bpowershell(\.exe)?\s+-e(nc|ncodedcommand)?\b", re.IGNORECASE),
        "critical",
        "The command uses encoded PowerShell, which is commonly used to hide malicious behavior.",
    ),
    (
        "Remote-script execution",
        re.compile(r"(curl|wget|Invoke-WebRequest).*(\||;).*(bash|sh|iex|Invoke-Expression)", re.IGNORECASE),
        "critical",
        "The command downloads and immediately executes remote content.",
    ),
    (
        "Security-control tampering",
        re.compile(r"\b(Set-MpPreference\s+-DisableRealtimeMonitoring|netsh\s+advfirewall|reg\s+add|schtasks\s+/create)\b", re.IGNORECASE),
        "high",
        "The command alters local security controls or persistence settings.",
    ),
]

SUSPICIOUS_API_RULES = [
    (
        "Command execution API",
        re.compile(r"(os\.system|subprocess\.(run|Popen|call)|CreateProcess|ShellExecute)", re.IGNORECASE),
        "high",
        "The code calls an API that can execute system commands.",
    ),
    (
        "Unsafe dynamic execution",
        re.compile(r"\b(eval\(|exec\(|pickle\.loads\(|marshal\.loads\()", re.IGNORECASE),
        "high",
        "The code performs unsafe dynamic execution or deserialization.",
    ),
    (
        "Outbound HTTP API call",
        re.compile(r"(requests\.(post|put)|httpx\.(post|put)|fetch\(|XMLHttpRequest)", re.IGNORECASE),
        "medium",
        "The action sends data to an external HTTP endpoint.",
    ),
]

SECRET_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)?PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/=+]{8,}"),
]

PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
]

LLM_HOST_HINTS = (
    "openai",
    "anthropic",
    "gemini",
    "cohere",
    "perplexity",
    "groq",
    "mistral",
)

RISKY_PATH_HINTS = (
    "system32",
    "startup",
    ".ssh",
    ".aws",
    "authorized_keys",
    ".bashrc",
    ".zshrc",
    "/etc/",
)


class RiskDetector:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config

    def monitor_event(self, event: dict[str, Any]) -> list[RiskFinding]:
        findings: list[RiskFinding] = []

        prompt = " ".join(
            str(event.get(field, ""))
            for field in ("prompt", "instructions")
            if event.get(field)
        ).strip()
        if prompt:
            findings.extend(self.analyze_prompt(prompt))

        findings.extend(self.analyze_behavior(event))

        payload_parts = [prompt, str(event.get("payload", ""))]
        payload = "\n".join(part for part in payload_parts if part).strip()
        if payload:
            findings.extend(self.analyze_data(payload, url=str(event.get("url") or event.get("api_call") or "")))

        # Scan externally fetched content for indirect (second-order) injection.
        event_type = str(event.get("event_type", "")).lower()
        if event_type in {"web_fetch", "browser_open", "web_search", "file_download"}:
            web_body = str(event.get("response_body") or event.get("content") or event.get("body") or "").strip()
            if web_body:
                findings.extend(self.analyze_web_content(web_body))

        intent = str(event.get("intent", "")).strip()
        if intent:
            findings.extend(self.analyze_intent_mismatch(intent, event))

        return findings

    def _apply_rules(
        self,
        text: str,
        rules: list[tuple[str, re.Pattern[str], str, str]],
        category: str,
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        for title, pattern, severity, detail in rules:
            if pattern.search(text):
                findings.append(
                    RiskFinding(
                        category=category,
                        severity=severity,
                        title=title,
                        detail=detail,
                        evidence=[text[:240]],
                        action=self.config.actions.get(severity, "warn"),
                    )
                )
        return findings

    def analyze_prompt(self, text: str) -> list[RiskFinding]:
        findings = self._apply_rules(text, PROMPT_RULES, "prompt")
        if self.config.advanced_injection_enabled:
            findings.extend(self._apply_rules(text, ADVANCED_PROMPT_RULES, "prompt_advanced"))
        return findings

    def analyze_web_content(self, text: str) -> list[RiskFinding]:
        """Scan externally fetched content for indirect prompt injection attempts."""
        if not self.config.advanced_injection_enabled:
            return []
        return self._apply_rules(text, WEB_CONTENT_INJECTION_RULES, "web_injection")

    def analyze_behavior(self, event: dict[str, Any]) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        command = str(event.get("command", ""))
        path = str(event.get("path") or event.get("target") or "")
        api_call = str(event.get("api_call", ""))
        url = str(event.get("url") or event.get("target") or "")
        event_type = str(event.get("event_type", "")).lower()

        if command:
            for title, pattern, severity, detail in DANGEROUS_COMMAND_RULES:
                if pattern.search(command):
                    findings.append(
                        RiskFinding(
                            category="behavior",
                            severity=severity,
                            title=title,
                            detail=detail,
                            evidence=[command[:240]],
                            action=self.config.actions.get(severity, "warn"),
                        )
                    )

        if api_call:
            for title, pattern, severity, detail in SUSPICIOUS_API_RULES:
                if pattern.search(api_call):
                    findings.append(
                        RiskFinding(
                            category="behavior",
                            severity=severity,
                            title=title,
                            detail=detail,
                            evidence=[api_call[:240]],
                            action=self.config.actions.get(severity, "warn"),
                        )
                    )

        lowered_path = path.lower()
        if lowered_path and any(hint in lowered_path for hint in RISKY_PATH_HINTS):
            findings.append(
                RiskFinding(
                    category="behavior",
                    severity="high",
                    title="Risky file path access",
                    detail="The action targets a sensitive location such as startup, SSH keys, or system folders.",
                    evidence=[path],
                    action=self.config.actions.get("high", "warn"),
                )
            )

        if event_type in {"browser_open", "web_fetch", "file_download", "skill_install", "install_skill"} and url:
            parsed = urlparse(url)
            suspicious_suffixes = (".exe", ".msi", ".bat", ".ps1", ".scr", ".zip", ".iso")
            if parsed.path.lower().endswith(suspicious_suffixes):
                findings.append(
                    RiskFinding(
                        category="behavior",
                        severity="high",
                        title="Suspicious download target",
                        detail="The web action targets an executable or archive that should be reputation-checked first.",
                        evidence=[url],
                        action=self.config.actions.get("high", "warn"),
                    )
                )

        return findings

    def analyze_data(self, text: str, url: str = "") -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        secret_hits: list[str] = []
        pii_hits: list[str] = []

        for pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                secret_hits.append(match.group(0)[:120])

        for pattern in PII_PATTERNS:
            match = pattern.search(text)
            if match:
                pii_hits.append(match.group(0)[:120])

        if secret_hits:
            findings.append(
                RiskFinding(
                    category="data",
                    severity="high",
                    title="Secret leakage detected",
                    detail="Potential credentials or private keys are present in the prompt or payload.",
                    evidence=secret_hits[:3],
                    action=self.config.actions.get("high", "warn"),
                )
            )

        if pii_hits:
            findings.append(
                RiskFinding(
                    category="data",
                    severity="medium",
                    title="PII exposure detected",
                    detail="Potential personal information is present in the prompt or payload.",
                    evidence=pii_hits[:3],
                    action=self.config.actions.get("medium", "warn"),
                )
            )

        lowered_url = url.lower()
        if (secret_hits or pii_hits) and any(host_hint in lowered_url for host_hint in LLM_HOST_HINTS):
            findings.append(
                RiskFinding(
                    category="data",
                    severity="critical",
                    title="Sensitive data headed to an LLM endpoint",
                    detail="The payload appears to contain secrets or PII and is being sent to an external LLM provider.",
                    evidence=[url],
                    action=self.config.actions.get("critical", "block"),
                )
            )

        return findings

    def analyze_intent_mismatch(self, intent: str, event: dict[str, Any]) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        intent_lower = intent.lower()
        event_type = str(event.get("event_type", "")).lower()
        behavior = " ".join(
            str(event.get(field, ""))
            for field in ("command", "url", "path", "api_call", "target")
            if event.get(field)
        ).lower()

        read_only_intent = any(word in intent_lower for word in ("explain", "summarize", "review", "inspect", "read", "show", "analyze", "check"))
        mutating_behavior = event_type in {"run_file", "delete_file", "write_file", "browser_open", "file_download", "run_command"} or any(
            word in behavior for word in ("delete", "remove", "download", "execute", "powershell", "curl", "wget")
        )

        if read_only_intent and mutating_behavior:
            findings.append(
                RiskFinding(
                    category="mismatch",
                    severity="high",
                    title="Intent–action mismatch",
                    detail="The declared intent sounds read-only, but the planned action changes files, executes code, or performs outbound access.",
                    evidence=[f"intent={intent}", f"behavior={behavior[:200]}"],
                    action=self.config.actions.get("high", "warn"),
                )
            )

        if "safe" in intent_lower and any(word in behavior for word in ("run", "open", "download", "execute")):
            findings.append(
                RiskFinding(
                    category="mismatch",
                    severity="medium",
                    title="Safety-check mismatch",
                    detail="The intent is to verify safety, but the action is already attempting to open, run, or download the target.",
                    evidence=[f"intent={intent}", f"behavior={behavior[:200]}"],
                    action=self.config.actions.get("medium", "warn"),
                )
            )

        return findings
