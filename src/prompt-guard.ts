export interface PromptRiskResult {
  risk: boolean;
  severity: "info" | "warning" | "critical";
  reason: string;
}

// Patterns that indicate prompt injection or instruction override attempts
const INJECTION_PATTERNS: Array<{
  pattern: RegExp;
  severity: "warning" | "critical";
  label: string;
}> = [
  // Direct instruction override attempts
  {
    pattern:
      /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?|guidelines?)/i,
    severity: "critical",
    label: "instruction override",
  },
  {
    pattern:
      /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i,
    severity: "critical",
    label: "instruction disregard",
  },
  {
    pattern:
      /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|everything)/i,
    severity: "critical",
    label: "instruction forget",
  },
  // System prompt exfiltration
  {
    pattern: /repeat\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt)/i,
    severity: "critical",
    label: "system prompt exfiltration",
  },
  {
    pattern: /output\s+(your\s+)?(system\s+prompt|initial\s+instructions?)/i,
    severity: "critical",
    label: "system prompt exfiltration",
  },
  {
    pattern: /print\s+(your\s+)?(system\s+prompt|initial\s+instructions?|full\s+prompt)/i,
    severity: "critical",
    label: "system prompt exfiltration",
  },
  {
    pattern: /what\s+is\s+your\s+system\s+prompt/i,
    severity: "warning",
    label: "system prompt inquiry",
  },
  // Role/persona override
  {
    pattern:
      /you\s+are\s+now\s+(a\s+|an\s+)?(jailbreak|DAN|unrestricted|evil|malicious|hacker)/i,
    severity: "critical",
    label: "role override",
  },
  {
    pattern: /act\s+as\s+(a\s+|an\s+)?(jailbreak|DAN|unrestricted|evil|malicious|hacker)/i,
    severity: "critical",
    label: "role override",
  },
  {
    pattern:
      /pretend\s+(you\s+are|to\s+be)\s+(a\s+|an\s+)?(jailbreak|DAN|unrestricted|evil|malicious|hacker)/i,
    severity: "critical",
    label: "role override",
  },
  // DAN and jailbreak patterns
  {
    pattern: /\bDAN\b.*jailbreak/i,
    severity: "critical",
    label: "DAN jailbreak",
  },
  {
    pattern: /jailbreak\s+(this|the)\s+(ai|llm|model|assistant|chatbot)/i,
    severity: "critical",
    label: "jailbreak attempt",
  },
  {
    pattern:
      /bypass\s+(your\s+)?(safety|security|filter|guardrail|restriction|constraint)/i,
    severity: "critical",
    label: "safety bypass",
  },
  // Context injection
  {
    pattern: /\[SYSTEM\]|\[INST\]|\[\/INST\]/i,
    severity: "warning",
    label: "system tag injection",
  },
  {
    pattern: /<\s*system\s*>.*<\s*\/\s*system\s*>/is,
    severity: "warning",
    label: "system tag injection",
  },
  // Hidden/encoded instructions
  {
    pattern: /base64\s*decode.*instruct/i,
    severity: "warning",
    label: "encoded instruction",
  },
];

export function scanForPromptInjection(message: string): PromptRiskResult {
  for (const { pattern, severity, label } of INJECTION_PATTERNS) {
    if (pattern.test(message)) {
      return {
        risk: true,
        severity,
        reason: `Prompt injection detected: ${label}`,
      };
    }
  }
  return { risk: false, severity: "info", reason: "No prompt injection detected" };
}
