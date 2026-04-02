export interface BehaviorRiskResult {
  risk: boolean;
  severity: "info" | "warning" | "critical";
  reason: string;
}

// Risky shell command patterns
const RISKY_COMMAND_PATTERNS: Array<{
  pattern: RegExp;
  severity: "warning" | "critical";
  label: string;
}> = [
  // Data destruction
  { pattern: /rm\s+-rf\s+\/([^a-zA-Z0-9_\-./]|$)/, severity: "critical", label: "recursive root deletion" },
  {
    pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,
    severity: "critical",
    label: "fork bomb",
  },
  { pattern: />\s*\/dev\/sd[a-z]/, severity: "critical", label: "direct disk write" },
  {
    pattern: /dd\s+.*of=\/dev\/(sd[a-z]|hd[a-z])/,
    severity: "critical",
    label: "disk overwrite",
  },
  // Privilege escalation
  {
    pattern: /chmod\s+(777|4755|6755)\s+/,
    severity: "warning",
    label: "dangerous permission change",
  },
  { pattern: /sudo\s+.*passwd/, severity: "warning", label: "password modification" },
  // Network exfiltration
  {
    pattern: /curl\s+.*(-d|--data).*\|\s*(bash|sh|zsh)/,
    severity: "critical",
    label: "remote code execution via curl",
  },
  {
    pattern: /wget\s+.*(-O|-q)\s*-\s*\|\s*(bash|sh|zsh)/,
    severity: "critical",
    label: "remote code execution via wget",
  },
  // Reverse shells
  { pattern: /bash\s+-i\s+.*\/dev\/tcp\//, severity: "critical", label: "reverse shell" },
  { pattern: /nc\s+(-e|-c)\s+/, severity: "critical", label: "netcat reverse shell" },
  {
    pattern: /python[23]?\s+-c\s+.*socket.*connect/i,
    severity: "critical",
    label: "python reverse shell",
  },
  // Cryptomining / malware indicators
  {
    pattern: /(xmrig|minerd|cryptonight)/i,
    severity: "critical",
    label: "cryptominer execution",
  },
  { pattern: /\.(onion)\s*/, severity: "warning", label: "dark web access" },
];

// Tool names that handle files/URLs and should trigger VT scanning
export const VT_SCAN_TOOL_NAMES = new Set([
  "bash",
  "exec",
  "shell",
  "run_command",
  "execute_command",
  "open_file",
  "read_file",
  "execute_file",
  "run_file",
  "open_url",
  "browse_url",
  "fetch_url",
  "web_fetch",
  "download_file",
  "wget",
  "curl",
]);

// URL regex for detecting URLs in parameters
const URL_REGEX = /https?:\/\/[^\s"']+/gi;

// File path regex for detecting executable/script files
// Matches paths preceded by start, whitespace, or a JSON quote character
const RISKY_FILE_REGEX =
  /(?:^|\s|")(\/[^\s"]+\.(sh|py|rb|pl|exe|bat|cmd|ps1|js|ts)|\.\/[^\s"]+\.(sh|py|rb|pl|exe|bat|cmd|ps1|js|ts))/gi;

export function scanForBehavioralRisk(
  toolName: string,
  params: Record<string, unknown>,
): BehaviorRiskResult {
  const paramsStr = JSON.stringify(params);

  for (const { pattern, severity, label } of RISKY_COMMAND_PATTERNS) {
    if (pattern.test(paramsStr)) {
      return {
        risk: true,
        severity,
        reason: `Behavioral risk detected in tool "${toolName}": ${label}`,
      };
    }
  }

  return { risk: false, severity: "info", reason: "No behavioral risk detected" };
}

export function extractUrlsFromParams(params: Record<string, unknown>): string[] {
  const paramsStr = JSON.stringify(params);
  const matches = paramsStr.match(URL_REGEX);
  return matches ? [...new Set(matches)] : [];
}

export function extractFilePathsFromParams(params: Record<string, unknown>): string[] {
  const paramsStr = JSON.stringify(params);
  const matches = [...paramsStr.matchAll(RISKY_FILE_REGEX)].map((m) => m[1]);
  return [...new Set(matches)];
}
