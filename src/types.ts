export interface AuditEntry {
  id: string;
  timestamp: string;
  type: "prompt_injection" | "behavioral_risk" | "vt_blocked" | "vt_clean" | "vt_error";
  severity: "info" | "warning" | "critical";
  details: string;
  toolName?: string;
  resource?: string;
  blocked: boolean;
}

export interface PluginState {
  auditLog: AuditEntry[];
  virustotalApiKey?: string;
}

export interface VirusTotalScanResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  total: number;
  resource: string;
}

export interface PluginConfig {
  virustotalApiKey?: string;
  promptGuardEnabled?: boolean;
  behaviorGuardEnabled?: boolean;
  vtScanEnabled?: boolean;
}
