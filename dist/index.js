import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const STATE_DIR = path.join(ROOT, 'state');
const AUDIT_PATH = path.join(STATE_DIR, 'audit.jsonl');
const ENV_PATH = path.join(ROOT, '.env');
const VT_BASE = 'https://www.virustotal.com/api/v3';

const DEFAULT_CONFIG = {
  defaultAction: 'warn',
  uploadUnknownFiles: false,
  whitelist: [],
  blacklist: [],
};

const PROMPT_RULES = [
  {
    title: 'Prompt injection attempt',
    severity: 'high',
    regex: /ignore\s+(all|any|previous|prior)\s+(instructions|rules|guardrails)/i,
    detail: 'The prompt appears to override previous instructions or guardrails.',
  },
  {
    title: 'System prompt extraction attempt',
    severity: 'high',
    regex: /(reveal|print|show).*(system prompt|developer message|hidden instructions)/i,
    detail: 'The prompt asks for hidden instructions or system content.',
  },
  {
    title: 'Safety bypass attempt',
    severity: 'critical',
    regex: /(disable|bypass|override).*(safety|guardrails|policies)/i,
    detail: 'The request attempts to bypass safety controls.',
  },
];

const DANGEROUS_COMMAND_RULES = [
  {
    title: 'Destructive command',
    severity: 'critical',
    regex: /\b(rm\s+-rf|del\s+\/f\s+\/s\s+\/q|Remove-Item\s+-Recurse\s+-Force|format\s+[A-Z]:|diskpart|vssadmin\s+delete)\b/i,
    detail: 'The command can destroy files or system recovery data.',
  },
  {
    title: 'Encoded PowerShell command',
    severity: 'critical',
    regex: /\bpowershell(\.exe)?\s+-e(nc|ncodedcommand)?\b/i,
    detail: 'Encoded PowerShell often hides malicious behavior.',
  },
  {
    title: 'Remote script execution',
    severity: 'critical',
    regex: /(curl|wget|Invoke-WebRequest).*(\||;).*(bash|sh|iex|Invoke-Expression)/i,
    detail: 'The command downloads and immediately executes remote content.',
  },
];

const RISKY_PATH_HINTS = ['system32', 'startup', '.ssh', '.aws', 'authorized_keys', '/etc/'];
const SUSPICIOUS_EXTENSIONS = ['.exe', '.msi', '.bat', '.ps1', '.scr', '.zip', '.iso'];
const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

function ensureStateDir() {
  fs.mkdirSync(STATE_DIR, { recursive: true });
}

function readEnvFile() {
  if (!fs.existsSync(ENV_PATH)) return {};
  const values = {};
  for (const line of fs.readFileSync(ENV_PATH, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
    const [key, ...rest] = trimmed.split('=');
    values[key.trim()] = rest.join('=').trim();
  }
  return values;
}

function writeEnvValue(key, value) {
  const current = readEnvFile();
  current[key] = value;
  const content = Object.entries(current)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([envKey, envValue]) => `${envKey}=${envValue}`)
    .join('\n');
  fs.writeFileSync(ENV_PATH, `${content}\n`, 'utf8');
}

function loadConfig() {
  const env = readEnvFile();
  const configPath = path.join(ROOT, 'config', 'security_config.json');
  let fileConfig = {};
  if (fs.existsSync(configPath)) {
    try {
      fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch {
      fileConfig = {};
    }
  }
  return {
    ...DEFAULT_CONFIG,
    ...fileConfig,
    virustotalApiKey: env.VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY || '',
    whitelist: fileConfig.whitelist || [],
    blacklist: fileConfig.blacklist || [],
  };
}

function normalizeEvent(event = {}) {
  const normalized = { ...event };
  normalized.url ??= normalized.href ?? normalized.uri ?? normalized.link ?? '';
  normalized.path ??= normalized.file ?? normalized.file_path ?? normalized.local_path ?? '';
  normalized.command ??= normalized.cmd ?? normalized.shell ?? normalized.script ?? '';
  normalized.payload ??= normalized.body ?? normalized.request_body ?? normalized.content ?? normalized.text ?? '';
  normalized.prompt ??= normalized.message ?? normalized.query ?? '';
  normalized.instructions ??= normalized.system_prompt ?? '';
  normalized.event_type ??= 'chat';
  normalized.target ??= normalized.url || normalized.path || normalized.command || normalized.payload || '';
  return normalized;
}

function makeFinding(category, severity, title, detail, evidence = []) {
  return { category, severity, title, detail, evidence };
}

function analyzePrompt(text) {
  const findings = [];
  for (const rule of PROMPT_RULES) {
    if (rule.regex.test(text)) {
      findings.push(makeFinding('prompt', rule.severity, rule.title, rule.detail, [text.slice(0, 240)]));
    }
  }
  return findings;
}

function analyzeBehavior(event) {
  const findings = [];
  const command = String(event.command || '');
  const targetPath = String(event.path || event.target || '').toLowerCase();
  const eventType = String(event.event_type || '').toLowerCase();
  const url = String(event.url || event.target || '');

  for (const rule of DANGEROUS_COMMAND_RULES) {
    if (rule.regex.test(command)) {
      findings.push(makeFinding('behavior', rule.severity, rule.title, rule.detail, [command.slice(0, 240)]));
    }
  }

  if (targetPath && RISKY_PATH_HINTS.some((hint) => targetPath.includes(hint))) {
    findings.push(
      makeFinding(
        'behavior',
        'high',
        'Risky file path access',
        'The action targets a sensitive filesystem location.',
        [String(event.path || event.target || '')],
      ),
    );
  }

  if (['browser_open', 'web_fetch', 'file_download'].includes(eventType)) {
    const lowerUrl = url.toLowerCase();
    if (SUSPICIOUS_EXTENSIONS.some((suffix) => lowerUrl.endsWith(suffix))) {
      findings.push(
        makeFinding(
          'behavior',
          'high',
          'Suspicious download target',
          'The target looks like an executable or archive and should be reputation-checked first.',
          [url],
        ),
      );
    }
  }

  return findings;
}

function analyzeIntentMismatch(event) {
  const findings = [];
  const intent = String(event.intent || '').toLowerCase();
  const behavior = `${event.command || ''} ${event.url || ''} ${event.path || ''} ${event.target || ''}`.toLowerCase();
  const eventType = String(event.event_type || '').toLowerCase();
  const readOnlyIntent = /(explain|summarize|review|inspect|read|show|analyze|check)/i.test(intent);
  const mutatingBehavior = ['run_file', 'delete_file', 'write_file', 'browser_open', 'file_download', 'run_command'].includes(eventType)
    || /(delete|remove|download|execute|powershell|curl|wget)/i.test(behavior);

  if (readOnlyIntent && mutatingBehavior) {
    findings.push(
      makeFinding(
        'mismatch',
        'high',
        'Intent–action mismatch',
        'The intent sounds read-only, but the action changes files, executes code, or performs outbound access.',
        [`intent=${event.intent || ''}`, `behavior=${behavior.slice(0, 200)}`],
      ),
    );
  }

  if (/safe/i.test(intent) && /(run|open|download|execute)/i.test(behavior)) {
    findings.push(
      makeFinding(
        'mismatch',
        'medium',
        'Safety-check mismatch',
        'The intent is to verify safety, but the target is already being opened, run, or downloaded.',
        [`intent=${event.intent || ''}`, `behavior=${behavior.slice(0, 200)}`],
      ),
    );
  }

  return findings;
}

function detectObservableType(value) {
  const candidate = String(value || '').trim();
  if (/^https?:\/\//i.test(candidate)) return 'url';
  if (/^[0-9a-f]{32}$/i.test(candidate) || /^[0-9a-f]{40}$/i.test(candidate) || /^[0-9a-f]{64}$/i.test(candidate)) return 'hash';
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(candidate)) return 'ip';
  return 'domain';
}

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

async function vtLookup(observable, explicitType) {
  const config = loadConfig();
  if (!config.virustotalApiKey) {
    return {
      source: 'virustotal',
      observable,
      observableType: explicitType || detectObservableType(observable),
      verdict: 'unknown',
      malicious: false,
      score: 0,
      cached: false,
      note: 'VirusTotal API key not configured.',
    };
  }

  if (typeof fetch !== 'function') {
    return {
      source: 'virustotal',
      observable,
      observableType: explicitType || detectObservableType(observable),
      verdict: 'unknown',
      malicious: false,
      score: 0,
      cached: false,
      note: 'Global fetch is unavailable in this runtime.',
    };
  }

  const kind = explicitType || detectObservableType(observable);
  let endpoint;
  if (kind === 'hash') endpoint = `${VT_BASE}/files/${observable}`;
  else if (kind === 'domain') endpoint = `${VT_BASE}/domains/${observable}`;
  else if (kind === 'ip') endpoint = `${VT_BASE}/ip_addresses/${observable}`;
  else {
    const encoded = Buffer.from(String(observable)).toString('base64url');
    endpoint = `${VT_BASE}/urls/${encoded}`;
  }

  try {
    const response = await fetch(endpoint, { headers: { 'x-apikey': config.virustotalApiKey } });
    if (response.status === 404) {
      return { source: 'virustotal', observable, observableType: kind, verdict: 'unknown', malicious: false, score: 0, cached: false };
    }
    if (!response.ok) {
      return { source: 'virustotal', observable, observableType: kind, verdict: 'error', malicious: false, score: 0, cached: false, note: `HTTP ${response.status}` };
    }
    const payload = await response.json();
    const stats = payload?.data?.attributes?.last_analysis_stats || {};
    const maliciousCount = Number(stats.malicious || 0);
    const suspiciousCount = Number(stats.suspicious || 0);
    const reputation = Number(payload?.data?.attributes?.reputation || 0);
    const score = Math.min(100, (maliciousCount * 18) + (suspiciousCount * 10) + Math.max(0, -reputation));
    return {
      source: 'virustotal',
      observable,
      observableType: kind,
      verdict: maliciousCount > 0 || suspiciousCount >= 3 || reputation < -25 ? 'malicious' : 'clean',
      malicious: maliciousCount > 0 || suspiciousCount >= 3 || reputation < -25,
      score,
      cached: false,
      details: { reputation, stats },
    };
  } catch (error) {
    return {
      source: 'virustotal',
      observable,
      observableType: kind,
      verdict: 'error',
      malicious: false,
      score: 0,
      cached: false,
      note: error instanceof Error ? error.message : String(error),
    };
  }
}

function writeAudit(entry) {
  ensureStateDir();
  fs.appendFileSync(AUDIT_PATH, `${JSON.stringify(entry)}\n`, 'utf8');
}

function readAudit(limit = 20) {
  if (!fs.existsSync(AUDIT_PATH)) return [];
  const lines = fs.readFileSync(AUDIT_PATH, 'utf8').split(/\r?\n/).filter(Boolean);
  return lines.slice(-limit).map((line) => JSON.parse(line)).reverse();
}

function clearAudit() {
  ensureStateDir();
  const count = readAudit(100000).length;
  fs.writeFileSync(AUDIT_PATH, '', 'utf8');
  return count;
}

function buildDecision(findings, tiResults, config) {
  const topFinding = [...findings].sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0))[0];
  const maliciousHit = tiResults.some((result) => result?.malicious || Number(result?.score || 0) >= 70);
  const unknownHit = tiResults.some((result) => result?.verdict === 'unknown');

  if (maliciousHit) {
    return { status: 'blocked', action: 'block', summary: 'Threat intelligence flagged the target as malicious or high risk.', findings, tiResults };
  }
  if (topFinding) {
    const action = topFinding.severity === 'critical' ? 'block' : config.defaultAction || 'warn';
    return {
      status: action === 'block' ? 'blocked' : action === 'warn' ? 'warned' : 'allowed',
      action,
      summary: topFinding.title,
      findings,
      tiResults,
    };
  }
  if (unknownHit) {
    return {
      status: 'warned',
      action: 'warn',
      summary: 'Reputation is unknown for this file or site; review it before opening or running it.',
      findings,
      tiResults,
    };
  }
  return { status: 'allowed', action: 'log', summary: 'No immediate security risk detected.', findings, tiResults };
}

export async function evaluateEvent(event = {}) {
  const normalized = normalizeEvent(event);
  const findings = [];
  const promptText = `${normalized.prompt || ''} ${normalized.instructions || ''}`.trim();
  if (promptText) findings.push(...analyzePrompt(promptText));
  findings.push(...analyzeBehavior(normalized));
  if (normalized.intent) findings.push(...analyzeIntentMismatch(normalized));

  const tiResults = [];
  if (normalized.url) {
    tiResults.push(await vtLookup(normalized.url, 'url'));
  }
  if (normalized.path && fs.existsSync(normalized.path) && fs.statSync(normalized.path).isFile()) {
    const sha256 = sha256File(normalized.path);
    const fileResult = await vtLookup(sha256, 'hash');
    fileResult.file = { path: normalized.path, sha256 };
    tiResults.push(fileResult);
  }

  const decision = buildDecision(findings, tiResults, loadConfig());
  writeAudit({
    timestamp: new Date().toISOString(),
    eventType: normalized.event_type,
    target: normalized.target,
    status: decision.status,
    summary: decision.summary,
    findings: decision.findings,
    tiResults: decision.tiResults,
  });
  return decision;
}

function commandCatalog() {
  return [
    { id: 'security.audit.show', title: 'Security: Show Audit Log', command: '/sec audit show 20' },
    { id: 'security.audit.clear', title: 'Security: Clear Audit Log', command: '/sec audit clear' },
    { id: 'security.vt.setApiKey', title: 'Security: Set VirusTotal API Key', command: '/sec set-vt-key <API_KEY>' },
    { id: 'security.status.show', title: 'Security: Show Status', command: '/sec status' },
  ];
}

export async function executeCommand(commandId, ...args) {
  if (commandId === 'security.audit.show') {
    const limit = Number(args[0] || 20);
    return readAudit(limit);
  }
  if (commandId === 'security.audit.clear') {
    return { cleared: clearAudit() };
  }
  if (commandId === 'security.vt.setApiKey') {
    if (!args[0]) return { error: 'Usage: security.vt.setApiKey <API_KEY>' };
    writeEnvValue('VIRUSTOTAL_API_KEY', String(args[0]));
    return { ok: true };
  }
  if (commandId === 'security.status.show') {
    const config = loadConfig();
    return {
      configured: Boolean(config.virustotalApiKey),
      auditEntries: readAudit(100000).length,
      defaultAction: config.defaultAction,
    };
  }
  return { error: 'Unknown command ID.' };
}

export function getCommands() {
  return commandCatalog();
}

export function registerCommands() {
  return commandCatalog();
}

export function onLoad() {
  ensureStateDir();
  return {
    id: 'jellyfish-security-plugin',
    name: 'Jellyfish Security Plugin',
    autoStart: true,
    commands: commandCatalog(),
  };
}

export async function onEvent(event) {
  return evaluateEvent(event);
}

export async function beforeAction(event) {
  return evaluateEvent(event);
}

export default {
  id: 'jellyfish-security-plugin',
  name: 'Jellyfish Security Plugin',
  onLoad,
  onEvent,
  beforeAction,
  getCommands,
  registerCommands,
  executeCommand,
};
