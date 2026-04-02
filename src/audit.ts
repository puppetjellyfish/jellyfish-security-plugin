import fs from "node:fs/promises";
import path from "node:path";
import type { AuditEntry, PluginState } from "./types.js";

const STATE_FILE = "jellyfish-security.json";
const MAX_AUDIT_ENTRIES = 1000;

export async function loadState(stateDir: string): Promise<PluginState> {
  const file = path.join(stateDir, STATE_FILE);
  try {
    const raw = await fs.readFile(file, "utf8");
    return JSON.parse(raw) as PluginState;
  } catch {
    return { auditLog: [] };
  }
}

export async function saveState(stateDir: string, state: PluginState): Promise<void> {
  const file = path.join(stateDir, STATE_FILE);
  await fs.mkdir(stateDir, { recursive: true });
  await fs.writeFile(file, JSON.stringify(state, null, 2), "utf8");
}

export async function appendAuditEntry(
  stateDir: string,
  entry: Omit<AuditEntry, "id">,
): Promise<AuditEntry> {
  const state = await loadState(stateDir);
  const full: AuditEntry = { id: crypto.randomUUID(), ...entry };
  state.auditLog.push(full);
  if (state.auditLog.length > MAX_AUDIT_ENTRIES) {
    state.auditLog = state.auditLog.slice(-MAX_AUDIT_ENTRIES);
  }
  await saveState(stateDir, state);
  return full;
}

export async function getAuditEntries(stateDir: string, count = 10): Promise<AuditEntry[]> {
  const state = await loadState(stateDir);
  return state.auditLog.slice(-count);
}

export async function clearAuditLog(stateDir: string): Promise<void> {
  const state = await loadState(stateDir);
  state.auditLog = [];
  await saveState(stateDir, state);
}

export async function getVtApiKey(stateDir: string): Promise<string | undefined> {
  const state = await loadState(stateDir);
  return state.virustotalApiKey;
}

export async function setVtApiKey(stateDir: string, apiKey: string): Promise<void> {
  const state = await loadState(stateDir);
  state.virustotalApiKey = apiKey;
  await saveState(stateDir, state);
}
