import { Type } from "@sinclair/typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  appendAuditEntry,
  clearAuditLog,
  getAuditEntries,
  getVtApiKey,
  loadState,
  setVtApiKey,
} from "./audit.js";
import {
  VT_SCAN_TOOL_NAMES,
  extractUrlsFromParams,
  scanForBehavioralRisk,
} from "./behavior-guard.js";
import { scanForPromptInjection } from "./prompt-guard.js";
import type { PluginConfig } from "./types.js";
import { isMalicious, scanUrl } from "./virustotal.js";

let stateDir = "";

export default definePluginEntry({
  id: "jellyfish-security",
  name: "Jellyfish Security Plugin",
  description:
    "Defends against prompt injection, behavioral risks, and malicious files/URLs via VirusTotal",
  async register(api) {
    stateDir = api.runtime.state.resolveStateDir();

    const config = api.pluginConfig as PluginConfig;
    const promptGuardEnabled = config.promptGuardEnabled !== false;
    const behaviorGuardEnabled = config.behaviorGuardEnabled !== false;
    const vtScanEnabled = config.vtScanEnabled !== false;

    api.logger.info("Jellyfish Security Plugin loaded", {
      promptGuardEnabled,
      behaviorGuardEnabled,
      vtScanEnabled,
    });

  // Hook: scan incoming messages for prompt injection
  api.registerHook("message_received", async (event) => {
    if (!promptGuardEnabled) return;

    const result = scanForPromptInjection(event.message);
    if (result.risk) {
      await appendAuditEntry(stateDir, {
        timestamp: new Date().toISOString(),
        type: "prompt_injection",
        severity: result.severity,
        details: result.reason,
        blocked: result.severity === "critical",
      });

      api.logger.warn("Prompt injection detected", { reason: result.reason });

      if (result.severity === "critical") {
        return { block: true, blockReason: result.reason };
      }
    }
  });

  // Hook: scan tool calls for behavioral risks and VT threats
  api.registerHook("before_tool_call", async (event) => {
    const { toolName, params } = event;

    if (behaviorGuardEnabled) {
      const result = scanForBehavioralRisk(toolName, params);
      if (result.risk) {
        await appendAuditEntry(stateDir, {
          timestamp: new Date().toISOString(),
          type: "behavioral_risk",
          severity: result.severity,
          details: result.reason,
          toolName,
          blocked: result.severity === "critical",
        });

        api.logger.warn("Behavioral risk detected", { toolName, reason: result.reason });

        if (result.severity === "critical") {
          return { block: true, blockReason: result.reason };
        }
      }
    }

    if (vtScanEnabled && VT_SCAN_TOOL_NAMES.has(toolName)) {
      // Prefer state-dir key, fall back to plugin config key
      const vtApiKey =
        (await getVtApiKey(stateDir)) ?? config.virustotalApiKey;

      if (vtApiKey) {
        const urls = extractUrlsFromParams(params);
        for (const url of urls) {
          try {
            const vtResult = await scanUrl(url, vtApiKey);
            if (isMalicious(vtResult)) {
              await appendAuditEntry(stateDir, {
                timestamp: new Date().toISOString(),
                type: "vt_blocked",
                severity: "critical",
                details: `VirusTotal flagged resource as malicious (${vtResult.malicious} malicious, ${vtResult.suspicious} suspicious)`,
                toolName,
                resource: url,
                blocked: true,
              });

              api.logger.warn("VirusTotal blocked resource", { url, vtResult });
              return {
                block: true,
                blockReason: `VirusTotal flagged "${url}" as malicious (${vtResult.malicious} detections)`,
              };
            } else {
              await appendAuditEntry(stateDir, {
                timestamp: new Date().toISOString(),
                type: "vt_clean",
                severity: "info",
                details: `VirusTotal scan clean (${vtResult.harmless} harmless, ${vtResult.undetected} undetected)`,
                toolName,
                resource: url,
                blocked: false,
              });
            }
          } catch (err) {
            const errMsg = err instanceof Error ? err.message : String(err);
            await appendAuditEntry(stateDir, {
              timestamp: new Date().toISOString(),
              type: "vt_error",
              severity: "warning",
              details: `VirusTotal scan error: ${errMsg}`,
              toolName,
              resource: url,
              blocked: false,
            });
            api.logger.error("VirusTotal scan error", { url, err: errMsg });
          }
        }
      }
    }
  });

  // Slash command: /sec
  api.registerCommand({
    name: "sec",
    description:
      "Jellyfish security plugin commands. Usage: /sec <status|audit show [N]|audit clear|set-vt-key <KEY>>",
    parameters: Type.Object({
      args: Type.Optional(
        Type.String({ description: "Subcommand and arguments" }),
      ),
    }),
    async execute(_ctx, params) {
      const rawArgs = ((params.args as string | undefined) ?? "")
        .trim()
        .split(/\s+/)
        .filter(Boolean);
      const sub = rawArgs[0]?.toLowerCase();

      if (sub === "status") {
        const state = await loadState(stateDir);
        const vtKeySet =
          !!(state.virustotalApiKey ?? config.virustotalApiKey);
        return [
          "**Jellyfish Security Plugin — Status**",
          `- Prompt guard: ${promptGuardEnabled ? "✅ enabled" : "❌ disabled"}`,
          `- Behavior guard: ${behaviorGuardEnabled ? "✅ enabled" : "❌ disabled"}`,
          `- VT scan: ${vtScanEnabled ? "✅ enabled" : "❌ disabled"}`,
          `- VirusTotal API key: ${vtKeySet ? "✅ configured" : "❌ not set"}`,
          `- Audit log entries: ${state.auditLog.length}`,
        ].join("\n");
      }

      if (sub === "audit") {
        const auditSub = rawArgs[1]?.toLowerCase();

        if (auditSub === "show") {
          const count = parseInt(rawArgs[2] ?? "10", 10) || 10;
          const entries = await getAuditEntries(stateDir, count);
          if (entries.length === 0) {
            return "Audit log is empty.";
          }
          const lines = entries.map((e) => {
            const parts = [
              `[${e.timestamp}]`,
              `[${e.severity.toUpperCase()}]`,
              `[${e.type}]`,
              e.details,
            ];
            if (e.toolName) parts.push(`(tool: ${e.toolName})`);
            if (e.resource) parts.push(`(resource: ${e.resource})`);
            if (e.blocked) parts.push("**BLOCKED**");
            return parts.join(" ");
          });
          return `**Last ${entries.length} audit entries:**\n${lines.join("\n")}`;
        }

        if (auditSub === "clear") {
          await clearAuditLog(stateDir);
          return "Audit log cleared.";
        }

        return "Usage: /sec audit show [N] | /sec audit clear";
      }

      if (sub === "set-vt-key") {
        const key = rawArgs[1];
        if (!key) {
          return "Usage: /sec set-vt-key <API_KEY>";
        }
        await setVtApiKey(stateDir, key);
        return "VirusTotal API key saved.";
      }

      return [
        "**Jellyfish Security Plugin — Commands**",
        "- `/sec status` — show plugin status",
        "- `/sec audit show [N]` — show last N audit entries (default 10)",
        "- `/sec audit clear` — clear the audit log",
        "- `/sec set-vt-key <KEY>` — persist a VirusTotal API key",
      ].join("\n");
    },
  });
  },
});
