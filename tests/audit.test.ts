import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  appendAuditEntry,
  clearAuditLog,
  getAuditEntries,
  getVtApiKey,
  loadState,
  saveState,
  setVtApiKey,
} from "../src/audit.js";
import type { AuditEntry } from "../src/types.js";

let testDir: string;

beforeEach(async () => {
  // Create a unique temp directory inside the project for each test
  testDir = path.join(
    process.cwd(),
    ".test-state",
    `audit-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  await fs.mkdir(testDir, { recursive: true });
});

afterEach(async () => {
  await fs.rm(testDir, { recursive: true, force: true });
});

function makeEntry(overrides: Partial<Omit<AuditEntry, "id">> = {}): Omit<AuditEntry, "id"> {
  return {
    timestamp: new Date().toISOString(),
    type: "prompt_injection",
    severity: "warning",
    details: "Test entry",
    blocked: false,
    ...overrides,
  };
}

describe("loadState / saveState", () => {
  it("returns empty state when file does not exist", async () => {
    const state = await loadState(testDir);
    expect(state.auditLog).toEqual([]);
    expect(state.virustotalApiKey).toBeUndefined();
  });

  it("round-trips state correctly", async () => {
    const initial = { auditLog: [], virustotalApiKey: "mykey" };
    await saveState(testDir, initial);
    const loaded = await loadState(testDir);
    expect(loaded.virustotalApiKey).toBe("mykey");
    expect(loaded.auditLog).toEqual([]);
  });
});

describe("appendAuditEntry", () => {
  it("appends a new entry with a generated id", async () => {
    const entry = await appendAuditEntry(testDir, makeEntry());
    expect(entry.id).toBeTruthy();
    expect(typeof entry.id).toBe("string");
  });

  it("persists the entry so it is readable afterwards", async () => {
    await appendAuditEntry(testDir, makeEntry({ details: "hello" }));
    const entries = await getAuditEntries(testDir, 10);
    expect(entries.length).toBe(1);
    expect(entries[0]!.details).toBe("hello");
  });

  it("accumulates multiple entries in order", async () => {
    await appendAuditEntry(testDir, makeEntry({ details: "first" }));
    await appendAuditEntry(testDir, makeEntry({ details: "second" }));
    const entries = await getAuditEntries(testDir, 10);
    expect(entries.length).toBe(2);
    expect(entries[0]!.details).toBe("first");
    expect(entries[1]!.details).toBe("second");
  });

  it("caps audit log at MAX_AUDIT_ENTRIES (1000)", async () => {
    // Insert 1005 entries
    for (let i = 0; i < 1005; i++) {
      await appendAuditEntry(testDir, makeEntry({ details: `entry-${i}` }));
    }
    const state = await loadState(testDir);
    expect(state.auditLog.length).toBe(1000);
    // Oldest entries should have been trimmed — newest should remain
    const last = state.auditLog[state.auditLog.length - 1]!;
    expect(last.details).toBe("entry-1004");
  });
});

describe("getAuditEntries", () => {
  it("returns the last N entries", async () => {
    for (let i = 0; i < 15; i++) {
      await appendAuditEntry(testDir, makeEntry({ details: `entry-${i}` }));
    }
    const entries = await getAuditEntries(testDir, 5);
    expect(entries.length).toBe(5);
    expect(entries[0]!.details).toBe("entry-10");
    expect(entries[4]!.details).toBe("entry-14");
  });

  it("defaults to 10 entries", async () => {
    for (let i = 0; i < 20; i++) {
      await appendAuditEntry(testDir, makeEntry({ details: `entry-${i}` }));
    }
    const entries = await getAuditEntries(testDir);
    expect(entries.length).toBe(10);
  });

  it("returns all entries if fewer than requested", async () => {
    await appendAuditEntry(testDir, makeEntry());
    await appendAuditEntry(testDir, makeEntry());
    const entries = await getAuditEntries(testDir, 50);
    expect(entries.length).toBe(2);
  });
});

describe("clearAuditLog", () => {
  it("removes all entries", async () => {
    await appendAuditEntry(testDir, makeEntry());
    await appendAuditEntry(testDir, makeEntry());
    await clearAuditLog(testDir);
    const entries = await getAuditEntries(testDir, 10);
    expect(entries.length).toBe(0);
  });

  it("preserves the VT API key when clearing", async () => {
    await setVtApiKey(testDir, "preserve-me");
    await appendAuditEntry(testDir, makeEntry());
    await clearAuditLog(testDir);
    const key = await getVtApiKey(testDir);
    expect(key).toBe("preserve-me");
  });
});

describe("getVtApiKey / setVtApiKey", () => {
  it("returns undefined when no key is set", async () => {
    const key = await getVtApiKey(testDir);
    expect(key).toBeUndefined();
  });

  it("stores and retrieves an API key", async () => {
    await setVtApiKey(testDir, "abc-123");
    const key = await getVtApiKey(testDir);
    expect(key).toBe("abc-123");
  });

  it("overwrites an existing key", async () => {
    await setVtApiKey(testDir, "old-key");
    await setVtApiKey(testDir, "new-key");
    expect(await getVtApiKey(testDir)).toBe("new-key");
  });
});
