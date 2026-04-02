import { describe, expect, it } from "vitest";
import { isMalicious } from "../src/virustotal.js";
import type { VirusTotalScanResult } from "../src/types.js";

function makeResult(overrides: Partial<VirusTotalScanResult> = {}): VirusTotalScanResult {
  return {
    malicious: 0,
    suspicious: 0,
    harmless: 70,
    undetected: 5,
    total: 75,
    resource: "https://example.com",
    ...overrides,
  };
}

describe("isMalicious", () => {
  it("returns false for a clean result", () => {
    expect(isMalicious(makeResult())).toBe(false);
  });

  it("returns true when malicious > 0", () => {
    expect(isMalicious(makeResult({ malicious: 1 }))).toBe(true);
  });

  it("returns true when malicious count is high", () => {
    expect(isMalicious(makeResult({ malicious: 40 }))).toBe(true);
  });

  it("returns false when suspicious is 2 or fewer", () => {
    expect(isMalicious(makeResult({ suspicious: 2 }))).toBe(false);
  });

  it("returns true when suspicious > 2", () => {
    expect(isMalicious(makeResult({ suspicious: 3 }))).toBe(true);
  });

  it("returns true when both malicious and suspicious are set", () => {
    expect(isMalicious(makeResult({ malicious: 1, suspicious: 3 }))).toBe(true);
  });

  it("returns false when totals are zero (unknown file)", () => {
    expect(
      isMalicious({
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        total: 0,
        resource: "abc123",
      }),
    ).toBe(false);
  });
});
