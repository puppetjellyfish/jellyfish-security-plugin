import type { VirusTotalScanResult } from "./types.js";

const VT_API_BASE = "https://www.virustotal.com/api/v3";
const SCAN_CACHE = new Map<string, { result: VirusTotalScanResult; timestamp: number }>();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function getCached(key: string): VirusTotalScanResult | undefined {
  const cached = SCAN_CACHE.get(key);
  if (!cached) return undefined;
  if (Date.now() - cached.timestamp > CACHE_TTL_MS) {
    SCAN_CACHE.delete(key);
    return undefined;
  }
  return cached.result;
}

function setCache(key: string, result: VirusTotalScanResult): void {
  SCAN_CACHE.set(key, { result, timestamp: Date.now() });
}

export async function scanUrl(url: string, apiKey: string): Promise<VirusTotalScanResult> {
  const cached = getCached(`url:${url}`);
  if (cached) return cached;

  // VT uses base64url (standard base64 without padding)
  const encoded = btoa(url).replace(/=/g, "");

  // Try to GET existing analysis first
  const getRes = await fetch(`${VT_API_BASE}/urls/${encoded}`, {
    headers: { "x-apikey": apiKey },
  });

  if (getRes.ok) {
    const data = (await getRes.json()) as VtApiResponse;
    const result = parseVtResponse(url, data);
    setCache(`url:${url}`, result);
    return result;
  }

  // Submit for analysis
  const formData = new URLSearchParams({ url });
  const submitRes = await fetch(`${VT_API_BASE}/urls`, {
    method: "POST",
    headers: {
      "x-apikey": apiKey,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: formData.toString(),
  });

  if (!submitRes.ok) {
    throw new Error(
      `VirusTotal URL submission failed: ${submitRes.status} ${submitRes.statusText}`,
    );
  }

  const submitData = (await submitRes.json()) as { data: { id: string } };
  const analysisId = submitData.data.id;

  // Poll for results (up to 30 seconds)
  for (let i = 0; i < 6; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5000));
    const pollRes = await fetch(`${VT_API_BASE}/analyses/${analysisId}`, {
      headers: { "x-apikey": apiKey },
    });
    if (!pollRes.ok) continue;
    const pollData = (await pollRes.json()) as VtAnalysisResponse;
    if (pollData.data.attributes.status === "completed") {
      const result = parseVtAnalysisResponse(url, pollData);
      setCache(`url:${url}`, result);
      return result;
    }
  }

  throw new Error("VirusTotal analysis timed out");
}

export async function scanFileHash(
  sha256: string,
  apiKey: string,
): Promise<VirusTotalScanResult> {
  const cached = getCached(`file:${sha256}`);
  if (cached) return cached;

  const res = await fetch(`${VT_API_BASE}/files/${sha256}`, {
    headers: { "x-apikey": apiKey },
  });

  if (res.status === 404) {
    // File not found in VT — treat as unknown (not malicious)
    return {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      total: 0,
      resource: sha256,
    };
  }

  if (!res.ok) {
    throw new Error(`VirusTotal file lookup failed: ${res.status} ${res.statusText}`);
  }

  const data = (await res.json()) as VtApiResponse;
  const result = parseVtResponse(sha256, data);
  setCache(`file:${sha256}`, result);
  return result;
}

export function isMalicious(result: VirusTotalScanResult): boolean {
  return result.malicious > 0 || result.suspicious > 2;
}

// Internal VT API response types
interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

interface VtApiResponse {
  data: {
    attributes: {
      last_analysis_stats: VtStats;
    };
  };
}

interface VtAnalysisResponse {
  data: {
    attributes: {
      status: string;
      stats: VtStats;
    };
  };
}

function parseVtResponse(resource: string, data: VtApiResponse): VirusTotalScanResult {
  const stats = data.data.attributes.last_analysis_stats;
  return {
    malicious: stats.malicious,
    suspicious: stats.suspicious,
    harmless: stats.harmless,
    undetected: stats.undetected,
    total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected,
    resource,
  };
}

function parseVtAnalysisResponse(
  resource: string,
  data: VtAnalysisResponse,
): VirusTotalScanResult {
  const stats = data.data.attributes.stats;
  return {
    malicious: stats.malicious,
    suspicious: stats.suspicious,
    harmless: stats.harmless,
    undetected: stats.undetected,
    total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected,
    resource,
  };
}
