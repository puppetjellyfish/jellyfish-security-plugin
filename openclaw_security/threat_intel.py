from __future__ import annotations

import base64
import hashlib
import ipaddress
from pathlib import Path
from time import perf_counter
from typing import Any

import requests

from .audit import AuditTrail
from .cache import TTLCache
from .config import SecurityConfig
from .models import ThreatIntelResult

VT_API_BASE = "https://www.virustotal.com/api/v3"


def detect_observable_type(value: str) -> str:
    candidate = value.strip()
    lowered = candidate.lower()

    if lowered.startswith(("http://", "https://")):
        return "url"

    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    if len(lowered) in {32, 40, 64} and all(char in "0123456789abcdef" for char in lowered):
        return "hash"

    return "domain"


class ThreatIntelClient:
    def __init__(self, config: SecurityConfig, audit: AuditTrail) -> None:
        self.config = config
        self.audit = audit
        self.cache = TTLCache(
            config.base_dir / "state" / "ti_cache.json",
            ttl_seconds=config.cache_ttl_seconds,
        )

    def check_observable(self, observable: str, observable_type: str | None = None) -> ThreatIntelResult:
        observable = observable.strip()
        if not observable:
            return ThreatIntelResult(
                source="none",
                observable="",
                observable_type="unknown",
                verdict="unknown",
                malicious=False,
                score=0,
                confidence=0.0,
                categories=["empty"],
            )

        kind = observable_type or detect_observable_type(observable)
        cache_key = f"{kind}:{observable.lower()}"
        cached = self.cache.get(cache_key)
        if cached:
            self.audit.record_cache_hit()
            return ThreatIntelResult(**cached, cached=True)

        if self.config.is_whitelisted(observable):
            result = ThreatIntelResult(
                source="policy",
                observable=observable,
                observable_type=kind,
                verdict="allowlisted",
                malicious=False,
                score=0,
                confidence=1.0,
                categories=["policy"],
                details={"match": "whitelist"},
            )
            self.cache.set(cache_key, result.to_dict())
            return result

        if self.config.is_blacklisted(observable):
            result = ThreatIntelResult(
                source="policy",
                observable=observable,
                observable_type=kind,
                verdict="malicious",
                malicious=True,
                score=100,
                confidence=1.0,
                categories=["policy"],
                details={"match": "blacklist"},
            )
            self.cache.set(cache_key, result.to_dict())
            return result

        results: list[ThreatIntelResult] = []

        vt_result = self._query_virustotal(observable, kind)
        if vt_result:
            results.append(vt_result)

        hs_result = self._query_generic_endpoint(
            source_name="hs-ti",
            settings=self.config.hs_ti,
            observable=observable,
            observable_type=kind,
            enabled=bool(self.config.hs_ti.get("enabled") and self.config.hs_ti.get("base_url")),
        )
        if hs_result:
            results.append(hs_result)

        for endpoint in self.config.custom_ti_endpoints:
            custom = self._query_generic_endpoint(
                source_name=endpoint.get("name", "custom-ti"),
                settings=endpoint,
                observable=observable,
                observable_type=kind,
                enabled=bool(endpoint.get("base_url")),
            )
            if custom:
                results.append(custom)

        aggregated = self._aggregate(observable, kind, results)
        self.cache.set(cache_key, aggregated.to_dict())
        return aggregated

    def check_file(self, file_path: str | Path) -> ThreatIntelResult:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return ThreatIntelResult(
                source="filesystem",
                observable=str(path),
                observable_type="file",
                verdict="missing",
                malicious=False,
                score=0,
                confidence=0.0,
                categories=["missing"],
                details={"exists": False},
            )

        hashes = {
            "md5": self._hash_file(path, "md5"),
            "sha1": self._hash_file(path, "sha1"),
            "sha256": self._hash_file(path, "sha256"),
        }

        result = self.check_observable(hashes["sha256"], "hash")
        result.details.setdefault("file", {})
        result.details["file"] = {
            "path": str(path),
            **hashes,
        }

        if result.verdict == "unknown" and self.config.upload_unknown_files and self.config.vt_api_key:
            result.details["upload"] = self._upload_file_to_virustotal(path)

        return result

    def _aggregate(
        self,
        observable: str,
        observable_type: str,
        results: list[ThreatIntelResult],
    ) -> ThreatIntelResult:
        if not results:
            return ThreatIntelResult(
                source="none",
                observable=observable,
                observable_type=observable_type,
                verdict="unknown",
                malicious=False,
                score=0,
                confidence=0.0,
                categories=["unknown"],
                details={"message": "No threat-intel providers are configured or returned a result."},
            )

        verdict = "malicious" if any(result.malicious for result in results) else "clean"
        if all(result.verdict == "unknown" for result in results):
            verdict = "unknown"

        return ThreatIntelResult(
            source=", ".join(result.source for result in results),
            observable=observable,
            observable_type=observable_type,
            verdict=verdict,
            malicious=any(result.malicious for result in results),
            score=max(result.score for result in results),
            confidence=max(result.confidence for result in results),
            categories=sorted({category for result in results for category in result.categories}),
            details={"sources": [result.to_dict() for result in results]},
            latency_ms=round(sum(result.latency_ms for result in results), 2),
        )

    def _query_virustotal(self, observable: str, observable_type: str) -> ThreatIntelResult | None:
        if not self.config.vt_api_key:
            return None

        headers = {"x-apikey": self.config.vt_api_key}
        if observable_type == "hash":
            url = f"{VT_API_BASE}/files/{observable}"
        elif observable_type == "domain":
            url = f"{VT_API_BASE}/domains/{observable}"
        elif observable_type == "ip":
            url = f"{VT_API_BASE}/ip_addresses/{observable}"
        else:
            encoded = base64.urlsafe_b64encode(observable.encode("utf-8")).decode("utf-8").rstrip("=")
            url = f"{VT_API_BASE}/urls/{encoded}"

        payload, latency_ms = self._request("GET", url, headers=headers)

        if payload.get("not_found"):
            return ThreatIntelResult(
                source="virustotal",
                observable=observable,
                observable_type=observable_type,
                verdict="unknown",
                malicious=False,
                score=0,
                confidence=0.2,
                categories=["unseen"],
                details=payload,
                latency_ms=latency_ms,
            )

        if payload.get("error"):
            return ThreatIntelResult(
                source="virustotal",
                observable=observable,
                observable_type=observable_type,
                verdict="error",
                malicious=False,
                score=0,
                confidence=0.0,
                categories=["error"],
                details=payload,
                latency_ms=latency_ms,
            )

        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        harmless_count = int(stats.get("harmless", 0))
        undetected_count = int(stats.get("undetected", 0))
        total = max(malicious_count + suspicious_count + harmless_count + undetected_count, 1)
        reputation = int(attributes.get("reputation", 0))

        score = min(100, (malicious_count * 18) + (suspicious_count * 10) + max(0, -reputation))
        malicious = malicious_count > 0 or suspicious_count >= 3 or reputation < -25
        confidence = round((malicious_count + suspicious_count + harmless_count) / total, 2)

        categories = []
        if malicious_count > 0:
            categories.append("malicious")
        if suspicious_count > 0:
            categories.append("suspicious")
        if not categories:
            categories.append("clean")

        return ThreatIntelResult(
            source="virustotal",
            observable=observable,
            observable_type=observable_type,
            verdict="malicious" if malicious else "clean",
            malicious=malicious,
            score=score,
            confidence=confidence,
            categories=categories,
            details={
                "reputation": reputation,
                "last_analysis_stats": stats,
                "last_modification_date": attributes.get("last_modification_date"),
            },
            latency_ms=latency_ms,
        )

    def _query_generic_endpoint(
        self,
        source_name: str,
        settings: dict[str, Any],
        observable: str,
        observable_type: str,
        enabled: bool,
    ) -> ThreatIntelResult | None:
        if not enabled:
            return None

        base_url = str(settings.get("base_url", "")).rstrip("/")
        if not base_url:
            return None

        headers: dict[str, str] = {}
        auth_header = settings.get("auth_header")
        api_key = settings.get("api_key") or self.config.hs_ti.get("api_key")
        if auth_header and api_key:
            headers[str(auth_header)] = str(api_key)

        method = str(settings.get("method", "GET")).upper()
        path = str(settings.get("observable_path", "/lookup"))
        params = {
            str(settings.get("value_param", "value")): observable,
            str(settings.get("type_param", "type")): observable_type,
        }

        payload, latency_ms = self._request(method, f"{base_url}{path}", headers=headers, params=params)
        if payload.get("error"):
            return ThreatIntelResult(
                source=source_name,
                observable=observable,
                observable_type=observable_type,
                verdict="error",
                malicious=False,
                score=0,
                confidence=0.0,
                categories=["error"],
                details=payload,
                latency_ms=latency_ms,
            )

        score = int(payload.get("score") or payload.get("risk_score") or 0)
        severity = str(payload.get("severity") or payload.get("verdict") or "").lower()
        malicious = bool(payload.get("malicious") or score >= 60 or severity in {"high", "critical", "malicious"})
        categories = payload.get("categories") or payload.get("labels") or []
        if isinstance(categories, str):
            categories = [categories]

        return ThreatIntelResult(
            source=source_name,
            observable=observable,
            observable_type=observable_type,
            verdict="malicious" if malicious else "clean",
            malicious=malicious,
            score=score,
            confidence=float(payload.get("confidence", 0.6 if payload else 0.0)),
            categories=list(categories),
            details=payload,
            latency_ms=latency_ms,
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], float]:
        start = perf_counter()
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                timeout=self.config.request_timeout_seconds,
            )
            latency_ms = round((perf_counter() - start) * 1000, 2)
            if response.status_code == 404:
                return {"not_found": True}, latency_ms

            response.raise_for_status()
            try:
                return response.json(), latency_ms
            except ValueError:
                return {"text": response.text}, latency_ms
        except requests.RequestException as exc:
            latency_ms = round((perf_counter() - start) * 1000, 2)
            return {"error": str(exc)}, latency_ms

    def _upload_file_to_virustotal(self, path: Path) -> dict[str, Any]:
        headers = {"x-apikey": self.config.vt_api_key}
        start = perf_counter()
        try:
            with path.open("rb") as handle:
                response = requests.post(
                    f"{VT_API_BASE}/files",
                    headers=headers,
                    files={"file": (path.name, handle)},
                    timeout=self.config.request_timeout_seconds,
                )
            latency_ms = round((perf_counter() - start) * 1000, 2)
            response.raise_for_status()
            return {
                "submitted": True,
                "latency_ms": latency_ms,
                "response": response.json(),
            }
        except requests.RequestException as exc:
            return {
                "submitted": False,
                "error": str(exc),
            }

    @staticmethod
    def _hash_file(path: Path, algorithm: str) -> str:
        digest = hashlib.new(algorithm)
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()
