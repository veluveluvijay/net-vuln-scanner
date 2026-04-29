#!python3
"""
net-vuln-scanner/nvd_client.py
NVD 2.0 API client with local in-memory caching and polite rate limiting.

NVD API documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

import logging
import time
from typing import Optional

import requests

logger = logging.getLogger("nvd_client")

# NVD 2.0 base URL
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits per NVD policy (without API key: 5 req/30 s; with key: 50 req/30 s)
RATE_LIMIT_NO_KEY   = (5,  30)   # (requests, window_seconds)
RATE_LIMIT_WITH_KEY = (50, 30)


class NVDClient:
    """
    Lightweight NVD 2.0 REST API client.

    Features:
    - In-memory response cache (keyed on query string) to avoid duplicate calls.
    - Automatic rate-limit backoff: if a 429 is received, waits and retries.
    - Supports both CPE-based and keyword-based vulnerability searches.

    Parameters:
    api_key : Optional NVD API key. Register at https://nvd.nist.gov/developers/request-an-api-key
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._cache: dict = {}
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "net-vuln-scanner/1.0 (security research tool)",
        })
        if api_key:
            self._session.headers["apiKey"] = api_key
            self._rate = RATE_LIMIT_WITH_KEY
        else:
            self._rate = RATE_LIMIT_NO_KEY

        # Sliding window rate limiter state
        self._request_timestamps: list = []

    #Public Interface

    def _convert_cpe(self, cpe22: str) -> str:
        if cpe22.startswith("cpe:2.3:"):
            return cpe22
        stripped = cpe22.replace("cpe:/", "").replace("cpe://", "")
        parts = stripped.split(":")
        while len(parts) < 11:
            parts.append("*")
        return "cpe:2.3:" + ":".join(parts)

    def cves_by_cpe(self, cpe: str, max_results: int = 10) -> list:
        cpe23 = self._convert_cpe(cpe)
        params = {"cpeName": cpe23, "resultsPerPage": max_results}
        return self._query(params)

    def cves_by_keyword(self, keyword: str, max_results: int = 5) -> list:

        """
        Return CVEs whose description contains the given keyword string.

        Parameters
        
        keyword     : Product/version string, e.g. 'OpenSSH 8.2'
        max_results : Maximum number of CVEs to return.
        """
        params = {"keywordSearch": keyword, "resultsPerPage": max_results}
        return self._query(params)

    #  Internal 

    def _query(self, params: dict) -> list:

        """
        Execute an NVD API query, using cache where possible.
        Returns a list of normalised CVE dicts.
        """
        cache_key = str(sorted(params.items()))
        if cache_key in self._cache:
            logger.debug("Cache hit for %s", cache_key)
            return self._cache[cache_key]

        self._rate_limit_wait()
        data = self._get(params)
        parsed = self._parse_response(data)
        self._cache[cache_key] = parsed
        return parsed

    def _get(self, params: dict, retries: int = 3) -> dict:
        """HTTP GET with retry/back-off on 429 and transient errors."""
        for attempt in range(1, retries + 1):
            try:
                resp = self._session.get(NVD_BASE_URL, params=params, timeout=15)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 30))
                    logger.warning(
                        "NVD rate limit hit. Sleeping %ds (attempt %d/%d)",
                        retry_after, attempt, retries,
                    )
                    time.sleep(retry_after)
                    continue

                if resp.status_code == 403:
                    logger.error("NVD API returned 403 — check your API key.")
                    return {}

                resp.raise_for_status()
                return resp.json()

            except requests.exceptions.Timeout:
                logger.warning("NVD request timed out (attempt %d/%d)", attempt, retries)
                time.sleep(2 ** attempt)
            except requests.exceptions.ConnectionError as exc:
                logger.warning("Connection error: %s (attempt %d/%d)", exc, attempt, retries)
                time.sleep(2 ** attempt)
            except requests.exceptions.HTTPError as exc:
                logger.error("HTTP error: %s", exc)
                return {}

        logger.error("NVD query failed after %d attempts.", retries)
        return {}

    def _rate_limit_wait(self) -> None:
        """
        Enforce NVD's sliding-window rate limit by sleeping when needed.
        """
        max_req, window = self._rate
        now = time.time()
        # Purge timestamps outside the window
        self._request_timestamps = [
            t for t in self._request_timestamps if now - t < window
        ]
        if len(self._request_timestamps) >= max_req:
            oldest = self._request_timestamps[0]
            sleep_for = window - (now - oldest) + 0.1
            if sleep_for > 0:
                logger.debug("Rate limit: sleeping %.1fs", sleep_for)
                time.sleep(sleep_for)
        self._request_timestamps.append(time.time())

    def _parse_response(self, data: dict) -> list:
        """
        Convert a raw NVD JSON response into a list of normalised CVE dicts.

        Each dict contains:
            id          : CVE-YYYY-NNNNN
            description : English description string
            cvss_score  : CVSS v3.1 base score (float), fallback to v2 score or 0.0
            cvss_vector : CVSS vector string
            severity    : CRITICAL / HIGH / MEDIUM / LOW / NONE
            references  : list of reference URL strings
            published   : ISO 8601 date string
            modified    : ISO 8601 date string
        """
        vulnerabilities = data.get("vulnerabilities", [])
        results = []

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            # Description (English preferred)
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available.",
            )

            # CVSS — prefer v3.1, fall back to v3.0, then v2
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            cvss_vector = "N/A"

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    if key.startswith("cvssMetricV3"):
                        cvss_score = float(m.get("cvssData", {}).get("baseScore", 0))
                        cvss_vector = m.get("cvssData", {}).get("vectorString", "N/A")
                    else:  # v2
                        cvss_score = float(m.get("cvssData", {}).get("baseScore", 0))
                        cvss_vector = m.get("cvssData", {}).get("vectorString", "N/A")
                    break

            severity = _cvss_to_severity(cvss_score)

            # References
            references = [
                r.get("url", "")
                for r in cve.get("references", [])
                if r.get("url")
            ]

            results.append({
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity": severity,
                "references": references[:5],   # cap at 5 per CVE
                "published": cve.get("published", ""),
                "modified": cve.get("lastModified", ""),
            })

        return results


# Module-level helper (mirrors scanner.py to avoid circular import)

def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
