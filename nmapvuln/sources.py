"""Vulnerability data sources: NVD 2.0 and Vulners.

Both clients speak plain urllib so the tool has no third-party dependencies.
Every response goes through the cache, and NVD's published rate limits are
honoured rather than discovered the hard way.
"""

from __future__ import annotations

import gzip
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from .cache import Cache
from .model import Finding, severity_from_score

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULNERS_URL = "https://vulners.com/api/v3/burp/software/"

USER_AGENT = "nmapvuln/1.0 (+scan validation and CVE correlation)"


class RateLimiter:
    """NVD allows 5 requests / 30s anonymously, 50 / 30s with an API key."""

    def __init__(self, requests: int, window: float):
        self.requests = max(1, requests)
        self.window = window
        self._hits: list[float] = []
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._hits = [t for t in self._hits if now - t < self.window]
            if len(self._hits) >= self.requests:
                sleep_for = self.window - (now - self._hits[0]) + 0.25
                if sleep_for > 0:
                    time.sleep(sleep_for)
                now = time.monotonic()
                self._hits = [t for t in self._hits if now - t < self.window]
            self._hits.append(time.monotonic())


class HttpError(Exception):
    pass


def _http(
    url: str,
    *,
    headers: Optional[dict] = None,
    data: Optional[bytes] = None,
    timeout: int = 45,
    retries: int = 3,
) -> Any:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json", "Accept-Encoding": "gzip"}
    if headers:
        hdrs.update(headers)
    if data is not None:
        hdrs.setdefault("Content-Type", "application/json")

    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            last_exc = exc
            # 403/429 from NVD means throttling, not a permission problem.
            if exc.code in (403, 429, 503) and attempt < retries - 1:
                time.sleep(6 * (attempt + 1))
                continue
            raise HttpError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(3 * (attempt + 1))
                continue
            raise HttpError(str(exc)) from exc
    raise HttpError(str(last_exc))


class NVDClient:
    def __init__(self, cache: Cache, api_key: str = "", verbose: bool = False):
        self.cache = cache
        self.api_key = api_key
        self.verbose = verbose
        self.limiter = RateLimiter(45 if api_key else 4, 30.0)
        self.request_count = 0
        self.errors: list[str] = []

    def _get(self, params: dict) -> Optional[dict]:
        query = urllib.parse.urlencode(params)
        key = f"nvd:{query}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached

        headers = {"apiKey": self.api_key} if self.api_key else {}
        self.limiter.wait()
        self.request_count += 1
        if self.verbose:
            print(f"  [nvd] {query}", file=sys.stderr)
        try:
            payload = _http(f"{NVD_URL}?{query}", headers=headers)
        except HttpError as exc:
            self.errors.append(f"NVD query failed ({query}): {exc}")
            return None
        self.cache.put(key, payload)
        return payload

    def by_cpe(self, cpe23: str) -> list[dict]:
        """CVEs whose applicability configuration matches this CPE."""
        return self._collect({"virtualMatchString": cpe23, "resultsPerPage": 500})

    def by_keyword(self, keyword: str) -> list[dict]:
        return self._collect({"keywordSearch": keyword, "resultsPerPage": 200})

    def _collect(self, params: dict) -> list[dict]:
        out: list[dict] = []
        start = 0
        while True:
            page = dict(params, startIndex=start)
            payload = self._get(page)
            if not payload:
                break
            vulns = payload.get("vulnerabilities", []) or []
            out.extend(v.get("cve", {}) for v in vulns if v.get("cve"))
            total = payload.get("totalResults", 0)
            start += payload.get("resultsPerPage", len(vulns)) or len(vulns)
            if start >= total or not vulns or start >= 2000:
                break
        return out


def finding_from_nvd(cve: dict) -> tuple[str, Optional[float], str, str, str, str, list[str]]:
    """Flatten an NVD CVE record into the fields the report needs."""
    cve_id = cve.get("id", "")

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "").strip()
            break

    score: Optional[float] = None
    vector = ""
    severity = ""
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {}) or {}
        score = data.get("baseScore")
        vector = data.get("vectorString", "")
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity") or ""
        break

    if not severity:
        severity = severity_from_score(score)

    published = (cve.get("published") or "")[:10]

    references = []
    for ref in cve.get("references", []) or []:
        url = ref.get("url")
        if url:
            references.append(url)

    return cve_id, score, vector, severity.upper(), published, description, references[:8]


class VulnersClient:
    """Vulners' software endpoint — the same data the vulners NSE script uses.

    An API key is required; without one the client stays disabled and the run
    silently falls back to NVD only.
    """

    def __init__(self, cache: Cache, api_key: str = "", verbose: bool = False):
        self.cache = cache
        self.api_key = api_key
        self.verbose = verbose
        self.enabled = bool(api_key)
        self.request_count = 0
        self.errors: list[str] = []
        self.limiter = RateLimiter(8, 10.0)

    def by_software(self, product: str, version: str) -> list[dict]:
        if not self.enabled or not product or not version:
            return []
        key = f"vulners:{product.lower()}:{version}"
        cached = self.cache.get(key)
        if cached is None:
            body = json.dumps(
                {
                    "software": product,
                    "version": version,
                    "type": "software",
                    "maxVulnerabilities": 60,
                    "apiKey": self.api_key,
                }
            ).encode("utf-8")
            self.limiter.wait()
            self.request_count += 1
            if self.verbose:
                print(f"  [vulners] {product} {version}", file=sys.stderr)
            try:
                cached = _http(VULNERS_URL, data=body)
            except HttpError as exc:
                self.errors.append(f"Vulners query failed ({product} {version}): {exc}")
                return []
            self.cache.put(key, cached)

        if cached.get("result") != "OK":
            return []
        search = (cached.get("data") or {}).get("search") or []
        return [item.get("_source", {}) for item in search if item.get("_source")]
