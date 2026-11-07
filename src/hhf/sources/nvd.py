"""NVD CVE API 2.0. Optional key in the apiKey header (never in the URL)."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from .base import Fetcher, SourceError, default_fetcher

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTRIBUTION = "This product uses data from the NVD API but is not endorsed or certified by the NVD (https://nvd.nist.gov)."


def _headers() -> dict:
    k = os.environ.get("NVD_API_KEY")
    return {"apiKey": k} if k else {}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _metric(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        ms = metrics.get(name) or []
        if not ms:
            continue
        ms = sorted(ms, key=lambda m: m.get("type") != "Primary")
        d = ms[0].get("cvssData", {})
        sev = (d.get("baseSeverity") or ms[0].get("baseSeverity") or "").lower() or None
        return d.get("baseScore"), sev, d.get("vectorString")
    return None, None, None


def _cpes(cve: dict) -> list[tuple[str, str]]:
    out = []

    def walk(nodes):
        for n in nodes:
            for m in n.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4 and m.get("vulnerable", True):
                    out.append((parts[3].lower(), parts[4].lower()))
            walk(n.get("nodes", []))

    for c in cve.get("configurations", []) or []:
        walk(c.get("nodes", []))
    return sorted(set(out))


def normalize(vuln: dict) -> dict:
    c = vuln.get("cve", vuln)
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score, sev, vector = _metric(c.get("metrics", {}))
    return {
        "id": c["id"].upper(),
        "published": c.get("published"),
        "description": desc,
        "cvss": score,
        "severity": sev,
        "vector": vector,
        "references": [{"url": r["url"], "tags": r.get("tags", [])} for r in c.get("references", [])],
        "cpes": _cpes(c),
        "status": c.get("vulnStatus"),
    }


def fetch_window(start: datetime, end: datetime, severities=("CRITICAL", "HIGH"),
                 fx: Fetcher | None = None, max_pages: int = 6) -> list[dict]:
    fx = fx or default_fetcher()
    out: dict[str, dict] = {}
    for sev in severities:
        idx = 0
        for _ in range(max_pages):
            params = {
                "pubStartDate": _iso(start), "pubEndDate": _iso(end),
                "cvssV3Severity": sev, "resultsPerPage": 2000, "startIndex": idx,
            }
            data = fx.get_json(URL, params=params, headers=_headers(), ttl=3600)
            for v in data.get("vulnerabilities", []):
                n = normalize(v)
                out[n["id"]] = n
            idx += data.get("resultsPerPage", 0) or 0
            if idx >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
                break
    return list(out.values())


def get_cve(cve_id: str, fx: Fetcher | None = None) -> dict | None:
    fx = fx or default_fetcher()
    try:
        data = fx.get_json(URL, params={"cveId": cve_id}, headers=_headers(), ttl=6 * 3600)
    except SourceError:
        return None
    vs = data.get("vulnerabilities", [])
    return normalize(vs[0]) if vs else None


def window_days(days: int, now: datetime | None = None) -> tuple[datetime, datetime]:
    now = now or datetime.now(timezone.utc)
    return now - timedelta(days=days), now
