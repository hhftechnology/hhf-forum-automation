"""Ubuntu Security Notices JSON API (https://ubuntu.com/security/notices.json)."""
from __future__ import annotations

from .base import Fetcher, SourceError, default_fetcher

URL = "https://ubuntu.com/security/notices.json"
ATTRIBUTION = "Ubuntu Security Notices (https://ubuntu.com/security/notices), (c) Canonical Ltd."


def notices_for_cve(cve: str, fx: Fetcher | None = None) -> list[dict]:
    fx = fx or default_fetcher()
    d = fx.get_json(URL, params={"details": cve, "limit": 5, "order": "newest"}, ttl=6 * 3600)
    out = []
    for n in d.get("notices", []):
        ids = [str(x).upper() for x in (n.get("cves_ids") or [])]
        if cve.upper() in ids:
            out.append({"id": n["id"], "title": n.get("title", ""), "published": n.get("published"),
                        "url": f"https://ubuntu.com/security/notices/{n['id']}"})
    return out


def usn_map(cves: list[str], fx: Fetcher | None = None, limit: int = 30) -> dict[str, list[dict]]:
    out, errors = {}, 0
    for c in cves[:limit]:
        try:
            n = notices_for_cve(c, fx)
        except SourceError:
            errors += 1
            if errors >= 2:  # source is down or slow: do not stall the run
                break
            continue
        if n:
            out[c.upper()] = n
    return out
