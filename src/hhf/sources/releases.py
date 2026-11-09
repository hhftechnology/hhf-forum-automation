"""GitHub releases of a repo (REST /repos/{repo}/releases). GITHUB_TOKEN is optional."""
from __future__ import annotations

import logging
import os

import httpx

log = logging.getLogger("hhf.releases")


def latest(repo: str, per_page: int = 5) -> list[dict]:
    """Non-draft releases, newest first. A failed request returns [] so one repo never stops the run."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = httpx.get(f"https://api.github.com/repos/{repo}/releases", params={"per_page": per_page},
                      headers=headers, timeout=20.0)
        r.raise_for_status()
        rows = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("releases fetch failed for %s: %s", repo, type(exc).__name__)
        return []
    return [{
        "repo": repo, "tag": x.get("tag_name"), "name": x.get("name") or x.get("tag_name"),
        "url": x.get("html_url"), "prerelease": bool(x.get("prerelease")), "body": x.get("body") or "",
    } for x in rows if not x.get("draft")]
