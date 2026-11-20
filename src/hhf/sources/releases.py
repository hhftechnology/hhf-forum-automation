"""GitHub releases of a repo (REST /repos/{repo}/releases). GITHUB_TOKEN is optional."""
from __future__ import annotations

import os
import time

import httpx

class ReleaseFetchError(RuntimeError):
    pass


class ReleaseRateLimit(ReleaseFetchError):
    pass


def latest(repo: str, per_page: int = 100) -> list[dict]:
    """Read all release pages. Failure is distinct from a repository with no releases."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    result = []
    page = 1
    try:
        while True:
            for attempt in range(5):
                r = httpx.get(f"https://api.github.com/repos/{repo}/releases", params={"per_page": per_page, "page": page},
                              headers=headers, timeout=20.0)
                limited = r.status_code == 429 or (r.status_code == 403 and
                          ("retry-after" in r.headers or r.headers.get("x-ratelimit-remaining") == "0"))
                if not limited:
                    break
                if attempt == 4:
                    raise ReleaseRateLimit(f"GitHub rate limit for {repo}; resume later")
                delay = max(float(r.headers.get("retry-after", 2 ** attempt)),
                            float(r.headers.get("x-ratelimit-reset", 0)) - time.time(), 0)
                if delay > 60:
                    raise ReleaseRateLimit(f"GitHub rate limit for {repo}; resume later")
                time.sleep(delay)
            r.raise_for_status()
            rows = r.json()
            if not isinstance(rows, list):
                raise ValueError("invalid release list")
            result.extend({"repo": repo, "id": x["id"], "tag": x.get("tag_name"),
                           "name": x.get("name") or x.get("tag_name"), "url": x["html_url"],
                           "published_at": x.get("published_at"), "prerelease": bool(x.get("prerelease")),
                           "body": x.get("body") or ""} for x in rows if not x.get("draft"))
            if not r.links.get("next"):
                return result
            page += 1
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        raise ReleaseFetchError(f"GitHub releases unavailable for {repo}: {type(exc).__name__}") from None
