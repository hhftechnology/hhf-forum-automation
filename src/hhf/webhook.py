"""Delivery: POST to the forum's discourse-workflows webhook, or --direct via discourse.py.

The bearer token and webhook URL come from the environment and are never logged.
"""
from __future__ import annotations

import logging
import os
import re
import time

import httpx

log = logging.getLogger("hhf.webhook")

URL_ENV = {"weekly_advisory": "WORKFLOW_WEBHOOK_URL_WEEKLY", "daily_briefing": "WORKFLOW_WEBHOOK_URL_DAILY"}
CATEGORY_ENV = {"weekly_advisory": "ADVISORY_DRAFTS_CATEGORY_ID", "daily_briefing": "BRIEFING_DRAFTS_CATEGORY_ID"}
CATEGORY_HINT = {"weekly_advisory": "advisory-drafts", "daily_briefing": "briefing-drafts"}
EXTERNAL_ID_RE = re.compile(r"^[\w-]{1,50}$")


class DeliveryError(RuntimeError):
    pass


def build_payload(kind: str, title: str, raw: str, tags: list[str], external_id: str) -> dict:
    if kind not in URL_ENV:
        raise ValueError(f"unknown kind {kind}")
    if not EXTERNAL_ID_RE.match(external_id):
        raise ValueError("external_id must match [\\w-]{1,50}")
    return {"kind": kind, "title": title, "raw": raw, "tags": tags,
            "external_id": external_id, "category_hint": CATEGORY_HINT[kind]}


def post_webhook(payload: dict, *, client: httpx.Client | None = None, sleep=time.sleep) -> int:
    url = os.environ.get(URL_ENV[payload["kind"]], "")
    token = os.environ.get("WORKFLOW_WEBHOOK_TOKEN", "")
    if not url or not token:
        raise DeliveryError(f"{URL_ENV[payload['kind']]} and WORKFLOW_WEBHOOK_TOKEN are required")
    own = client is None
    client = client or httpx.Client(timeout=30.0)
    try:
        for attempt in range(3):
            try:
                r = client.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
            except httpx.HTTPError as exc:
                log.warning("webhook network error %s", type(exc).__name__)
                sleep(2 ** attempt)
                continue
            if r.status_code in (429, 502, 503, 504):
                sleep(2 ** attempt * 2)
                continue
            if r.status_code >= 300:
                raise DeliveryError(f"webhook returned HTTP {r.status_code}")
            return r.status_code
        raise DeliveryError("webhook unreachable after retries")
    finally:
        if own:
            client.close()


def post_direct(payload: dict, *, client=None) -> dict:
    """Create the topic through discourse.py; idempotent on external_id."""
    from .discourse import DiscourseClient

    cid = os.environ.get(CATEGORY_ENV[payload["kind"]], "")
    if not cid.isdigit():
        raise DeliveryError(f"{CATEGORY_ENV[payload['kind']]} must be a numeric category id")
    c = client or DiscourseClient()
    existing = c.get_topic_by_external_id(payload["external_id"])
    if existing:
        return {"status": "exists", "topic_id": existing.get("id")}
    res = c.create_topic(title=payload["title"], raw=payload["raw"], category=int(cid),
                         external_id=payload["external_id"], tags=payload["tags"])
    return {"status": "created", "topic_id": res.get("topic_id"), "post_id": res.get("id")}


def deliver(payload: dict, *, direct: bool = False) -> dict:
    if direct:
        return post_direct(payload)
    return {"status": "webhook", "http": post_webhook(payload)}
