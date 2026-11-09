"""POST to the forum's discourse-workflows webhook.

The bearer token and webhook URL come from the environment and are never logged.
"""
from __future__ import annotations

import logging
import os
import time

import httpx

log = logging.getLogger("hhf.webhook")

URL_ENV = {"release": "WORKFLOW_WEBHOOK_URL_RELEASE"}


class DeliveryError(RuntimeError):
    pass


def configured(kind: str) -> bool:
    return bool(os.environ.get(URL_ENV[kind]) and os.environ.get("WORKFLOW_WEBHOOK_TOKEN"))


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
