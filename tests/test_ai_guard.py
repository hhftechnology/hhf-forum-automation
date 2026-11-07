import json

import httpx
import pytest

from hhf import ai

FACTS = {"project": "Traefik", "ids": ["GHSA-xv5x-242w-7hf7", "CVE-2026-1111"], "fixed": "3.6.2",
         "affected": ">= 3.0.0, < 3.6.2", "description": "An unauthenticated client can leak 4096 bytes per connection."}
FACTS_TEXT = json.dumps(FACTS)


def test_accepts_supported_text():
    t = "Traefik before 3.6.2 leaks memory when an unauthenticated client sends headers (CVE-2026-1111)."
    assert ai.violations(t, FACTS_TEXT) == []


@pytest.mark.parametrize(
    "text,needle",
    [
        ("This is tracked as CVE-2026-9999.", "unknown id"),
        ("See GHSA-zzzz-yyyy-xxxx for more.", "unknown id"),
        ("Upgrade to 3.7.0 immediately.", "unknown version"),
        ("Fixed in v3.6.3.", "unknown version"),
        ("It leaks 8192 bytes.", "unknown number"),
        ("More at https://evil.example/x", "unknown url"),
        ("## Heading\nText", "markdown"),
    ],
)
def test_rejects_invented_facts(text, needle):
    assert any(needle in v for v in ai.violations(text, FACTS_TEXT))


def test_version_with_v_prefix_matches_facts():
    assert ai.violations("Fixed in v3.6.2.", FACTS_TEXT) == []


def test_ids_are_case_insensitive():
    assert ai.violations("see cve-2026-1111", FACTS_TEXT) == []


class Fake(ai.Provider):
    name = "fake"

    def __init__(self, reply):
        self.reply = reply

    def available(self):
        return True

    def complete(self, system, user, client, max_tokens=1200):
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_writer_rejects_bad_then_falls_back_to_next_provider():
    w = ai.AIWriter([Fake("Fixed in 9.9.9."), Fake("Traefik leaks memory until 3.6.2.")])
    assert w.prose("x", FACTS) == "Traefik leaks memory until 3.6.2."
    assert w.stats["rejected"] == 1 and w.stats["ok"] == 1


def test_writer_returns_none_when_all_fail():
    w = ai.AIWriter([Fake(ai.ProviderError("down")), Fake("CVE-2026-0000 is new")])
    assert w.prose("x", FACTS) is None


def test_writer_disabled_or_no_keys(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert ai.AIWriter().active is False
    assert ai.AIWriter([Fake("x")], enabled=False).prose("x", FACTS) is None


def test_pick_validates_against_options():
    assert ai.AIWriter([Fake("phishing")]).pick("t", ["phishing", "ddos"]) == "phishing"
    assert ai.AIWriter([Fake("something else")]).pick("t", ["phishing", "ddos"]) is None


def test_gemini_key_goes_in_header_not_url(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "SECRET-KEY-123")
    seen = {}

    def handler(req):
        seen["url"] = str(req.url)
        seen["hdr"] = req.headers.get("x-goog-api-key")
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "ok text"}]}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert ai.Gemini().complete("s", "u", client) == "ok text"
    assert "SECRET" not in seen["url"] and seen["hdr"] == "SECRET-KEY-123"


def test_github_models_endpoint_and_bearer(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    seen = {}

    def handler(req):
        seen["url"] = str(req.url)
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert ai.GitHubModels().complete("s", "u", client) == "hi"
    assert seen["url"] == "https://models.github.ai/inference/chat/completions" and seen["auth"] == "Bearer tok"
