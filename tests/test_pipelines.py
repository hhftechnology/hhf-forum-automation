import json
from datetime import date, datetime, timedelta, timezone

import pytest

from hhf import ai, daily, weekly, webhook
from hhf.facts import Advisory

WL = weekly.load_watchlist()


def build_weekly(mock_fx, posted=None, writer=None):
    return weekly.build(date(2026, 11, 1), date(2026, 11, 7), fx=mock_fx, writer=writer or ai.AIWriter(enabled=False),
                        projects=WL, posted=posted or {}, sleep=lambda s: None)


def test_watchlist_covers_required_projects():
    names = {p["name"].lower() for p in WL}
    for n in ["traefik", "caddy", "nginx", "keycloak", "authentik", "nextcloud", "immich", "jellyfin", "plex", "vaultwarden",
              "gitea", "forgejo", "home assistant", "pangolin", "crowdsec", "portainer", "proxmox", "wordpress", "pgadmin",
              "grafana", "uptime kuma", "incus", "lxd", "docker", "bind", "openssh", "synapse", "mastodon", "paperless-ngx", "n8n"]:
        assert n in names, n


def test_weekly_end_to_end(mock_fx):
    r = build_weekly(mock_fx)
    raw = r["raw"]
    assert r["title"] == "Weekly Self-Hosted Security Summary: November 1 – November 7, 2026"
    assert r["tags"] == ["security", "cve", "weekly-security", "self-hosted"]
    assert r["external_id"] == "weekly-advisory-2026-11-07"
    assert raw.startswith("Here’s a roundup of **")
    assert "Start with your edge:" in raw and "(see *Missed Earlier*)" in raw
    # reference layout
    assert "### **1. " in raw and "**Technical Details** :" in raw and "* **Severity** : " in raw
    assert "| CVE | CVSS | Exploitation | EPSS | Action |" in raw
    assert "**Remediation Steps**" in raw and "**Official References**" in raw and "**Reference** : [" in raw
    assert "## Missed Earlier" in raw and "## Sources" in raw
    # KEV item first, with CVE row + action
    assert "### **1. Keycloak" in raw and "### **2. Traefik" in raw
    assert "| CVE-2026-1111 | 9.8 | Known exploited (CISA KEV) | 0.640 (98.5th percentile) | Patch now |" in raw
    # GHSA without CVE
    assert "(no CVE yet)" in raw and "— (no CVE yet) | 7.5 | None known | N/A | Patch this week |" in raw
    # upgrade command from the watchlist image, workaround, USN, NVD references
    assert "`docker pull traefik:3.6.2`" in raw and "Disable the Negotiate header" in raw
    assert "https://ubuntu.com/security/notices/USN-9000-1" in raw and "https://nvd.nist.gov/vuln/detail/CVE-2026-1111" in raw
    # unrelated GHSA excluded, NVD-only Nextcloud included (CVSS 8.8, EPSS 0.12 -> 72h, public PoC)
    assert "left-pad" not in raw and "Unrelated" not in raw
    assert "| CVE-2026-4444 | 8.8 | Public PoC | 0.120 (91.0th percentile) | Patch within 72h |" in raw
    assert "CVE-2026-5555" not in raw  # no watchlist match
    # missed earlier: Grafana from Oct 20 (8-30 days old)
    assert raw.index("## Missed Earlier") < raw.index("Grafana older issue")
    assert "Security-related releases" in raw and "v3.6.2" in raw
    assert "SECRET" not in raw


def test_weekly_skips_already_posted(mock_fx):
    r = build_weekly(mock_fx, posted={"GHSA-aaaa-bbbb-cccc": "2026-11-01", "GHSA-gggg-hhhh-iiii": "2026-11-01"})
    body = r["raw"].split("## Sources")[0]
    assert "jwt algorithm" not in body and "Grafana older issue" not in body
    assert "Traefik" in body  # unposted items are still included


def test_weekly_ids_for_state(mock_fx):
    r = build_weekly(mock_fx)
    assert {"GHSA-xv5x-242w-7hf7", "GHSA-aaaa-bbbb-cccc", "CVE-2026-1111", "GHSA-gggg-hhhh-iiii"} <= set(r["ids"])


def test_weekly_cli_dry_run_writes_file_only(mock_fx, monkeypatch, tmp_path):
    monkeypatch.setattr(weekly, "default_fetcher", lambda: mock_fx)
    monkeypatch.setattr(webhook, "deliver", lambda *a, **k: pytest.fail("dry-run must not deliver"))
    state = tmp_path / "posted.json"
    rc = weekly.main(["--since", "2026-11-01", "--until", "2026-11-07", "--dry-run", "--no-ai",
                      "--out-dir", str(tmp_path), "--state", str(state)])
    assert rc == 0 and (tmp_path / "weekly_advisory-2026-11-07.md").exists() and not state.exists()


def test_weekly_cli_delivers_and_records_state(mock_fx, monkeypatch, tmp_path):
    monkeypatch.setattr(weekly, "default_fetcher", lambda: mock_fx)
    sent = []
    monkeypatch.setattr(webhook, "deliver", lambda p, direct=False: sent.append(p) or {"status": "webhook"})
    state = tmp_path / "posted.json"
    weekly.main(["--since", "2026-11-01", "--until", "2026-11-07", "--no-ai", "--state", str(state)])
    assert sent[0]["kind"] == "weekly_advisory" and sent[0]["category_hint"] == "advisory-drafts"
    assert "GHSA-aaaa-bbbb-cccc" in json.loads(state.read_text())["posted"]


def test_weekly_uses_ai_prose_only_when_it_passes_the_guard(mock_fx):
    class P(ai.Provider):
        name = "p"
        def available(self): return True
        def complete(self, system, user, client, max_tokens=1200):
            return "Fixed in 99.99.99 (CVE-2099-0001)." if "Technical Details" in user else "patch the proxies."

    r = build_weekly(mock_fx, writer=ai.AIWriter([P()]))
    assert "99.99.99" not in r["raw"] and "CVE-2099-0001" not in r["raw"]
    assert r["ai"]["rejected"] >= 1


def test_daily_end_to_end(mock_fx, monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("OTX_KEY", raising=False)
    fcfg = {"news": [{"name": "Test News", "url": "https://feeds.test/news.xml"}],
            "advisories": [{"name": "CISA", "url": "https://feeds.test/cisa.xml", "kind": "cisa"}]}
    now = datetime(2026, 11, 7, 5, 30, tzinfo=timezone.utc)
    r = daily.build(now - timedelta(hours=24), now, fx=mock_fx, writer=ai.AIWriter(enabled=False), fcfg=fcfg, sleep=lambda s: None)
    raw = r["raw"]
    assert r["title"] == "Daily Threat Briefing: Saturday, November 7, 2026"
    assert r["external_id"] == "daily-briefing-2026-11-07"
    for h in ["## Executive Summary", "## Threat Level Overview", "## Top Threats", "## Actively Exploited Vulnerabilities",
              "## Ransomware Activity by Sector", "## Notable IOCs", "## Recommended Actions", "## Sources"]:
        assert h in raw
    assert "| CVE | Product | CVSS | EPSS | KEV due date | Action |" in raw
    assert "| CVE-2026-1111 | Red Hat Keycloak | 9.8 | 0.640 (98.5th percentile) | 2026-11-27 | Patch now |" in raw
    assert "| Healthcare | 2 |" in raw
    assert "**Severity:** " in raw and "**Type:** " in raw and "**Industry:** " in raw
    assert r["tags"][0] == "daily-briefing" and r["tags"][1] in ("critical", "high", "medium", "low") and len(r["tags"]) <= 10
    assert "ransomware" in r["tags"]
    assert "ABUSECH_AUTH_KEY not set" in raw  # skipped optional source is explained, not silent
    assert "ransomware.live" in raw and "CISA" in raw
    assert "http://" not in raw.split("## Notable IOCs")[1].split("## Recommended")[0]


def test_daily_merges_kev_and_news_on_same_cve():
    a = daily.Threat("A", "s", "u1", "KEV", "kev", cves={"CVE-2026-1"}, score=50)
    b = daily.Threat("B", "s", "u2", "News", "news", cves={"CVE-2026-1"}, score=30)
    top = daily.select([a, b])
    assert len(top) == 1 and top[0].also == [("News", "u2")]


def test_daily_per_kind_cap():
    ts = [daily.Threat(f"n{i}", "s", f"u{i}", "N", "news", score=100 - i) for i in range(6)]
    assert len(daily.select(ts)) == 3


def test_webhook_payload_and_bearer(monkeypatch):
    import httpx
    monkeypatch.setenv("WORKFLOW_WEBHOOK_URL_DAILY", "https://forum.test/workflows/webhooks/daily")
    monkeypatch.setenv("WORKFLOW_WEBHOOK_TOKEN", "TOK")
    seen = {}

    def h(req):
        seen["auth"], seen["body"] = req.headers["authorization"], json.loads(req.content)
        return httpx.Response(200, json={"ok": True})

    p = webhook.build_payload("daily_briefing", "T", "raw", ["daily-briefing"], "daily-briefing-2026-11-07")
    assert set(p) == {"kind", "title", "raw", "tags", "external_id", "category_hint"}
    assert webhook.post_webhook(p, client=httpx.Client(transport=httpx.MockTransport(h))) == 200
    assert seen["auth"] == "Bearer TOK" and seen["body"]["category_hint"] == "briefing-drafts"
    with pytest.raises(ValueError):
        webhook.build_payload("daily_briefing", "T", "raw", [], "bad id!")
    monkeypatch.delenv("WORKFLOW_WEBHOOK_TOKEN")
    with pytest.raises(webhook.DeliveryError):
        webhook.post_webhook(p)


def test_direct_delivery_is_idempotent(monkeypatch):
    monkeypatch.setenv("BRIEFING_DRAFTS_CATEGORY_ID", "123")
    created = []

    class C:
        def __init__(self, existing): self.existing = existing
        def get_topic_by_external_id(self, eid): return {"id": 7} if self.existing else None
        def create_topic(self, **kw): return created.append(kw) or {"topic_id": 9, "id": 10}

    p = webhook.build_payload("daily_briefing", "T", "raw", ["daily-briefing"], "daily-briefing-2026-11-07")
    assert webhook.post_direct(p, client=C(True))["status"] == "exists" and not created
    assert webhook.post_direct(p, client=C(False))["status"] == "created"
    assert created[0]["category"] == 123 and created[0]["external_id"] == "daily-briefing-2026-11-07" and created[0]["tags"] == ["daily-briefing"]


def test_markdown_neutralises_untrusted_text():
    from hhf.render import render_weekly
    a = Advisory(key="CVE-1", title="x", project="p")
    out = weekly.view(a, "ping @admin <script>alert(1)</script>")
    md = render_weekly({"intro": "i", "items": [{**out, "title": "t|x"}], "missed": [], "extra": [], "releases": [],
                        "sources": [], "prose_note": "n"})
    assert "@admin" not in md and "<script>" not in md
