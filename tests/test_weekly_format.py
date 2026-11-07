"""Layout tests for the weekly advisory (reference: forum topic 4696, tests/fixtures/format/reference_4696.md)."""
import json
import re
from datetime import date, datetime, timezone

import httpx
import pytest

from conftest import make_router
from hhf import ai, weekly
from hhf.facts import Advisory, fmt_epss, has_public_poc, is_exploit_reference, md_text, ordinal
from hhf.render import _env, render_weekly
from hhf.sources import ghsa as ghsa_src
from hhf.sources.base import Fetcher
from hhf.textfmt import (fit_title, humanize_range, humanize_ranges, is_pseudo, scrub_pseudo, short_title,
                         strip_project, title_case)

WL = weekly.load_watchlist()


# ---- fixture set mirroring the reference's first three items -----------------------------------
def _ghsa(ghsa, title, repo, sev, cvss, desc, vulns, pub="2026-11-02T10:00:00Z", cve=None):
    return {"ghsa_id": ghsa, "cve_id": cve, "html_url": f"https://github.com/advisories/{ghsa}", "summary": title,
            "description": desc, "severity": sev, "cvss": {"score": cvss} if cvss else None, "published_at": pub,
            "source_code_location": f"https://github.com/{repo}", "references": [], "withdrawn_at": None,
            "vulnerabilities": vulns}


def _v(eco, name, rng, fixed):
    return {"package": {"ecosystem": eco, "name": name}, "vulnerable_version_range": rng, "first_patched_version": fixed}


GHSAS = [
    _ghsa("GHSA-xv5x-242w-7hf7", "Traefik has an unauthenticated NTLM/Negotiate header memory exhaustion bug", "traefik/traefik",
          "high", 7.5, "### Summary\n\nAny request with an `Authorization: NTLM` header leaks memory.\n\n### Workarounds\n\n"
          "Strip `Authorization: NTLM` headers at an upstream proxy.\n",
          [_v("go", "github.com/traefik/traefik/v2", ">= v2.11.58, <= v2.11.60", "v2.11.61"),
           _v("go", "github.com/traefik/traefik/v3", ">= v3.7.14, <= v3.7.16", "v3.7.17")]),
    _ghsa("GHSA-r766-rf9f-588h", "Caddy: {host} in root lets clients escape the site tree", "caddyserver/caddy", "high", None,
          "If you build the site root from the Host header the client picks the directory.",
          [_v("go", "github.com/caddyserver/caddy/v2", "<= 2.11.7", "2.11.8")], pub="2026-11-04T10:00:00Z"),
    _ghsa("GHSA-f278-mgc7-46j3", "Caddy php_fastcgi path rule bypass via dot segments", "caddyserver/caddy", "high", 7.1,
          "Bypass.", [_v("go", "github.com/caddyserver/caddy/v2", "< 2.11.8", "2.11.8")], pub="2026-11-04T09:00:00Z"),
    _ghsa("GHSA-jf74-f69g-hcj9", "Caddy file_server exposes TLS private keys", "caddyserver/caddy", "high", 7.5,
          "Keys exposed.", [_v("go", "github.com/caddyserver/caddy/v2", "< 2.11.8", "2.11.8")], pub="2026-11-04T08:00:00Z"),
    {**_ghsa("GHSA-j97h-3f8r-mrjr", "Keycloak JWT algorithm confusion", "keycloak/keycloak", "critical", 9.8,
             "Heap overflow.", [_v("maven", "org.keycloak:keycloak-services", "< 26.6.4", "26.6.4")], pub="2026-10-06T10:00:00Z"),
     "github_reviewed_at": "2026-10-30T10:00:00Z"},
]


def _nvd(cve, desc, score):
    return {"cve": {"id": cve, "published": "2026-11-03T09:00:00.000", "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": desc}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*"}]}]}],
                    "references": []}}


NVD = {"resultsPerPage": 3, "startIndex": 0, "totalResults": 3, "vulnerabilities": [
    _nvd("CVE-2026-94300", "BIND 9 named GSS-TSIG security context reuse can corrupt memory.", 8.1),
    _nvd("CVE-2026-19630", "BIND 9 unlimited compression pointer processing burns CPU.", 7.5),
    _nvd("CVE-2026-96888", "BIND 9 crashes with redirect zones and qname-minimization strict.", 7.5)]}
USN = {"notices": [{"id": "USN-8969-1", "title": "bind9", "published": "2026-11-03T10:00:00",
                    "cves_ids": ["CVE-2026-94300"]}]}


@pytest.fixture
def golden_fx(tmp_path):
    def gh(req):
        rows = GHSAS if req.url.params.get("severity") == "high" else [g for g in GHSAS if g["severity"] == "critical"]
        return httpx.Response(200, text=json.dumps(rows))

    def nvd(req):
        if req.url.params.get("cveId"):
            return httpx.Response(200, json={"vulnerabilities": []})
        return httpx.Response(200, json=NVD if req.url.params.get("cvssV3Severity") == "HIGH" else
                              {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []})

    def ubuntu(req):
        return httpx.Response(200, json=USN if "CVE-2026-94300" in req.url.params.get("details", "") else {"notices": []})

    h = make_router({"api.github.com/advisories": gh, "services.nvd.nist.gov/rest/json/cves/2.0": nvd,
                     "ubuntu.com/security/notices.json": ubuntu})
    client = httpx.Client(transport=httpx.MockTransport(h), follow_redirects=True)
    return Fetcher(cache_dir=tmp_path / "c", client=client, sleep=lambda s: None, max_retries=0)


def build(fx, **kw):
    return weekly.build(date(2026, 10, 29), date(2026, 11, 4), fx=fx, writer=ai.AIWriter(enabled=False),
                        projects=WL, posted={}, sleep=lambda s: None, **kw)


def test_golden_structure(golden_fx):
    r = build(golden_fx)
    raw = r["raw"]
    assert r["title"] == "🚨 Weekly Self-Hosted Security Summary (October 29 – November 4, 2026)"
    lines = raw.split("\n")

    # intro: counts advisories, singular/plural, missed project names, edge then patch-fast skeleton
    m = re.match(r"^Here’s a roundup of \*\*(\d+) critical/high security issues\*\* disclosed this week affecting popular "
                 r"open-source self-hosted projects, plus \*\*1 earlier advisory for Keycloak\*\* we hadn’t covered yet "
                 r"\(see \*Missed Earlier\*\)\. Start with your edge: (.+)\.( Then patch fast: .+\.)?$", lines[0])
    assert m, lines[0]
    assert int(m.group(1)) == 7  # 1 Traefik + 3 BIND + 3 Caddy advisories (not items)
    assert "Start with your edge: Start with your edge" not in raw
    assert "Traefik" in m.group(2) and "Caddy" in m.group(2) and "BIND" in m.group(2)

    heads = [ln for ln in lines if ln.startswith("### ")]
    assert [h.split(".")[0] for h in heads] == ["### **1", "### **2", "### **3", "### **4"]
    assert all(re.fullmatch(r"### \*\*\d+\. [^:]+: .+\*\*", h) for h in heads)
    assert heads[0].startswith("### **1. BIND: ") or heads[0].startswith("### **1. Traefik: ") or heads[0].startswith("### **1. Caddy: ")

    # Traefik item: GHSA only, two Go modules, exact bullets
    t = raw[raw.index("### **", raw.index("Traefik: ") - 10):]
    t = t.split("\n---\n")[0]
    assert "**GHSA-xv5x-242w-7hf7** (no CVE yet) | Disclosed: November 2, 2026  \n**Project** : Traefik\n" in t  # hard break
    assert "\n\n**Technical Details** : " in t
    for label in ("Severity", "Affected", "Fixed", "Workaround"):
        assert f"\n* **{label}** : " in t
    assert "* **Severity** : High (CVSS 7.5)" in t
    assert "* **Affected** : v2.11.58 – v2.11.60, v3.7.14 – v3.7.16" in t
    assert "* **Fixed** : v2.11.61, v3.7.17" in t
    assert "| CVE | CVSS | Exploitation | EPSS | Action |\n|---|---|---|---|---|\n| GHSA-xv5x-242w-7hf7 | 7.5 | None known | N/A | Patch this week |" in t
    steps = [ln for ln in t.split("\n") if ln.startswith("**Remediation Steps**")]
    assert len(steps) == 1 and re.fullmatch(r"\*\*Remediation Steps\*\* : 1\. .+ 2\. .+", steps[0])
    assert "review" not in steps[0].lower() and "verify" not in steps[0].lower()
    assert "\n**Reference** : [GHSA-xv5x-242w-7hf7](https://github.com/traefik/traefik/security/advisories/GHSA-xv5x-242w-7hf7)\n" in t
    assert "Official References" not in raw

    # BIND item: three CVEs folded into one, USN link, "and N more"
    b = raw[raw.index("**CVE-2026-94300**"):].split("\n---\n")[0]
    assert b.startswith("**CVE-2026-94300** (and 2 more, incl. CVE-2026-19630, CVE-2026-96888) | Disclosed: November 3, 2026  \n**Project** : BIND")
    assert b.count("\n| CVE-2026-") == 3
    assert "[USN-8969-1](https://ubuntu.com/security/notices/USN-8969-1)" in b

    # Caddy item: primary is the highest CVSS of three Highs; 3 GHSAs on the Reference line, 3 table rows
    c = raw[raw.index("**GHSA-jf74-f69g-hcj9**"):].split("\n---\n")[0]
    assert c.startswith("**GHSA-jf74-f69g-hcj9** (no CVE yet, and 2 more, incl. GHSA-f278-mgc7-46j3, GHSA-r766-rf9f-588h) | Disclosed")
    assert "* **Severity** : High (CVSS 7.5)" in c and "* **Affected** : before 2.11.8" in c
    assert "GHSA-r766-rf9f-588h | N/A | None known" in c  # no CVSS score yet -> N/A in the table
    ref = [ln for ln in c.split("\n") if ln.startswith("**Reference**")][0]
    assert ref.count(" / ") == 2 and "All Caddy advisories" not in ref
    assert c.count("\n| GHSA-") == 3
    assert re.search(r"^### \*\*\d\. Caddy: .*, 2 More\*\*$", raw, re.M)

    # footer order
    order = ["## **Key Takeaways This Week**", "**Recommendation** : Review your self-hosted stack this weekend and prioritize "
             "upgrades for any of the above projects you’re running.", "Stay secure!",
             "*Questions or need config help? Post in [Help](https://forum.hhf.technology/c/help/85).*", "## **Missed Earlier**",
             "These came out before this week and weren’t in an earlier summary. They only reached the GitHub global advisory "
             "database this week.", "### **4. Keycloak: ", "*Data: GitHub Advisory Database, NVD, FIRST EPSS, CISA KEV, Ubuntu Security Notices.*"]
    pos = [raw.index(x) for x in order]
    assert pos == sorted(pos)
    bullets = [ln for ln in raw[pos[0]:pos[1]].split("\n") if ln.startswith("* ")]
    assert 4 <= len(bullets) <= 7 and all(re.match(r"^\* \*\*[^*]+\*\*", b) for b in bullets)
    assert "---\n\n## **Missed Earlier**" in raw
    assert "(added to GitHub Advisory Database October 30)" in raw
    for gone in ("Also disclosed this week", "Security-related releases", "## Sources", "&lt;", "&gt;"):
        assert gone not in raw
    assert len(raw) < 30000


# ---- unit tests ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("n,s", [(1, "1st"), (2, "2nd"), (3, "3rd"), (4, "4th"), (11, "11th"), (12, "12th"), (13, "13th"),
                                 (21, "21st"), (22, "22nd"), (23, "23rd"), (61, "61st"), (101, "101st"), (111, "111th"), (0, "0th")])
def test_ordinal(n, s):
    assert ordinal(n) == s


def test_epss_format():
    assert fmt_epss(0.004, 0.61) == "0.4% (61st percentile)"
    assert fmt_epss(0.003, 0.232) == "0.3% (23rd percentile)"
    assert fmt_epss(0.0002, 0.05) == "0.02% (5th percentile)"
    assert fmt_epss(0.5, None) == "50.0%"


def test_pseudo_versions_never_shown_raw():
    pv = "0.0.0-20260102150405-abcdef123456"
    assert is_pseudo(pv) and is_pseudo("v0.0.0-20260102150405-abcdef123456") and not is_pseudo("v1.2.3")
    assert scrub_pseudo(f"fixed in v{pv}") == "fixed in commit abcdef1"
    assert humanize_range(f"< {pv}") == "before commit abcdef1"


def _pseudo_adv():
    g = _ghsa("GHSA-aaaa-bbbb-cccc", "Gitea flaw", "go-gitea/gitea", "high", 7.5, "d",
              [_v("go", "code.gitea.io/gitea", "< 0.0.0-20260102150405-abcdef123456", "0.0.0-20260102150405-abcdef123456")])
    return weekly.advisory_from_ghsa(ghsa_src.normalize(g), next(p for p in WL if p["name"] == "Gitea"))


def _fx(tmp_path, routes):
    def handler(req):
        key = f"{req.url.host}{req.url.path}"
        if key in routes:
            return httpx.Response(200, json=routes[key])
        return httpx.Response(404, json={})
    return Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda s: None, max_retries=0)


def test_pseudo_resolved_from_repo_advisory(tmp_path):
    a = _pseudo_adv()
    assert a.fixed == "" and a.pseudo
    fx = _fx(tmp_path, {"api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-aaaa-bbbb-cccc":
                        {"vulnerabilities": [{"patched_versions": "1.24.5"}]}})
    weekly.resolve_pseudo(a, fx)
    assert a.fixed == "1.24.5" and a.fixed_version == "1.24.5"


def test_pseudo_resolved_from_release_after_commit(tmp_path):
    a = _pseudo_adv()
    rels = [{"tag_name": "v1.25.0", "html_url": "u", "published_at": "2026-03-01T00:00:00Z", "body": ""},
            {"tag_name": "v1.24.9", "html_url": "u", "published_at": "2026-01-10T00:00:00Z", "body": ""},
            {"tag_name": "v1.24.8", "html_url": "u", "published_at": "2025-12-01T00:00:00Z", "body": ""}]
    weekly.resolve_pseudo(a, _fx(tmp_path, {"api.github.com/repos/go-gitea/gitea/releases": rels}))
    assert a.fixed == "v1.24.9"  # the first tag after the fixing commit (2026-01-02)


def test_pseudo_without_tag_falls_back_to_commit(tmp_path):
    a = _pseudo_adv()
    weekly.resolve_pseudo(a, _fx(tmp_path, {}))
    assert a.fixed == "Fixed in commit abcdef1 (no tagged release yet)" and a.fixed_version is None
    g = weekly.Group("Gitea", [a])
    v = weekly.view(g, "p")
    assert "0.0.0-2026" not in json.dumps(v) and "Fixed in commit abcdef1" in json.dumps(v, ensure_ascii=False)


def test_markdown_templates_do_not_autoescape():
    assert _env.autoescape is False or not _env.autoescape
    assert md_text("before < 3.6.2 and <= 2.0, `<host>`") == "before < 3.6.2 and <= 2.0, `<host>`"
    assert md_text("<script>x</script>").startswith("&lt;script>")
    a = Advisory(key="CVE-1", title="x", project="p", affected="< 3.6.2", cves=["CVE-1"])
    md = render_weekly({"intro": "i", "items": [weekly.view(weekly.Group("p", [a]), "a < b & c > d")], "missed": [],
                        "takeaways": ["* x"], "data_line": "d"})
    assert "&lt;" not in md and "&amp;" not in md and "a < b & c > d" in md


def test_grouping_merges_incus_and_lxd_and_orders_by_severity():
    def adv(project, group, sev, cvss, ghsa, cve=None):
        return Advisory(key=ghsa, title=f"{project} {ghsa}", project=project, group=group, ghsa=ghsa,
                        cves=[cve] if cve else [], severity=sev, cvss=cvss, published=datetime(2026, 11, 1, tzinfo=timezone.utc))
    items = [adv("Incus", "Incus & LXD", "high", 8.0, "GHSA-1111-1111-1111"),
             adv("LXD", "Incus & LXD", "critical", 10.0, "GHSA-2222-2222-2222", "CVE-2026-1"),
             adv("Gitea", "Gitea", "high", 7.5, "GHSA-3333-3333-3333"),
             adv("Gitea", "Gitea", "high", 8.7, "GHSA-4444-4444-4444")]
    groups = weekly.group_advisories(items)
    assert [g.label for g in groups] == ["Incus & LXD", "Gitea"]
    assert groups[0].primary.project == "LXD" and len(groups[0].others) == 1
    assert groups[1].primary.ghsa == "GHSA-4444-4444-4444"
    assert weekly.id_line(groups[0]) == "**CVE-2026-1** (and 1 more, incl. GHSA-1111-1111-1111)"
    v = weekly.view(groups[1], "p")
    assert v["title"].endswith(", 1 More") and "**Project** : Gitea" in v["head"]
    wl = {p["name"]: p.get("group") for p in WL}
    assert wl["Incus"] == wl["LXD"] == "Incus & LXD"


def test_group_caps_and_leftovers(golden_fx):
    # more groups than MAX_MAIN: the extra projects land in "Also this week"
    items = [Advisory(key=f"CVE-2026-{i}", title="Some bug", project=f"Proj{i}", group=f"Proj{i}", cves=[f"CVE-2026-{i}"],
                      severity="high", cvss=8.0 - i / 100, fixed="1.0", fixed_version="1.0",
                      published=datetime(2026, 11, 1, tzinfo=timezone.utc)) for i in range(14)]
    groups = weekly.group_advisories(items)
    bullets = weekly.takeaways(groups[:weekly.MAX_MAIN], groups[weekly.MAX_MAIN:], [])
    assert weekly.MAX_MAIN == 11 and weekly.MAX_MISSED == 3
    also = [b for b in bullets if b.startswith("**Also this week**")]
    assert len(also) == 1 and "Proj11 CVE-2026-11 (CVSS 7.9, fixed 1.0)" in also[0] and "Proj13" in also[0]
    assert 4 <= len(bullets) <= 7


def test_title_cleanup():
    names = ["Traefik"]
    assert strip_project("Traefik has an unauthenticated memory/FD exhaustion bug", names) == "unauthenticated memory/FD exhaustion bug"
    assert strip_project("Traefik: Unauthenticated Header", names) == "Unauthenticated Header"
    assert strip_project("Traefik’s router is slow.", names) == "router is slow"
    assert short_title("Traefik has an unauthenticated NTLM header exhausts memory", names) == \
        "Unauthenticated NTLM Header Exhausts Memory"
    assert title_case("authentication bypass via jwt algorithm confusion in the API") == \
        "Authentication Bypass via JWT Algorithm Confusion in the API"
    assert title_case("`{host}` in root lets clients escape the site tree, XSS in pgAdmin OAuth2") == \
        "`{host}` in Root Lets Clients Escape the Site Tree, XSS in pgAdmin OAuth2"
    t = fit_title("Gitea", "OAuth2 Account Takeover, Actions Approval Bypass " + "and Many More Words " * 6, more=18)
    assert len(t) <= 90 and t.endswith(", 18 More") and t.startswith("Gitea: OAuth2")


def test_version_ranges():
    assert humanize_range("<= 2.11.7") == "≤ 2.11.7"
    assert humanize_range("< 26.7.8") == "before 26.7.8"
    assert humanize_range(">= v2.11.58, <= v2.11.60") == "v2.11.58 – v2.11.60"
    assert humanize_range(">= 1.0.0, < 2.0.0") == "1.0.0 – before 2.0.0"
    assert humanize_range(">= 0, < 5.1") == "before 5.1"
    assert humanize_ranges(["< 1.2", "< 1.2", "<= 3.0"]) == "before 1.2, ≤ 3.0"


def test_exploitation_rule():
    assert is_exploit_reference("https://www.exploit-db.com/exploits/1", osv_type="EXPLOIT")
    assert is_exploit_reference("https://packetstormsecurity.com/files/1", osv_type="ARTICLE")
    assert is_exploit_reference("https://github.com/x/CVE-2026-1-poc", osv_type="EXPLOIT")
    assert is_exploit_reference("https://github.com/x/y/blob/main/exploit.py", osv_type="ARTICLE")
    assert not is_exploit_reference("https://github.com/x/y/pull/3", osv_type="EXPLOIT")  # not a PoC path
    assert not is_exploit_reference("https://github.com/x/y/security/advisories/GHSA-1", osv_type="WEB")
    assert not is_exploit_reference("https://github.com/x/poc", osv_type="WEB")  # type must be EXPLOIT/ARTICLE
    assert not is_exploit_reference("https://exploit-db.com/exploits/1", osv_type="exploit")  # exact type
    assert is_exploit_reference("https://example.org/x", nvd_tags=["Third Party Advisory", "Exploit"])
    assert not is_exploit_reference("https://example.org/x", nvd_tags=["Vendor Advisory", "Patch"])
    # "### PoC" in an advisory body (the LXD false positive) no longer counts
    a = weekly.advisory_from_ghsa(ghsa_src.normalize(
        _ghsa("GHSA-aaaa-bbbb-cccc", "LXD auth bypass", "canonical/lxd", "critical", 10.0, "### PoC\n\ncurl ...\n",
              [_v("go", "github.com/canonical/lxd", "< 5", "5")], cve="CVE-2026-112816")), next(p for p in WL if p["name"] == "LXD"))
    assert a.poc is False and a.rows()[0]["exploitation"] == "None known"
    assert has_public_poc(osv_refs=[{"type": "EXPLOIT", "url": "https://www.exploit-db.com/exploits/9"}])
    assert not has_public_poc(osv_refs=[{"type": "WEB", "url": "https://www.exploit-db.com/exploits/9"}], nvd_refs=[{"url": "u", "tags": []}])
    kev = Advisory(key="CVE-1", title="t", project="p", cves=["CVE-1"], kev={"CVE-1": {}}, poc=True)
    assert kev.rows()[0]["exploitation"] == "Known exploited (CISA KEV)"


def test_severity_line_variants():
    a = Advisory(key="x", title="t", project="p", severity="high")
    assert weekly.severity_line(a) == "High (no CVSS score yet)"
    a.cvss, a.cvss_version, a.severity = 9.5, "4.0", "critical"
    assert weekly.severity_line(a) == "Critical (CVSS v4.0 9.5)"
    a.cvss_version, a.cvss, a.severity = None, 7.5, "high"
    assert weekly.severity_line(a, kev=True) == "High (CVSS 7.5), on CISA KEV"


def test_ghsa_only_reviewed_this_week_is_missed_with_added_date(tmp_path):
    rec = {**_ghsa("GHSA-zzzz-yyyy-xxxx", "Grafana old bug", "grafana/grafana", "high", 8.0, "d",
                   [_v("go", "github.com/grafana/grafana", "< 12", "12")], pub="2026-07-01T00:00:00Z"),
           "github_reviewed_at": "2026-11-02T00:00:00Z"}

    def gh(req):
        return httpx.Response(200, json=[rec] if req.url.params.get("updated") and req.url.params.get("severity") == "high" else [])
    h = make_router({"api.github.com/advisories": gh})
    fx = Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(h)), sleep=lambda s: None, max_retries=0)
    r = build(fx)
    assert "## **Missed Earlier**" in r["raw"]
    assert "Disclosed: July 1, 2026 (added to GitHub Advisory Database November 2)" in r["raw"]


def test_ai_clauses_keep_skeleton_and_fall_back(golden_fx):
    class P(ai.Provider):
        name = "p"
        def available(self): return True
        def complete(self, system, user, client, max_tokens=1200):
            if "Separate the clauses" in user:
                return "BIND can be crashed remotely ||| Caddy lets clients escape the site tree ||| Traefik has an unauthenticated memory exhaustion bug"
            return "Unauthenticated memory exhaustion bug" if "Title Case" in user else "A plain description of the flaw."
    r = weekly.build(date(2026, 10, 29), date(2026, 11, 4), fx=golden_fx, writer=ai.AIWriter([P()]), projects=WL, posted={},
                     sleep=lambda s: None)
    first = r["raw"].split("\n")[0]
    assert "Start with your edge: " in first and first.count("Start with your edge") == 1
    assert "Traefik has an unauthenticated memory exhaustion bug" in first
    assert "Then patch fast" not in first or "Then patch fast: " in first


def test_commit_ids_are_not_versions():
    sha = "9be31a019f780647fb689c458408c8803263c812"
    assert weekly.split_versions([sha, "9.19"]) == (["9.19"], [sha])
    assert scrub_pseudo(f"before {sha}") == "before commit 9be31a0"


def test_folded_earlier_advisory_never_becomes_primary():
    def adv(ghsa, sev, cvss, day):
        return Advisory(key=ghsa, title="t", project="Gitea", group="Gitea", ghsa=ghsa, severity=sev, cvss=cvss,
                        published=datetime(2026, 11, day, tzinfo=timezone.utc))
    g = weekly.group_advisories([adv("GHSA-1111-1111-1111", "high", 7.5, 2)])[0]
    g.fold(adv("GHSA-2222-2222-2222", "critical", 9.9, 1))
    assert g.primary.ghsa == "GHSA-1111-1111-1111" and len(g.others) == 1


def test_clip_phrase_does_not_leave_dangling_parts():
    from hhf.textfmt import clip_phrase
    assert clip_phrase("Authentication and Authorization Bypass Through Unverified Client Certificate Chains", 68) == \
        "Authentication and Authorization Bypass"
    assert "(" not in clip_phrase("Authenticated RCE via Apprise CLI Argument Injection (Missing Separator Allows It)", 62)
