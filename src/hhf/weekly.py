"""B2: weekly self-hosted security advisory.

    python -m hhf.weekly [--since YYYY-MM-DD] [--until YYYY-MM-DD] [--dry-run] [--direct] [--no-ai]
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from datetime import date, datetime, time as dtime, timedelta, timezone
from pathlib import Path

import yaml

from . import ai as ai_mod
from .facts import Advisory, fmt_date, fmt_range, md_text, severity_from_cvss
from .sources import epss, ghsa, kev, nvd, osv, releases, ubuntu
from .sources.base import Fetcher, SourceError, default_fetcher

log = logging.getLogger("hhf.weekly")
ROOT = Path(__file__).resolve().parents[2]
TAGS = ["security", "cve", "weekly-security", "self-hosted"]
MAX_MAIN, MAX_MISSED, MAX_PER_PROJECT, MAX_BRIEF = 12, 5, 3, 25
MAX_CHARS = 30000  # stay under Discourse max_post_length (32000)
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ---- watchlist --------------------------------------------------------------
def load_watchlist(path: Path | None = None) -> list[dict]:
    return yaml.safe_load((path or ROOT / "config" / "watchlist.yml").read_text(encoding="utf-8"))["projects"]


def match_ghsa(g: dict, projects: list[dict]) -> dict | None:
    url = (g.get("repo_url") or "").lower()
    for p in projects:
        repo = (p.get("repo") or "").lower()
        if repo and re.search(rf"github\.com/{re.escape(repo)}(?:$|[/#?])", url):
            return p
    for v in g.get("vulns", []):
        eco, name = (v.get("ecosystem") or "").lower(), (v.get("package") or "").lower()
        for p in projects:
            for pk in p.get("packages", []):
                if pk["ecosystem"].lower() == eco and pk["name"].lower() == name:
                    return p
    return None


def _kw_re(words: list[str]) -> re.Pattern:
    return re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in words) + r")(?![\w-])", re.I)


def match_nvd(rec: dict, projects: list[dict]) -> dict | None:
    for p in projects:
        nv = p.get("nvd", {})
        if nv.get("exclude") and re.search("|".join(nv["exclude"]), rec.get("description", ""), re.I):
            continue
        kws = [k.lower() for k in nv.get("keywords", [])]
        vendors = {v.lower() for v in nv.get("vendors", [])}
        for vendor, product in rec.get("cpes", []):
            prod, ven = product.replace("_", " "), vendor.replace("_", " ")
            if prod in kws or ven in kws or (vendor in vendors and any(k in prod for k in kws)):
                return p
        if not rec.get("cpes") and kws and _kw_re(kws).search(rec.get("description", "")):
            return p
    return None


# ---- text helpers -------------------------------------------------------------
def plain_summary(desc: str, limit: int = 420) -> str:
    t = re.sub(r"```.*?```", " ", desc or "", flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"(?im)^\s*reported (from|by|in)\b[^\n]*$", " ", t)
    t = re.sub(r"https?://\S+", " ", t)
    t = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", t)
    lines = []
    for ln in t.splitlines():
        s = ln.strip()
        if not s or re.match(r"^#{1,6}\s*(summary|details|description|impact|overview|poc|patches?|workarounds?|references?)\s*$", s, re.I):
            continue
        s = re.sub(r"^#{1,6}\s*", "", s)
        s = re.sub(r"[*_`]+", "", s)
        lines.append(s)
    t = re.sub(r"\s+", " ", " ".join(lines)).strip()
    if len(t) <= limit:
        return t
    cut = t[:limit]
    end = max(cut.rfind(". "), cut.rfind("; "))
    return (cut[: end + 1] if end > limit * 0.5 else cut.rsplit(" ", 1)[0] + "…")


def find_workaround(desc: str) -> str:
    m = re.search(r"#{1,6}\s*Workarounds?\s*\n+(.*?)(?=\n#{1,6}\s|\Z)", desc or "", re.S | re.I)
    if not m:
        return ""
    t = plain_summary(m.group(1), 300)
    return "" if re.match(r"(?i)^(none|n/a|no workaround)", t) else t


def mentions_poc(desc: str, refs: list[dict | str]) -> bool:
    if re.search(r"#{1,6}\s*(PoC|Proof of Concept)\b", desc or "", re.I):
        return True
    for r in refs:
        if isinstance(r, dict) and any(t in ("Exploit", "exploit") for t in r.get("tags", [])):
            return True
        if isinstance(r, str) and re.search(r"exploit-db\.com|/poc\b", r, re.I):
            return True
    return False


# ---- building advisories ----------------------------------------------------------
def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def clean_versions(raw: list[str]) -> list[str]:
    out = []
    for r in raw:
        for part in re.split(r"[,;]\s*", r or ""):
            v = re.sub(r"^[<>=~^\s]+", "", part).strip()
            if v and v not in out:
                out.append(v)
    return out


def advisory_from_ghsa(g: dict, project: dict) -> Advisory:
    summary = g["title"] or g["ghsa"]
    title = summary if summary.lower().startswith(project["name"].lower()) else f"{project['name']}: {summary}"
    fixed = clean_versions([v["fixed"] for v in g["vulns"] if v.get("fixed")])
    affected = "; ".join(
        f"{v['package']} {v['range']}".strip() for v in g["vulns"] if v.get("range")
    )
    a = Advisory(
        key=g["ghsa"], title=title, project=project["name"], ghsa=g["ghsa"],
        cves=[g["cve"]] if g.get("cve") else [], published=_dt(g["published"]),
        severity=g["severity"], cvss=g["cvss"], description=g["description"],
        affected=affected, fixed=", ".join(fixed), fixed_version=fixed[0] if fixed else None,
        ecosystem=(g["vulns"][0].get("ecosystem") if g["vulns"] else None),
        package=(g["vulns"][0].get("package") if g["vulns"] else None),
        image=project.get("image"), category=project.get("category", ""),
        workaround=find_workaround(g["description"]), sources={"GHSA"},
    )
    a.poc = mentions_poc(g["description"], g.get("references", []))
    repo = project.get("repo")
    vendor_url = f"https://github.com/{repo}/security/advisories/{g['ghsa']}" if repo else g["url"]
    a.references.append(("Vendor advisory", vendor_url))
    a.references.append((g["ghsa"], g["url"]))
    return a


def advisory_from_nvd(n: dict, project: dict) -> Advisory:
    first = plain_summary(n["description"], 100).rstrip("….")
    a = Advisory(
        key=n["id"], title=f"{project['name']}: {n['id']} ({first})", project=project["name"], cves=[n["id"]],
        published=_dt(n["published"]), severity=n["severity"] or severity_from_cvss(n["cvss"]), cvss=n["cvss"],
        description=n["description"], image=project.get("image"), category=project.get("category", ""),
        sources={"NVD"},
    )
    a.poc = mentions_poc(n["description"], n["references"])
    for r in n["references"][:3]:
        if "Vendor Advisory" in r["tags"] or "Patch" in r["tags"]:
            a.references.append(("Vendor advisory" if "Vendor Advisory" in r["tags"] else "Patch", r["url"]))
    return a


def finalize(a: Advisory, nvd_by_id: dict[str, dict], osv_info: dict | None, kev_idx: dict, epss_map: dict,
             usn_map: dict) -> None:
    for cve in a.cves:
        n = nvd_by_id.get(cve)
        if n:
            if a.cvss is None and n["cvss"] is not None:
                a.cvss = n["cvss"]
            a.poc = a.poc or mentions_poc("", n["references"])
            a.sources.add("NVD")
        if cve in kev_idx:
            a.kev[cve] = kev_idx[cve]
            a.sources.add("KEV")
        if cve in epss_map:
            a.epss[cve] = epss_map[cve]
        for u in usn_map.get(cve, []):
            if (u["id"], u["url"]) not in a.usn:
                a.usn.append((u["id"], u["url"]))
    if osv_info:
        a.sources.add("OSV")
        if not a.fixed and osv_info["fixed"]:
            fv = clean_versions(osv_info["fixed"])
            a.fixed = ", ".join(fv)
            a.fixed_version = fv[0] if fv else None
        if not a.affected and osv_info["ranges"]:
            a.affected = "; ".join(osv_info["ranges"][:3])
    if a.severity is None or (a.cvss is not None and SEV_RANK.get(a.severity, 0) < SEV_RANK.get(severity_from_cvss(a.cvss) or "", 0)):
        a.severity = severity_from_cvss(a.cvss) or a.severity
    for cve in a.cves:
        a.references.append((f"NVD {cve}", f"https://nvd.nist.gov/vuln/detail/{cve}"))
        if cve in a.kev:
            a.references.append(("CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
    for uid, url in a.usn:
        a.references.append((uid, url))
    seen, refs = set(), []
    for lab, url in a.references:
        if url not in seen:
            seen.add(url)
            refs.append((lab, url))
    a.references = refs


def keep(a: Advisory) -> bool:
    return a.is_kev or a.severity in ("critical", "high") or (a.cvss or 0) >= 7.0


def merge_by_cve(items: list[Advisory]) -> list[Advisory]:
    out: list[Advisory] = []
    for a in items:
        dup = next((o for o in out if (a.ghsa and a.ghsa == o.ghsa) or set(a.cves) & set(o.cves)), None)
        if not dup:
            out.append(a)
            continue
        keep_a, drop = (dup, a) if dup.ghsa or not a.ghsa else (a, dup)
        keep_a.cves = list(dict.fromkeys(keep_a.cves + drop.cves))
        keep_a.cvss = keep_a.cvss if keep_a.cvss is not None else drop.cvss
        keep_a.sources |= drop.sources
        keep_a.poc = keep_a.poc or drop.poc
        keep_a.references += [r for r in drop.references if r not in keep_a.references]
        out[out.index(dup)] = keep_a
    return out


# ---- remediation text ----------------------------------------------------------------
def upgrade_command(a: Advisory) -> str:
    v = (a.fixed_version or "").lstrip("v>= ").strip()
    if not v:
        return ""
    if a.image:
        return f"docker pull {a.image}:{v}"
    pkg, eco = a.package, (a.ecosystem or "").lower()
    cmds = {
        "go": f"go get {pkg}@v{v}", "npm": f"npm install {pkg}@{v}", "pip": f"pip install --upgrade '{pkg}>={v}'",
        "composer": f"composer require {pkg}:^{v}", "rubygems": f"bundle update {pkg}",
        "nuget": f"dotnet add package {pkg} --version {v}", "rust": f"cargo update -p {pkg}",
    }
    return cmds.get(eco, "")


def remediation_steps(a: Advisory) -> list[str]:
    steps = []
    v = a.fixed_version
    if v and "," in a.fixed:
        steps.append(f"Upgrade {a.project} to the fixed release for your branch ({a.fixed}), or a later version.")
    elif v:
        cmd = upgrade_command(a)
        s = f"Upgrade {a.project} to **{v}** or later"
        s += f", for example `{cmd}` (confirm the exact image or package tag in the vendor release notes)." if cmd else "."
        steps.append(s)
    else:
        steps.append(f"No fixed release is listed yet. Track the vendor advisory for {a.project} and upgrade as soon as one ships.")
    if a.workaround:
        steps.append(f"If you cannot upgrade immediately, apply the vendor workaround: {a.workaround}")
    else:
        steps.append("If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.")
    if a.is_kev:
        steps.append("This vulnerability is in CISA KEV and is known to be exploited: review logs for signs of compromise and rotate secrets the service could reach.")
    else:
        steps.append("Review recent logs of the affected service for unusual requests before and after patching.")
    steps.append(f"Verify: after the restart, confirm the running version is {v + ' or later' if v else 'the patched release'} and the service passes its health check.")
    return steps


def severity_line(a: Advisory) -> str:
    s = (a.severity or "unrated").capitalize()
    return f"{s} (CVSS {a.cvss:.1f})" if a.cvss is not None else s


def id_line(a: Advisory) -> str:
    if a.ghsa:
        if a.cves:
            return f"**{a.ghsa}** / " + " / ".join(f"**{c}**" for c in a.cves)
        return f"**{a.ghsa}** (no CVE yet)"
    return " / ".join(f"**{c}**" for c in a.cves)


def facts_for(a: Advisory) -> dict:
    return {
        "project": a.project, "title": a.title, "ids": ([a.ghsa] if a.ghsa else []) + a.cves,
        "severity": severity_line(a), "affected": a.affected, "fixed": a.fixed,
        "known_exploited_cisa_kev": a.is_kev, "public_poc": a.poc,
        "description": plain_summary(a.description, 900),
    }


def det_prose(a: Advisory) -> str:
    t = plain_summary(a.description, 420)
    return t or f"{a.project} published a security advisory; see the references for details."


def _low_rate(fx: Fetcher) -> bool:
    try:
        return int(getattr(fx, "rate_remaining", None) or 99) < 6
    except ValueError:
        return False


# ---- orchestration -----------------------------------------------------------------------
def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"posted": {}}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def collect(since: date, until: date, *, fx: Fetcher, projects: list[dict], posted: dict,
            max_repos: int = 60) -> tuple[list[Advisory], list[Advisory], dict, list[dict]]:
    stats: dict[str, int] = {}
    missed_start = until - timedelta(days=30)
    start_dt = datetime.combine(missed_start, dtime.min, timezone.utc)
    end_dt = datetime.combine(until + timedelta(days=1), dtime.min, timezone.utc)
    since_dt = datetime.combine(since, dtime.min, timezone.utc)

    # GHSA
    gh: dict[str, tuple[dict, dict]] = {}
    try:
        rows = ghsa.global_advisories(missed_start, fx)
    except SourceError as exc:
        log.warning("GHSA global failed: %s", exc)
        rows = []
    stats["ghsa_global"] = len(rows)
    for g in rows:
        p = match_ghsa(g, projects)
        if p and not g["withdrawn"]:
            gh[g["ghsa"]] = (g, p)
    n_repo = 0
    for p in projects[:]:
        if not p.get("repo") or n_repo >= max_repos:
            continue
        if _low_rate(fx):
            log.warning("GitHub rate limit nearly exhausted; skipping remaining per-repo advisories")
            break
        n_repo += 1
        for g in ghsa.repo_advisories(p["repo"], fx):
            pub = _dt(g["published"])
            if pub and pub >= start_dt and not g["withdrawn"] and g["severity"] in ("critical", "high", None):
                gh.setdefault(g["ghsa"], (g, p))
    stats["ghsa_matched"] = len(gh)

    # NVD window
    try:
        nvd_recs = nvd.fetch_window(start_dt, end_dt, fx=fx)
    except SourceError as exc:
        log.warning("NVD window failed: %s", exc)
        nvd_recs = []
    stats["nvd_window"] = len(nvd_recs)
    nvd_by_id = {r["id"]: r for r in nvd_recs}
    nvd_hits = [(r, p) for r in nvd_recs if (p := match_nvd(r, projects))]
    stats["nvd_matched"] = len(nvd_hits)

    items = [advisory_from_ghsa(g, p) for g, p in gh.values()] + [advisory_from_nvd(r, p) for r, p in nvd_hits]
    items = merge_by_cve(items)

    # enrich
    kev_idx = {}
    try:
        kev_idx = kev.load(fx)
    except SourceError as exc:
        log.warning("KEV failed: %s", exc)
    stats["kev_catalog"] = len(kev_idx)
    for a in items:
        for c in a.cves:
            if c not in nvd_by_id and len(nvd_by_id) < 400:
                r = nvd.get_cve(c, fx)
                if r:
                    nvd_by_id[c] = r
    all_cves = sorted({c for a in items for c in a.cves})
    epss_map = epss.lookup(all_cves, fx) if all_cves else {}
    stats["epss_scores"] = len(epss_map)
    for a in items:
        a_osv = osv.lookup(a.ghsa or a.cves[0], fx) if (a.ghsa or a.cves) and not a.fixed else None
        finalize(a, nvd_by_id, a_osv, kev_idx, epss_map, {})
    items = [a for a in items if keep(a) and a.published]
    stats["kept"] = len(items)

    # releases
    rel: list[dict] = []
    n_rel = 0
    for p in projects:
        if not p.get("repo") or n_rel >= max_repos:
            continue
        if _low_rate(fx):
            log.warning("GitHub rate limit nearly exhausted; skipping remaining release lookups")
            break
        n_rel += 1
        for r in releases.since(releases.latest(p["repo"], fx), since_dt):
            if r["security"] and not r["prerelease"]:
                rel.append({**r, "project": p["name"], "published": r["published"][:10]})
    stats["security_releases"] = len(rel)

    def order(a):
        cat = {"edge": 0, "identity": 1}.get(a.category, 2)  # edge first within a severity tier
        return (not a.is_kev, -SEV_RANK.get(a.severity or "", 0), cat, -(a.cvss or 0), a.project.lower())

    already = set(posted)
    main = sorted([a for a in items if a.published >= since_dt and a.key not in already], key=order)
    missed = sorted([a for a in items if a.published < since_dt and a.key not in already
                     and not (set(a.cves) & already)], key=order)
    stats["candidates"] = len(main)
    missed = missed[:MAX_MISSED]
    shown = main + missed
    usn = ubuntu.usn_map(sorted({c for a in shown for c in a.cves}), fx)
    stats["usn_matches"] = len(usn)
    for a in shown:
        for c in a.cves:
            for u in usn.get(c, []):
                if (u["id"], u["url"]) not in a.usn:
                    a.usn.append((u["id"], u["url"]))
                    a.references.append((u["id"], u["url"]))
    stats["main"], stats["missed"] = len(main), len(missed)
    return main, missed, stats, rel


def edge_sentence(main: list[Advisory], writer: ai_mod.AIWriter, counts: dict) -> tuple[str, bool]:
    edge = [a for a in main if a.category == "edge"]
    ident = [a for a in main if a.category == "identity"]
    facts = {"edge": [f"{a.project} ({severity_line(a)})" for a in edge],
             "identity": [f"{a.project} ({severity_line(a)})" for a in ident],
             "other_projects": sorted({a.project for a in main if a.category not in ("edge", "identity")}),
             "counts": counts}
    if writer.active:
        t = writer.prose(
            "Write ONE or TWO sentences that continue the phrase 'Start with your edge:' (reverse proxies, VPN, "
            "DNS, SSH) and then say what to patch next. Do not repeat the phrase itself.", facts, max_chars=400)
        if t:
            return t, True
    parts = []
    if edge:
        parts.append("patch " + ", ".join(dict.fromkeys(a.project for a in edge)) + " first")
    else:
        parts.append("no reverse-proxy, VPN or DNS issues were found this week")
    if ident:
        parts.append("then identity and authentication services (" + ", ".join(dict.fromkeys(a.project for a in ident)) + ")")
    others = facts["other_projects"]
    if others:
        parts.append("then the remaining apps (" + ", ".join(others[:8]) + ")")
    return "; ".join(parts) + ".", False


def view(a: Advisory, prose: str) -> dict:
    return {
        "title": a.title, "id_line": id_line(a), "disclosed": fmt_date(a.published), "project": a.project,
        "prose": prose, "severity_line": severity_line(a),
        "affected": a.affected or "See the vendor advisory for affected versions.",
        "fixed": a.fixed or "No fixed release listed yet.",
        "workaround": a.workaround or "None documented.",
        "rows": a.rows(), "steps": remediation_steps(a), "references": a.references,
        "ref_label": a.ghsa or (a.cves[0] if a.cves else a.key),
        "ref_url": next((u for l, u in a.references if l == (a.ghsa or "")), a.references[0][1] if a.references else ""),
    }


SOURCES = [
    "GitHub Advisory Database (GHSA), CC-BY-4.0: https://github.com/advisories",
    "NVD CVE API 2.0. " + nvd.ATTRIBUTION,
    "OSV.dev: https://osv.dev (per-record licences apply)",
    "FIRST EPSS: See EPSS at https://www.first.org/epss",
    "CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "Ubuntu Security Notices: https://ubuntu.com/security/notices",
    "GitHub Releases of watchlist projects: https://docs.github.com/en/rest/releases",
]


def build(since: date, until: date, *, fx: Fetcher, writer: ai_mod.AIWriter, projects: list[dict],
          posted: dict, sleep=time.sleep) -> dict:
    from .render import render_weekly

    all_main, missed, stats, rel = collect(since, until, fx=fx, projects=projects, posted=posted)
    main, extra, per = [], [], {}
    for a in all_main:  # per-project cap keeps one noisy project (e.g. 13 Incus/LXD advisories) from crowding out the rest
        if len(main) < MAX_MAIN and per.get(a.project, 0) < MAX_PER_PROJECT:
            main.append(a)
            per[a.project] = per.get(a.project, 0) + 1
        else:
            extra.append(a)
    extra = extra[:MAX_BRIEF]
    stats["brief_only"] = len(extra)
    prose = {a.key: det_prose(a) for a in main + missed}

    def render_all(used_ai: bool, edge: str) -> str:
        lead = (f"Here’s a roundup of **{len(main) + len(extra)} critical/high security issues** disclosed this week "
                "affecting popular open-source self-hosted projects")
        lead += f", plus **{len(missed)} earlier advisories** (see *Missed Earlier*)." if missed else "."
        ctx = {
            "intro": f"{lead} Start with your edge: {edge}",
            "items": [view(a, prose[a.key]) for a in main], "missed": [view(a, prose[a.key]) for a in missed],
            "extra": [{"project": a.project, "title": a.title, "cvss": severity_line(a), "kev": a.is_kev,
                       "ids": " / ".join(([a.ghsa] if a.ghsa else []) + a.cves), "url": a.references[0][1] if a.references else ""} for a in extra],
            "releases": rel, "sources": SOURCES,
            "prose_note": ("AI-assisted from the supplied facts and fact-checked automatically." if used_ai
                           else "generated from the supplied facts without AI."),
        }
        return render_weekly(ctx)

    def fit(used_ai: bool, edge: str) -> str:
        raw = render_all(used_ai, edge)
        while len(raw) > MAX_CHARS and (missed or main):
            if missed:
                missed.pop()
            else:
                extra.insert(0, main.pop())  # demoted to the short list
                extra[:] = extra[:MAX_BRIEF]
            stats["trimmed_for_size"] = stats.get("trimmed_for_size", 0) + 1
            raw = render_all(used_ai, edge)
        return raw

    edge, _ = edge_sentence(main + extra, ai_mod.AIWriter(enabled=False), {})
    raw = fit(False, edge)  # first pass sizes the post with deterministic prose
    used_ai = False
    if writer.active:
        for a in main:
            t = writer.prose(
                "Write the 'Technical Details' paragraph for this advisory: 2 to 3 plain sentences saying what "
                "the flaw is, what an attacker can do and who is affected.", facts_for(a), max_chars=700)
            sleep(4)  # stay under free-tier per-minute limits
            if t:
                prose[a.key], used_ai = t, True
        edge_ai, ok = edge_sentence(main + extra, writer, {"new_items": len(main), "missed_items": len(missed)})
        used_ai = used_ai or ok
        raw = fit(used_ai, edge_ai)
    stats["main"], stats["missed"] = len(main), len(missed)
    title = f"Weekly Self-Hosted Security Summary: {fmt_range(since, until)}"
    return {"title": title, "raw": raw, "tags": TAGS,
            "external_id": f"weekly-advisory-{until.isoformat()}", "stats": stats,
            "ids": [x for a in main + extra + missed for x in [a.key, *a.cves]], "n_main": len(main) + len(extra),
            "n_missed": len(missed), "ai": writer.stats}


def main(argv: list[str] | None = None) -> int:
    from . import webhook

    ap = argparse.ArgumentParser(description="Weekly self-hosted security advisory")
    ap.add_argument("--since", type=date.fromisoformat, help="window start (default: 7 days before --until)")
    ap.add_argument("--until", type=date.fromisoformat, default=datetime.now(timezone.utc).date())
    ap.add_argument("--dry-run", action="store_true", help="write out/weekly_advisory-<date>.md, no writes")
    ap.add_argument("--direct", action="store_true", help="create the topic via the Discourse API")
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "out")
    ap.add_argument("--state", type=Path, default=ROOT / "state" / "posted.json")
    ap.add_argument("--max-repos", type=int, default=60, help="cap on per-repo GitHub calls")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # request URLs stay out of the logs
    since = args.since or args.until - timedelta(days=7)

    state = load_state(args.state)
    res = build(since, args.until, fx=default_fetcher(), writer=ai_mod.AIWriter(enabled=not args.no_ai),
                projects=load_watchlist(), posted=state.get("posted", {}))
    print(json.dumps({"title": res["title"], "stats": res["stats"], "ai": res["ai"]}, indent=2))
    if args.dry_run:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        out = args.out_dir / f"weekly_advisory-{args.until.isoformat()}.md"
        out.write_text(f"<!-- tags: {', '.join(res['tags'])} | external_id: {res['external_id']} -->\n\n"
                       f"# {res['title']}\n\n{res['raw']}", encoding="utf-8")
        print(f"dry-run: wrote {out}")
        return 0
    payload = webhook.build_payload("weekly_advisory", res["title"], res["raw"], res["tags"], res["external_id"])
    print(json.dumps(webhook.deliver(payload, direct=args.direct)))
    for k in res["ids"]:
        state.setdefault("posted", {})[k] = args.until.isoformat()
    save_state(args.state, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
