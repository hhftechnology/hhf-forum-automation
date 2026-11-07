"""B3: daily threat briefing (24h window).

    python -m hhf.daily [--since ISO] [--dry-run] [--direct] [--no-ai]
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import ai as ai_mod
from . import classify as cl
from .facts import SEVERITY_ORDER, action_for, fmt_cvss, fmt_epss, severity_from_cvss
from .sources import abusech, epss, feeds, kev, nvd, otx, ransomware
from .sources.base import Fetcher, SourceError, default_fetcher

log = logging.getLogger("hhf.daily")
ROOT = Path(__file__).resolve().parents[2]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
MAX_THREATS = 8


@dataclass
class Threat:
    title: str
    summary: str
    url: str
    source: str
    kind: str  # kev | advisory | ics | news | nvd | ransomware | otx
    severity: str = "medium"
    types: list[str] = field(default_factory=list)
    industries: list[str] = field(default_factory=list)
    cves: set[str] = field(default_factory=set)
    score: float = 0.0
    also: list[tuple[str, str]] = field(default_factory=list)
    facts: dict = field(default_factory=dict)


def first_sentences(text: str, n: int = 2, limit: int = 320) -> str:
    parts = re.split(r"(?<=[.!?])\s+", (text or "").strip())
    out = " ".join(parts[:n]).strip()
    if len(out) > limit:
        out = out[:limit].rsplit(" ", 1)[0] + "…"
    return out


def load_feeds() -> dict:
    return yaml.safe_load((ROOT / "config" / "feeds.yml").read_text(encoding="utf-8"))


def kev_summary(v: dict) -> str:
    return (f"{v['vendorProject']} {v['product']}: {v['vulnerabilityName']}. CISA added {v['cveID']} to the Known "
            f"Exploited Vulnerabilities catalog on {v['dateAdded']}, so exploitation has been observed in the wild; "
            f"federal agencies must remediate by {v['dueDate']}. Required action: {v.get('requiredAction', 'see CISA')}")


def score(t: Threat) -> float:
    s = SEVERITY_ORDER[t.severity] * 10
    s += {"kev": 15, "advisory": 4, "ics": 2, "news": 3, "nvd": 1, "otx": 1, "ransomware": 6}.get(t.kind, 0)
    if "zero-day" in t.types:
        s += 6
    if "ransomware" in t.types:
        s += 3
    if t.cves:
        s += 1
    return s


def classify_threat(t: Threat, tax: dict, picker, *, kev_flag=False, cvss=None, ransomware_flag=False,
                    text: str | None = None) -> None:
    text = text or f"{t.title}. {t.summary}"
    c = cl.classify(text, tax, picker, kev=kev_flag, cvss=cvss, ransomware=ransomware_flag)
    t.severity, t.types, t.industries = c.severity, c.types, c.industries
    t.cves |= {x.upper() for x in CVE_RE.findall(text)}
    t.score = score(t)


def collect(since: datetime, now: datetime, *, fx: Fetcher, tax: dict, picker, fcfg: dict) -> dict:
    stats: dict[str, int] = {}
    notes: list[str] = []
    threats: list[Threat] = []
    all_sev: list[str] = []

    # CISA KEV
    kev_idx: dict = {}
    try:
        kev_idx = kev.load(fx)
    except SourceError as exc:
        notes.append(f"KEV failed: {exc}")
    new_kev = kev.added_since(kev_idx, since.date())
    stats["kev_new"] = len(new_kev)

    # NVD (critical/high published in the window)
    nvd_recs: list[dict] = []
    try:
        nvd_recs = nvd.fetch_window(since, now, fx=fx)
    except SourceError as exc:
        notes.append(f"NVD failed: {exc}")
    stats["nvd_crit_high"] = len(nvd_recs)
    nvd_by_id = {r["id"]: r for r in nvd_recs}
    for v in new_kev[:15]:
        if v["cveID"].upper() not in nvd_by_id:
            r = nvd.get_cve(v["cveID"], fx)
            if r:
                nvd_by_id[r["id"]] = r

    # EPSS for everything we may display
    cve_ids = sorted({v["cveID"].upper() for v in new_kev} | {r["id"] for r in nvd_recs if (r["cvss"] or 0) >= 9})
    epss_map = epss.lookup(cve_ids, fx)
    stats["epss_scores"] = len(epss_map)

    # KEV rows + threats
    kev_rows = []
    for v in new_kev:
        cid = v["cveID"].upper()
        n = nvd_by_id.get(cid)
        cvss = n["cvss"] if n else None
        e = epss_map.get(cid)
        kev_rows.append({
            "cve": cid, "product": f"{v['vendorProject']} {v['product']}", "cvss": fmt_cvss(cvss),
            "epss": fmt_epss(*(e or (None, None))), "due": v.get("dueDate", "N/A"),
            "action": action_for(True, e[0] if e else None, cvss),
        })
        t = Threat(title=f"{v['vendorProject']} {v['product']}: {v['vulnerabilityName']} ({cid})",
                   summary=kev_summary(v), url=f"https://nvd.nist.gov/vuln/detail/{cid}", source="CISA KEV", kind="kev",
                   cves={cid}, facts={"cve": cid, "vendor": v["vendorProject"], "product": v["product"],
                                      "name": v["vulnerabilityName"], "date_added": v["dateAdded"], "due": v["dueDate"],
                                      "cvss": cvss, "epss": e[0] if e else None,
                                      "ransomware_use": v.get("knownRansomwareCampaignUse")})
        classify_threat(t, tax, picker, kev_flag=True, cvss=cvss, text=t.title)
        threats.append(t)
        all_sev.append(t.severity)

    # NVD-only high-risk CVEs (not already KEV)
    kev_set = {v["cveID"].upper() for v in new_kev}
    for r in nvd_recs:
        all_sev.append(severity_from_cvss(r["cvss"]) or (r["severity"] or "high"))
    risky = sorted((r for r in nvd_recs if r["id"] not in kev_set and (r["cvss"] or 0) >= 9),
                   key=lambda r: (-(epss_map.get(r["id"], (0, 0))[0]), -(r["cvss"] or 0)))[:3]
    for r in risky:
        e = epss_map.get(r["id"])
        t = Threat(title=f"{r['id']}: {first_sentences(r['description'], 1, 110)}",
                   summary=first_sentences(r["description"], 2, 300), url=f"https://nvd.nist.gov/vuln/detail/{r['id']}",
                   source="NVD", kind="nvd", cves={r["id"]},
                   facts={"cve": r["id"], "cvss": r["cvss"], "epss": e[0] if e else None, "description": r["description"][:600]})
        classify_threat(t, tax, picker, cvss=r["cvss"])
        if not t.types:
            t.types = ["vuln-exploit"]
        threats.append(t)

    # CISA + ICS advisories, news
    for kind, lst in (("advisory", [f for f in fcfg["advisories"] if f.get("kind") == "cisa"]),
                      ("ics", [f for f in fcfg["advisories"] if f.get("kind") == "ics"]),
                      ("news", fcfg["news"])):
        n_items = 0
        for f in lst:
            items = feeds.fetch_feed(f, since, fx, kind=kind)
            n_items += len(items)
            for it in items[:12]:
                t = Threat(title=it["title"], summary=first_sentences(it["summary"], 2, 300), url=it["url"],
                           source=it["source"], kind=kind, facts={"headline": it["title"], "excerpt": it["summary"][:500],
                                                                  "source": it["source"]})
                if kind == "ics":
                    t.summary = t.summary or "CISA published an industrial control systems advisory."
                classify_threat(t, tax, picker)
                if kind == "ics" and "iot-ot" not in t.types:
                    t.types = ["iot-ot"] + t.types[:2]
                threats.append(t)
                all_sev.append(t.severity)
        stats[f"{kind}_items"] = n_items

    # ransomware.live
    rw_rows = ransomware.recent(since, fx)
    stats["ransomware_victims"] = len(rw_rows)
    rw_sectors = ransomware.by_sector(rw_rows)
    if rw_rows:
        top = rw_sectors[0]
        groups = [g for s in rw_sectors for g in s["groups"]][:3]
        t = Threat(title=f"Ransomware: {len(rw_rows)} new victims listed across {len(rw_sectors)} sectors",
                   summary=(f"ransomware.live listed {len(rw_rows)} new victims in the last 24 hours. The most affected "
                            f"sector was {top['sector']} ({top['count']}), with activity from {', '.join(dict.fromkeys(groups))}."),
                   url="https://www.ransomware.live", source="ransomware.live", kind="ransomware",
                   facts={"victims": len(rw_rows), "sectors": rw_sectors[:5]})
        classify_threat(t, tax, picker, ransomware_flag=True)
        smap = {k.lower(): v for k, v in tax.get("sector_map", {}).items()}
        inds = [smap[s["sector"].lower()] for s in rw_sectors[:3] if s["sector"].lower() in smap]
        t.industries = list(dict.fromkeys(inds))[:2] or t.industries
        t.severity = "high" if len(rw_rows) < 40 else "critical" if len(rw_rows) > 120 else t.severity
        t.score = score(t)
        threats.append(t)
        all_sev.append(t.severity)

    # OTX
    pulses, n = otx.pulses(since, fx)
    notes += n
    stats["otx_pulses"] = len(pulses)
    for p in pulses[:8]:
        t = Threat(title=p["name"] or "OTX pulse", summary=first_sentences(p["description"], 2, 300) or "Threat pulse shared on AlienVault OTX.",
                   url=p["url"], source="AlienVault OTX", kind="otx",
                   facts={"name": p["name"], "tags": p["tags"][:8], "adversary": p["adversary"]})
        classify_threat(t, tax, picker)
        threats.append(t)
        all_sev.append(t.severity)

    # abuse.ch
    iocs_by_src, n = abusech.collect(fx)
    notes += n
    for k, v in iocs_by_src.items():
        stats[f"abusech_{k.lower()}"] = len(v)
    iocs = pick_iocs(iocs_by_src, pulses)

    return {"threats": threats, "kev_rows": kev_rows, "new_kev": new_kev, "nvd": nvd_recs, "epss": epss_map,
            "rw_rows": rw_rows, "rw_sectors": rw_sectors, "iocs": iocs, "iocs_by_src": iocs_by_src, "pulses": pulses,
            "all_sev": all_sev, "stats": stats, "notes": notes}


def pick_iocs(by_src: dict[str, list[dict]], pulses: list[dict], limit: int = 12) -> list[dict]:
    out: list[dict] = []
    tf = sorted(by_src.get("ThreatFox", []), key=lambda i: -(i.get("confidence") or 0))
    quota = {"ThreatFox": 6, "URLhaus": 4, "MalwareBazaar": 2}
    for src in ("ThreatFox", "URLhaus", "MalwareBazaar"):
        rows = tf if src == "ThreatFox" else by_src.get(src, [])
        for r in rows[: quota[src]]:
            if r.get("value"):
                out.append({"source": src, "type": r.get("type") or "", "value": r["value"], "malware": r.get("malware") or r.get("threat_type") or ""})
    for p in pulses:
        for i in p["indicators"][:3]:
            if len(out) < limit and i["value"]:
                out.append({"source": "OTX", "type": i["type"] or "", "value": i["value"], "malware": p["name"] or ""})
    return out[:limit]


def select(threats: list[Threat]) -> list[Threat]:
    """Top threats: best score first, merge items about the same CVE, max 3 per source kind."""
    chosen: list[Threat] = []
    per_kind: dict[str, int] = {}
    for t in sorted(threats, key=lambda t: -t.score):
        dup = next((c for c in chosen if (t.cves and t.cves & c.cves) or t.url == c.url), None)
        if dup:
            dup.also.append((t.source, t.url))
            continue
        if per_kind.get(t.kind, 0) >= 3:
            continue
        per_kind[t.kind] = per_kind.get(t.kind, 0) + 1
        chosen.append(t)
        if len(chosen) >= MAX_THREATS:
            break
    return chosen


def overall_severity(top: list[Threat], new_kev_crit: bool) -> str:
    crit = sum(1 for t in top if t.severity == "critical")
    if new_kev_crit or crit >= 3:
        return "critical"
    if crit or any(t.severity == "high" for t in top):
        return "high"
    return "medium" if top else "low"


def det_executive(data: dict, top: list[Threat], overall: str) -> str:
    s = data["stats"]
    parts = [f"The overall threat level is {overall} for the last 24 hours."]
    bits = []
    if s.get("kev_new"):
        bits.append(f"{s['kev_new']} new CISA KEV {'entry' if s['kev_new'] == 1 else 'entries'}")
    if s.get("nvd_crit_high"):
        bits.append(f"{s['nvd_crit_high']} critical or high CVEs published")
    if s.get("ransomware_victims"):
        bits.append(f"{s['ransomware_victims']} new ransomware victims listed")
    if len(bits) > 1:
        bits[-1] = "and " + bits[-1]
    if bits:
        parts.append("We tracked " + ", ".join(bits) + ".")
    if top:
        parts.append(f"Top story: {top[0].title}.")
    return " ".join(parts)


def recommended_actions(data: dict, top: list[Threat]) -> list[str]:
    acts = []
    kr = data["kev_rows"]
    if kr:
        cves = ", ".join(r["cve"] for r in kr[:5])
        acts.append(f"Patch or mitigate the newly listed CISA KEV vulnerabilities ({cves}) first; they are exploited in the wild and carry a CISA due date.")
    hi = [r for r in data["nvd"] if (r["cvss"] or 0) >= 9 and data["epss"].get(r["id"], (0, 0))[0] >= 0.1]
    if hi:
        acts.append("Prioritise critical CVEs with an EPSS score of 0.1 or more: " + ", ".join(r["id"] for r in hi[:5]) + ".")
    if data["rw_sectors"]:
        acts.append(f"Ransomware activity is concentrated in {data['rw_sectors'][0]['sector']}: verify offline backups, patch internet-facing edge devices and review remote-access logins.")
    if any(t.kind == "ics" for t in top) or any("iot-ot" in t.types for t in top):
        acts.append("Review the CISA ICS advisories above if you run the affected industrial or IoT products, and keep them off the internet.")
    if data["iocs"]:
        acts.append("Validate the defanged indicators above and add them to blocklists or detection rules where relevant.")
    acts.append("Read the linked advisories for the products you run and subscribe to vendor security notices.")
    return acts[:6]


def build(since: datetime, now: datetime, *, fx: Fetcher, writer: ai_mod.AIWriter, tax: dict | None = None,
          fcfg: dict | None = None, sleep=time.sleep) -> dict:
    from .render import render_daily

    tax = tax or cl.load_taxonomy()
    fcfg = fcfg or load_feeds()
    data = collect(since, now, fx=fx, tax=tax, picker=writer if writer.active else None, fcfg=fcfg)
    top = select(data["threats"])
    new_kev_crit = any(r["cvss"] != "N/A" and float(r["cvss"]) >= 9 for r in data["kev_rows"])
    overall = overall_severity(top, new_kev_crit)

    used_ai = False
    if writer.active:
        for t in top:
            txt = writer.prose("Write a 2 to 3 sentence summary of this threat for a security briefing.", t.facts, max_chars=500)
            sleep(4)
            if txt:
                t.summary, used_ai = txt, True
    exec_facts = {"overall": overall, "counts": data["stats"],
                  "top": [{"title": t.title, "severity": t.severity, "types": t.types} for t in top[:5]]}
    executive = writer.prose("Write a 3 to 4 sentence executive summary of the last 24 hours of threat activity.",
                             exec_facts, max_chars=700) if writer.active else None
    used_ai = used_ai or bool(executive)
    executive = executive or det_executive(data, top, overall)

    sev_counts = [(s, data["all_sev"].count(s)) for s in ("critical", "high", "medium", "low")]
    classes = [cl.Classification(t.severity, t.types, t.industries) for t in top]
    tags = cl.topic_tags(overall, classes, tax)
    day = now.date()
    sources = [kev.ATTRIBUTION, feeds.ATTRIBUTION_CISA, nvd.ATTRIBUTION, epss.ATTRIBUTION, ransomware.ATTRIBUTION]
    if data["iocs_by_src"]:
        sources.append(abusech.ATTRIBUTION)
    if data["pulses"]:
        sources.append(otx.ATTRIBUTION)
    sources += [f"{f['name']} ({f['url']})" for f in fcfg["news"]]
    ioc_note = "; ".join(data["notes"]) or "No indicator data was available in this window."
    ctx = {
        "executive": executive, "overall": overall, "severity_counts": sev_counts,
        "threats": [{"title": t.title, "severity": t.severity, "types": t.types, "industries": t.industries,
                     "summary": t.summary, "source": t.source, "url": t.url, "also": t.also} for t in top],
        "kev_rows": data["kev_rows"], "ransomware": data["rw_sectors"][:8], "ransomware_total": len(data["rw_rows"]),
        "iocs": data["iocs"], "ioc_note": ioc_note, "actions": recommended_actions(data, top), "sources": sources,
        "prose_note": ("AI-assisted from the supplied facts and fact-checked automatically." if used_ai
                       else "generated from the supplied facts without AI."),
    }
    title = f"Daily Threat Briefing: {day.strftime('%A')}, {day.strftime('%B')} {day.day}, {day.year}"
    return {"title": title, "raw": render_daily(ctx), "tags": tags, "external_id": f"daily-briefing-{day.isoformat()}",
            "stats": {**data["stats"], "top_threats": len(top)}, "notes": data["notes"], "ai": writer.stats,
            "overall": overall}


def main(argv: list[str] | None = None) -> int:
    from . import webhook

    ap = argparse.ArgumentParser(description="Daily threat briefing")
    ap.add_argument("--since", type=datetime.fromisoformat, help="window start, ISO (default: now - 24h, UTC)")
    ap.add_argument("--dry-run", action="store_true", help="write out/daily_briefing-<date>.md, no writes")
    ap.add_argument("--direct", action="store_true")
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "out")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    now = datetime.now(timezone.utc)
    since = args.since or now - timedelta(hours=24)
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)

    res = build(since, now, fx=default_fetcher(), writer=ai_mod.AIWriter(enabled=not args.no_ai))
    print(json.dumps({"title": res["title"], "overall": res["overall"], "tags": res["tags"], "stats": res["stats"],
                      "notes": res["notes"], "ai": res["ai"]}, indent=2))
    if args.dry_run:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        out = args.out_dir / f"daily_briefing-{now.date().isoformat()}.md"
        out.write_text(f"<!-- tags: {', '.join(res['tags'])} | external_id: {res['external_id']} -->\n\n"
                       f"# {res['title']}\n\n{res['raw']}", encoding="utf-8")
        print(f"dry-run: wrote {out}")
        return 0
    payload = webhook.build_payload("daily_briefing", res["title"], res["raw"], res["tags"], res["external_id"])
    print(json.dumps(webhook.deliver(payload, direct=args.direct)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
