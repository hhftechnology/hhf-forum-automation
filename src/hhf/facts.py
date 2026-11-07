"""Shared pure helpers: action rule, exploitation label, defanging, formatting."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from urllib.parse import urlsplit

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def severity_from_cvss(score: float | None) -> str | None:
    if score is None or score <= 0:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def action_for(kev: bool, epss: float | None, cvss: float | None) -> str:
    """KEV or EPSS >= 0.5 -> now; CVSS >= 9 or EPSS >= 0.1 -> 72h; else this week."""
    if kev or (epss is not None and epss >= 0.5):
        return "Patch now"
    if (cvss is not None and cvss >= 9.0) or (epss is not None and epss >= 0.1):
        return "Patch within 72h"
    return "Patch this week"


def exploitation_label(kev: bool, poc: bool) -> str:
    if kev:
        return "Known exploited (CISA KEV)"
    if poc:
        return "Public PoC"
    return "None known"


def fmt_epss(epss: float | None, pct: float | None) -> str:
    if epss is None:
        return "N/A"
    out = f"{epss:.3f}"
    if pct is not None:
        out += f" ({pct * 100:.1f}th percentile)"
    return out


def fmt_cvss(score: float | None) -> str:
    return "N/A" if score is None else f"{score:.1f}"


def fmt_date(d: date | datetime | str | None) -> str:
    if d is None:
        return "N/A"
    if isinstance(d, str):
        d = datetime.fromisoformat(d.replace("Z", "+00:00"))
    return f"{d.strftime('%B')} {d.day}, {d.year}"


def fmt_range(start: date, end: date) -> str:
    if start.year == end.year:
        return f"{start.strftime('%B')} {start.day} – {end.strftime('%B')} {end.day}, {end.year}"
    return f"{fmt_date(start)} – {fmt_date(end)}"


# ---- defanging ------------------------------------------------------------
def defang(value: str) -> str:
    """Make a URL, domain or IP safe to paste: hxxp://, [.] in the host part."""
    v = (value or "").strip()
    if not v:
        return v
    v = re.sub(r"^http", "hxxp", v, flags=re.I)
    v = re.sub(r"^ftp", "fxp", v, flags=re.I)
    scheme = ""
    if "://" in v:
        scheme, v = v.split("://", 1)
        scheme += "://"
    m = re.match(r"([^/?#]*)(.*)$", v, flags=re.S)
    host, tail = m.group(1), m.group(2)
    return scheme + host.replace(".", "[.]") + tail


def md_cell(s: object) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def md_text(s: object) -> str:
    """Neutralise untrusted text for the forum: no HTML, no accidental @mentions."""
    t = str(s if s is not None else "")
    t = t.replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"@(?=\w)", "@\u200b", t)
    return t


# ---- advisory model ---------------------------------------------------------
@dataclass
class Advisory:
    key: str  # primary id (GHSA or CVE) used for dedupe and posted.json
    title: str
    project: str
    ghsa: str | None = None
    cves: list[str] = field(default_factory=list)
    published: datetime | None = None
    severity: str | None = None
    cvss: float | None = None
    description: str = ""
    affected: str = ""
    fixed: str = ""
    fixed_version: str | None = None
    ecosystem: str | None = None
    package: str | None = None
    image: str | None = None
    category: str = ""
    workaround: str = ""
    poc: bool = False
    kev: dict[str, dict] = field(default_factory=dict)  # cve -> kev entry
    epss: dict[str, tuple[float, float]] = field(default_factory=dict)  # cve -> (score, pct)
    usn: list[tuple[str, str]] = field(default_factory=list)  # (id, url)
    references: list[tuple[str, str]] = field(default_factory=list)  # (label, url)
    sources: set[str] = field(default_factory=set)

    @property
    def is_kev(self) -> bool:
        return bool(self.kev)

    @property
    def max_epss(self) -> tuple[float, float] | tuple[None, None]:
        if not self.epss:
            return (None, None)
        return max(self.epss.values(), key=lambda t: t[0])

    def action(self) -> str:
        return action_for(self.is_kev, self.max_epss[0], self.cvss)

    def rows(self) -> list[dict]:
        """One table row per CVE (or one placeholder row when there is no CVE yet)."""
        out = []
        for cve in self.cves or [None]:
            e = self.epss.get(cve) if cve else None
            kev = cve in self.kev if cve else False
            out.append(
                {
                    "cve": cve or "— (no CVE yet)",
                    "cvss": fmt_cvss(self.cvss),
                    "exploitation": exploitation_label(kev, self.poc),
                    "epss": fmt_epss(*(e or (None, None))),
                    "action": action_for(kev, e[0] if e else None, self.cvss),
                }
            )
        return out


def host_of(url: str) -> str:
    return urlsplit(url).netloc
