"""Pure text helpers for the weekly advisory layout: versions, Go pseudo-versions, titles."""
from __future__ import annotations

import re
from datetime import datetime, timezone

# ---- Go pseudo-versions -----------------------------------------------------
# v0.0.0-20260102150405-abcdef123456, v1.2.4-0.20260102150405-abcdef123456, v1.2.3-20260102150405-abcdef123456
PSEUDO_RE = re.compile(r"(?<![/@\w-])v?\d+\.\d+\.\d+-(?:0\.)?(\d{14})-([0-9a-f]{12})\b", re.I)


def is_pseudo(version: str) -> bool:
    return bool(PSEUDO_RE.fullmatch((version or "").strip()))


def pseudo_parts(version: str) -> tuple[datetime, str] | None:
    m = PSEUDO_RE.fullmatch((version or "").strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return ts, m.group(2).lower()


COMMIT_RE = re.compile(r"(?<![/@\w-])[0-9a-f]{40}\b")


def is_commit(version: str) -> bool:
    """A bare git commit id (OSV lists these as 'fixed' for projects without tagged fixes)."""
    return bool(re.fullmatch(r"[0-9a-f]{40}", (version or "").strip(), re.I))


def scrub_pseudo(text: str) -> str:
    """Pseudo-versions and bare commit ids are never shown raw: replace them with 'commit <sha7>'."""
    t = PSEUDO_RE.sub(lambda m: f"commit {m.group(2)[:7].lower()}", text or "")
    return COMMIT_RE.sub(lambda m: f"commit {m.group(0)[:7].lower()}", t)


# ---- version ranges ---------------------------------------------------------
_OP_RE = re.compile(r"(>=|<=|>|<|=)\s*([^\s,;]+)")


def humanize_range(raw: str) -> str:
    """'<= 2.11.7' -> '≤ 2.11.7'; '< 26.7.8' -> 'before 26.7.8'; '>= 1.0.0, < 2.0.0' -> '1.0.0 – before 2.0.0'."""
    raw = (raw or "").strip()
    return scrub_pseudo(_humanize(raw))


def _humanize(raw: str) -> str:
    ops = _OP_RE.findall(raw)
    if not ops:
        return raw
    lo = hi = eq = None
    for op, ver in ops:
        if op in (">=", ">"):
            lo = (op, ver)
        elif op in ("<=", "<"):
            hi = (op, ver)
        else:
            eq = ver
    if eq and not lo and not hi:
        return eq
    if lo and lo[1] in ("0", "0.0", "0.0.0"):
        lo = None
    if lo and hi:
        return f"{lo[1]} – {hi[1]}" if hi[0] == "<=" else f"{lo[1]} – before {hi[1]}"
    if hi:
        return f"≤ {hi[1]}" if hi[0] == "<=" else f"before {hi[1]}"
    if lo:
        return f"{lo[1]} or later" if lo[0] == ">=" else f"after {lo[1]}"
    return raw


def humanize_ranges(raws: list[str]) -> str:
    out: list[str] = []
    for r in raws:
        h = humanize_range(r)
        if h and h not in out:
            out.append(h)
    return ", ".join(out)


# ---- titles -----------------------------------------------------------------
SMALL_WORDS = {"a", "an", "and", "as", "at", "but", "by", "for", "in", "of", "on", "or", "the", "to", "via", "vs", "with",
               "from", "into", "than", "per", "is", "are", "can", "no"}


ACRONYMS = {w.lower(): w for w in (
    "JWT RCE XSS CSRF SSRF SQL API URL URI DNS TLS SSL SSH HTTP HTTPS CVE DoS DDoS IP UI OAuth OAuth2 LDAP SAML OIDC SSO MFA 2FA "
    "XML JSON YAML CPU VPN ID IDs OS CLI ACL PHP CSS HTML JS SQLi XXE LFI RFI IDOR TOTP FD FDs NTLM GSS-TSIG TSIG DNSSEC "
    "RPZ UDP TCP FTP FTPS SMTP IMAP RSS SVG PDF MCP AI USN KEV TLS ACME CA PKI WAF CDN VM VMs GUI SDK TOTP HMAC").split()}


def _keep(word: str) -> bool:
    """Acronyms, mixed case, versions and code are left alone."""
    core = re.sub(r"^\W+|\W+$", "", word)
    if not core:
        return True
    return bool(re.search(r"\d", core) or re.search(r"[A-Z]", core[1:]) or "`" in word or "{" in word or "_" in core)


def _cap_part(part: str, first: bool) -> str:
    if not part:
        return part
    m = re.fullmatch(r"(\W*)(.*?)(\W*)", part)
    if m and m.group(2).lower() in ACRONYMS:
        return m.group(1) + ACRONYMS[m.group(2).lower()] + m.group(3)
    if _keep(part):
        return part
    if not first and part.lower() in SMALL_WORDS:
        return part.lower()
    m = re.search(r"[A-Za-z]", part)
    if not m:
        return part
    i = m.start()
    return part[:i] + part[i].upper() + part[i + 1:]


def title_case(s: str) -> str:
    """Title Case that keeps code spans, acronyms (NTLM, RCE), mixed case (pgAdmin, OAuth2) and versions intact."""
    out, in_code, first = [], False, True
    for word in re.split(r"(\s+)", s.strip()):
        if not word or word.isspace():
            out.append(word)
            continue
        was_code = in_code
        if word.count("`") % 2:
            in_code = not in_code
        if was_code or in_code or "`" in word:
            out.append(word)
        else:
            bits = re.split(r"([/\-–—])", word)
            out.append("".join(b if i % 2 else _cap_part(b, first and i == 0) for i, b in enumerate(bits)))
        first = False
    return "".join(out)


def lower_phrase(s: str) -> str:
    """Lower-case a Title Case phrase for use inside a sentence, keeping acronyms and code."""
    out = []
    for word in re.split(r"(\s+)", s.strip()):
        out.append(word if (not word or word.isspace() or _keep(word)) else word.lower())
    return "".join(out)


def strip_project(summary: str, names: list[str]) -> str:
    """Remove a leading 'Project:', 'Project has a' or plain 'Project ' from an advisory summary."""
    s = re.sub(r"\s+", " ", summary or "").strip()
    uniq = sorted({n for n in names if n}, key=len, reverse=True)
    for _ in range(3):
        before = s
        for n in uniq:
            pat = (rf"^{re.escape(n)}(?:\s+v?\d[\d.]*(?=['’]s\b|\s+[A-Za-z]))?(?:['’]s)?(?:\s*[:\-–—]\s*|\s+(?:has|have|is|are|contains?)\s+(?:an?\s+|the\s+)?|\s+)")
            s2 = re.sub(pat, "", s, count=1, flags=re.I)
            s2 = re.sub(r"^(?:allows?|permits?|enables?|lets?)\s+(?:an?\s+|the\s+)?", "", s2, flags=re.I)
            if s2 != s and s2:
                s = s2
                break
        if s == before:
            break
    return s.strip().rstrip(".").strip()


def short_title(summary: str, names: list[str], fallback: str = "Security Advisory") -> str:
    s = strip_project(summary, names)
    return title_case(s) if s else fallback


def fit_title(label: str, short: str, more: int = 0, limit: int = 90) -> str:
    """'<Project>: <Short Title>' (plus ', N More'), at most ~`limit` characters."""
    suffix = f", {more} More" if more > 0 else ""
    head = f"{label}: "
    room = max(limit - len(head) - len(suffix), 20)
    if len(short) > room:
        cut = short[:room]
        short = clip_phrase(short, room)
    return f"{head}{short}{suffix}"


def clip_phrase(s: str, room: int) -> str:
    """Shorten `s` to at most `room` characters at a natural break, never inside parentheses or code."""
    if len(s) <= room:
        return s
    cut = s[:room]
    low = cut.lower()
    best = -1
    for sep in (": ", " - ", " – ", ", ", " via ", " in ", " when ", " through ", " from ", " by ", " and ", " after ", " with "):
        i = low.rfind(sep)
        if i >= room * 0.45:
            best = max(best, i)
    cut = cut[:best] if best > 0 else (cut.rsplit(" ", 1)[0] if " " in cut else cut)
    while cut.count("(") > cut.count(")"):
        cut = cut[: cut.rfind("(")]
    if cut.count("`") % 2:
        cut = cut[: cut.rfind("`")]
    words = cut.rstrip(" ,;:-–(").split(" ")
    while len(words) > 1 and words[-1].lower().strip(",;:") in SMALL_WORDS:
        words.pop()
    return " ".join(words).rstrip(" ,;:-–(")


def join_list(items: list[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def join_names(items: list[str]) -> str:
    """'A', 'A and B', 'A, B and C' (no Oxford comma, as in the reference)."""
    items = [i for i in items if i]
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + f" and {items[-1]}"
