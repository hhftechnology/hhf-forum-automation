"""Import Fumadocs MDX docs from GitHub into Discourse doc categories.

    python -m hhf.docs_import --dry-run            # render to out/, no writes
    python -m hhf.docs_import --repo crowdsec_manager --only-changed
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import mimetypes
import os
import posixpath
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import httpx
import yaml

from .mdx import convert_mdx, doc_slug, find_leftover_jsx, rewrite_links

log = logging.getLogger("hhf.docs_import")

MARKER_RE = re.compile(r"<!-- hhf-docs-sync sha256:([0-9a-f]{64}) blob:([\w-]*) -->\s*\Z")
DEFAULT_URL = "https://forum.hhf.technology"


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------
@dataclass
class RepoCfg:
    repo: str
    path: str
    category_id: int | None
    branch: str = "main"
    label: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.repo.split("/")[-1]


def load_config(path: str | Path) -> list[RepoCfg]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    tags = data.get("tags") or []
    out = []
    for r in data["repos"]:
        out.append(
            RepoCfg(
                repo=r["repo"],
                path=r["path"].strip("/"),
                category_id=r.get("category_id"),
                branch=r.get("branch", "main"),
                label=r.get("label") or r["repo"].split("/")[-1],
                tags=list(r.get("tags", tags)),
            )
        )
    return out


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def external_id(repo: str, path: str) -> str:
    """Discourse external_id: max 50 chars, /\\A[\\w-]+\\z/, unique case-insensitively
    (app/models/topic.rb: EXTERNAL_ID_MAX_LENGTH = 50). The readable logical id is
    f"{repo}:{path}"; it is sanitised and suffixed with an 8-char sha1 of the original."""
    logical = f"{repo}:{path}"
    digest = hashlib.sha1(logical.lower().encode()).hexdigest()[:8]
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", logical).strip("-")
    return f"{slug[:41].rstrip('-')}-{digest}"


def digest_of(title: str, raw: str) -> str:
    return hashlib.sha256(f"{title}\n{raw}".encode()).hexdigest()


def with_marker(raw: str, digest: str, blob: str) -> str:
    return f"{raw.rstrip()}\n\n<!-- hhf-docs-sync sha256:{digest} blob:{blob} -->\n"


def pretty(name: str) -> str:
    return re.sub(r"[-_]+", " ", name).strip().title()


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "topic"


# --------------------------------------------------------------------------
# GitHub (read only)
# --------------------------------------------------------------------------
class GitHub:
    def __init__(self, token: str | None = None, transport: httpx.BaseTransport | None = None):
        token = token if token is not None else os.environ.get("GITHUB_TOKEN")
        headers = {"User-Agent": "hhf-docs-import"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(headers=headers, transport=transport, timeout=30, follow_redirects=True)
        self._cache: dict[str, bytes] = {}

    def tree(self, repo: str, branch: str) -> dict[str, str]:
        """{path: blob sha} for every blob; a single recursive git/trees call."""
        r = self._http.get(
            f"https://api.github.com/repos/{repo}/git/trees/{branch}",
            params={"recursive": "1"},
            headers={"Accept": "application/vnd.github+json"},
        )
        r.raise_for_status()
        data = r.json()
        if data.get("truncated"):
            log.warning("%s: git tree truncated", repo)
        return {e["path"]: e["sha"] for e in data["tree"] if e["type"] == "blob"}

    def raw_url(self, repo: str, branch: str, path: str) -> str:
        return f"https://raw.githubusercontent.com/{repo}/{branch}/{quote(path)}"

    def raw(self, repo: str, branch: str, path: str) -> bytes:
        url = self.raw_url(repo, branch, path)
        if url not in self._cache:
            r = self._http.get(url)
            r.raise_for_status()
            self._cache[url] = r.content
        return self._cache[url]


# --------------------------------------------------------------------------
# ordering (Fumadocs meta.json)
# --------------------------------------------------------------------------
@dataclass
class Section:
    title: str | None
    pages: list[str] = field(default_factory=list)  # rel paths w/o extension ("a/b")


class DocTree:
    """rel-path model of the docs folder. ``files`` are mdx paths relative to the
    docs root without extension; ``metas`` maps directory ('' = root) -> meta.json."""

    def __init__(self, files: set[str], metas: dict[str, dict]):
        self.files = files
        self.metas = metas
        self.dirs = {""}
        for f in files:
            parts = f.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                self.dirs.add("/".join(parts[:i]))

    def _children(self, d: str) -> tuple[list[str], list[str]]:
        pre = d + "/" if d else ""
        files, dirs = [], set()
        for f in self.files:
            if f.startswith(pre):
                rest = f[len(pre):]
                if "/" in rest:
                    dirs.add(rest.split("/")[0])
                else:
                    files.append(rest)
        key = lambda n: (n != "index", n)  # noqa: E731
        return sorted(files, key=key), sorted(dirs)

    def dir_pages(self, d: str, seen: set[str] | None = None) -> list[str]:
        """Pages in a directory (recursive, flattened) following meta.json order."""
        seen = set() if seen is None else seen
        pre = d + "/" if d else ""
        files, dirs = self._children(d)
        meta = self.metas.get(d)
        out: list[str] = []

        def add_file(n: str):
            p = pre + n
            if p in self.files and p not in seen:
                seen.add(p)
                out.append(p)

        def add_dir(n: str):
            out.extend(self.dir_pages(pre + n, seen))

        def add_rest():
            for n in files:
                add_file(n)
            for n in dirs:
                if (pre + n) not in seen:
                    add_dir(n)

        if not meta or not meta.get("pages"):
            add_rest()
            return out
        for entry in meta["pages"]:
            if not isinstance(entry, str):
                continue
            if entry == "..." or entry == "z...a":
                add_rest()
            elif entry.startswith("..."):
                add_dir(entry[3:])
            elif re.match(r"^---.*---$", entry) or re.match(r"^\[.*\]\(.*\)$", entry) or entry.startswith("!"):
                continue
            elif (pre + entry) in self.files:
                add_file(entry)
            elif (pre + entry) in self.dirs:
                add_dir(entry)
        return out

    def title_of_dir(self, d: str) -> str:
        meta = self.metas.get(d) or {}
        return meta.get("title") or pretty(d.split("/")[-1])

    def sections(self) -> list[Section]:
        """Top level sections for the index topic (listed pages only)."""
        meta = self.metas.get("") or {}
        entries = meta.get("pages") if isinstance(meta.get("pages"), list) else None
        out = [Section(None)]
        seen: set[str] = set()
        if entries is None:
            entries = ["..."]
        has_sep = any(isinstance(e, str) and re.match(r"^---.+---$", e) for e in entries)

        def cur() -> Section:
            return out[-1]

        for e in entries:
            if not isinstance(e, str):
                continue
            m = re.match(r"^---(.+)---$", e)
            if m:
                out.append(Section(m.group(1).strip()))
            elif e in ("...", "z...a"):
                files, dirs = self._children("")
                for n in files:
                    if n not in seen and n in self.files:
                        seen.add(n)
                        cur().pages.append(n)
                for n in dirs:
                    self._add_dir_section(n, out, seen, has_sep)
            elif e.startswith("..."):
                self._add_dir_section(e[3:], out, seen, True)
            elif re.match(r"^\[.*\]\(.*\)$", e) or e.startswith("!"):
                continue
            elif e in self.files:
                if e not in seen:
                    seen.add(e)
                    cur().pages.append(e)
            elif e in self.dirs:
                self._add_dir_section(e, out, seen, has_sep)
        return [s for s in out if s.pages]

    def _add_dir_section(self, d: str, out: list[Section], seen: set[str], flatten: bool):
        if d not in self.dirs:
            return
        pages = [p for p in self.dir_pages(d) if p not in seen]
        if not pages:
            return
        seen.update(pages)
        if flatten:
            out[-1].pages.extend(pages)
        else:
            out.append(Section(self.title_of_dir(d), pages))

    def link_targets(self) -> dict[str, str]:
        """slug -> rel page, including folder slugs (index page or first page)."""
        m = {}
        for f in self.files:
            slug = re.sub(r"(^|/)index$", "", f)
            m[slug] = f
        for d in self.dirs:
            if d not in m:
                pages = self.dir_pages(d)
                if pages:
                    m[d] = pages[0]
        return m


# --------------------------------------------------------------------------
# sync
# --------------------------------------------------------------------------
@dataclass
class Page:
    rel: str  # path relative to docs root, no extension
    repo_path: str  # path in repo, with extension
    blob: str
    title: str = ""
    raw: str = ""  # converted body (links unresolved)
    topic_id: int | None = None
    slug: str = ""
    post_id: int | None = None
    existing_marker: tuple[str, str] | None = None
    created_digest: str | None = None


@dataclass
class Stats:
    repo: str
    pages: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    unresolved_links: list[str] = field(default_factory=list)
    leftover: list[str] = field(default_factory=list)
    unlisted: list[str] = field(default_factory=list)
    index_set: str = ""


def load_tree(cfg: RepoCfg, gh: GitHub) -> tuple[DocTree, dict[str, str]]:
    blobs = gh.tree(cfg.repo, cfg.branch)
    pre = cfg.path + "/"
    files, metas, shas = set(), {}, {}
    for p, sha in blobs.items():
        if not p.startswith(pre):
            continue
        rel = p[len(pre):]
        if rel.endswith(".mdx"):
            files.add(rel[:-4])
            shas[rel[:-4]] = sha
        elif rel.endswith("meta.json"):
            d = posixpath.dirname(rel)
            try:
                metas[d] = json.loads(gh.raw(cfg.repo, cfg.branch, p))
            except ValueError:
                log.warning("bad meta.json %s", p)
    return DocTree(files, metas), shas


def build_titles(cfg: RepoCfg, pages: list[Page]) -> None:
    """Topic titles are globally unique in Discourse: prefix with the project
    label and disambiguate duplicates with the folder name."""
    for p in pages:
        t = p.title
        if not t.lower().startswith(cfg.label.lower()):
            t = f"{cfg.label}: {t}"
        p.title = t[:250]
    seen: dict[str, int] = {}
    for p in pages:
        seen[p.title.lower()] = seen.get(p.title.lower(), 0) + 1
    for p in pages:
        if seen[p.title.lower()] > 1:
            folder = posixpath.dirname(p.rel)
            extra = pretty(folder.split("/")[-1]) if folder else pretty(posixpath.basename(p.rel))
            p.title = f"{p.title} ({extra})"[:250]


def make_image_resolver(cfg: RepoCfg, gh: GitHub, rel: str, client, upload: bool, uploaded: dict):
    app_root = cfg.path.split("/content/")[0] if "/content/" in cfg.path else cfg.path
    doc_dir = posixpath.dirname(f"{cfg.path}/{rel}.mdx")

    def resolve(src: str) -> str | None:
        clean = src.split("?")[0].split("#")[0]
        repo_path = (
            posixpath.normpath(f"{app_root}/public{clean}")
            if clean.startswith("/")
            else posixpath.normpath(posixpath.join(doc_dir, clean))
        )
        raw_url = gh.raw_url(cfg.repo, cfg.branch, repo_path)
        if not upload or client is None:
            return raw_url
        if repo_path in uploaded:
            return uploaded[repo_path]
        try:
            data = gh.raw(cfg.repo, cfg.branch, repo_path)
            res = client.upload_file(posixpath.basename(repo_path), data)
            url = res.get("url") or raw_url
            if url.startswith("/"):
                url = client.base_url + url
        except Exception as exc:  # noqa: BLE001
            log.warning("image upload failed for %s (%s); using raw URL", repo_path, type(exc).__name__)
            url = raw_url
        uploaded[repo_path] = url
        return url

    return resolve


def index_raw(cfg: RepoCfg, sections: list[Section], titles: dict[str, str], urls: dict[str, str]) -> str:
    """Index topic body in the shape discourse-doc-categories' DocIndexTopicParser reads:
    a heading starts a section, each list item `[Title](topic url)` is a link."""
    out = [f"Documentation index for {cfg.label}. Generated from {cfg.repo}; edits are overwritten.\n"]
    for s in sections:
        if s.title:
            out.append(f"## {s.title}\n")
        out.append("\n".join(f"- [{titles[p]}]({urls[p]})" for p in s.pages) + "\n")
    return "\n".join(out)


def sync_repo(
    cfg: RepoCfg,
    gh: GitHub,
    client,
    *,
    dry_run: bool,
    only_changed: bool = False,
    upload_images: bool = True,
    out_dir: Path = Path("out"),
    base_url: str = DEFAULT_URL,
) -> Stats:
    st = Stats(cfg.repo)
    tree, shas = load_tree(cfg, gh)
    sections = tree.sections()
    listed = {p for s in sections for p in s.pages}
    st.unlisted = sorted(tree.files - listed)
    order = [p for s in sections for p in s.pages] + st.unlisted
    pages = [Page(rel, f"{cfg.path}/{rel}.mdx", shas[rel]) for rel in order]
    st.pages = len(pages)
    by_rel = {p.rel: p for p in pages}
    if not dry_run and cfg.category_id is None:
        raise SystemExit(f"{cfg.repo}: category_id is not set in config/docs.yml")

    # existing topics (read only)
    if client is not None:
        for p in pages:
            t = client.get_topic_by_external_id(external_id(cfg.repo, p.repo_path))
            if t:
                p.topic_id, p.slug = t["id"], t.get("slug", "")
                p.post_id = t["post_stream"]["posts"][0]["id"]
                m = MARKER_RE.search(client.get_post(p.post_id).get("raw", ""))
                p.existing_marker = (m.group(1), m.group(2)) if m else None
        index_ext = external_id(cfg.repo, "__doc_index__")
        index_topic = client.get_topic_by_external_id(index_ext)
        if only_changed and index_topic and all(
            p.existing_marker and p.existing_marker[1] == p.blob for p in pages
        ):
            st.skipped = len(pages)
            log.info("%s: nothing changed", cfg.repo)
            return st

    # pass A: convert, create missing topics
    uploaded: dict[str, str] = {}
    for p in pages:
        src = gh.raw(cfg.repo, cfg.branch, p.repo_path).decode("utf-8")
        resolver = make_image_resolver(cfg, gh, p.rel, client, upload_images and not dry_run, uploaded)
        conv = convert_mdx(src, fallback_title=pretty(posixpath.basename(p.rel)), image_resolver=resolver)
        p.title, p.raw = conv.title, conv.body
    plain_titles = {p.rel: p.title for p in pages}
    build_titles(cfg, pages)

    for p in pages:
        if client is not None and p.topic_id is None:
            body = p.raw
            dg = digest_of(p.title, body)
            res = client.create_topic(
                title=p.title,
                raw=with_marker(body, dg, p.blob),
                category=cfg.category_id,
                external_id=external_id(cfg.repo, p.repo_path),
                tags=cfg.tags,
            )
            p.topic_id, p.slug, p.post_id = res["topic_id"], res["topic_slug"], res["id"]
            p.created_digest = dg
            p.existing_marker = (dg, p.blob)
            st.created += 1

    # pass B: resolve links, edit changed
    link_targets = tree.link_targets()
    urls: dict[str, str] = {}
    for p in pages:
        urls[p.rel] = (
            f"/t/{p.slug}/{p.topic_id}" if p.topic_id else f"{base_url}/t/{slugify(p.title)}"
        )
    known = {slug: urls[rel] for slug, rel in link_targets.items()}
    final: dict[str, str] = {}
    for p in pages:
        raw = rewrite_links(p.raw, p.rel + ".mdx", known, st.unresolved_links)
        final[p.rel] = raw
        st.leftover += [f"{p.rel}: {h}" for h in find_leftover_jsx(raw)]
        dg = digest_of(p.title, raw)
        text = with_marker(raw, dg, p.blob)
        if dry_run:
            _write(out_dir / cfg.name / f"{p.rel}.md", f"<!-- title: {p.title} -->\n" + text)
            continue
        if p.existing_marker and p.existing_marker[0] == dg:
            if p.created_digest is None:
                st.unchanged += 1
            continue
        client.edit_first_post(
            p.post_id, text, topic_id=p.topic_id, title=p.title, edit_reason="docs sync from GitHub"
        )
        st.updated += 1

    # index topic
    body = index_raw(cfg, sections, plain_titles, urls)
    idx_dg = digest_of("index", body)
    idx_text = with_marker(body, idx_dg, "")
    if dry_run:
        _write(out_dir / cfg.name / "_index.md", idx_text)
        return st
    idx_title = f"{cfg.label} Documentation"
    if not index_topic:
        res = client.create_topic(
            title=idx_title, raw=idx_text, category=cfg.category_id, external_id=index_ext, tags=cfg.tags
        )
        index_id = res["topic_id"]
    else:
        index_id = index_topic["id"]
        post_id = index_topic["post_stream"]["posts"][0]["id"]
        m = MARKER_RE.search(client.get_post(post_id).get("raw", ""))
        if not (m and m.group(1) == idx_dg):
            client.edit_first_post(post_id, idx_text, edit_reason="docs sync from GitHub")
    cat = client.get_category(cfg.category_id)
    if cat.get("doc_index_topic_id") != index_id:
        client.update_category(cfg.category_id, doc_index_topic_id=index_id)
    st.index_set = f"topic {index_id}"
    return st


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="config/docs.yml")
    ap.add_argument("--dry-run", action="store_true", help="render to --out, no Discourse access")
    ap.add_argument("--repo", action="append", help="owner/name or name; repeatable")
    ap.add_argument("--only-changed", action="store_true")
    ap.add_argument("--no-upload-images", action="store_true", help="use raw GitHub URLs for images")
    ap.add_argument("--out", default="out")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    cfgs = load_config(args.config)
    if args.repo:
        want = {r.lower() for r in args.repo if r}
        cfgs = [c for c in cfgs if c.repo.lower() in want or c.name.lower() in want]
        if not cfgs:
            log.error("no repo matches %s", args.repo)
            return 2
    gh = GitHub()
    client = None
    base = os.environ.get("DISCOURSE_URL", DEFAULT_URL).rstrip("/") or DEFAULT_URL
    if not args.dry_run:
        from .discourse import DiscourseClient

        client = DiscourseClient()
    rc = 0
    for cfg in cfgs:
        st = sync_repo(
            cfg, gh, client, dry_run=args.dry_run, only_changed=args.only_changed,
            upload_images=not args.no_upload_images, out_dir=Path(args.out), base_url=base,
        )
        print(
            f"{cfg.repo}: pages={st.pages} created={st.created} updated={st.updated} "
            f"unchanged={st.unchanged} skipped={st.skipped} unlisted={len(st.unlisted)} "
            f"unresolved_links={len(st.unresolved_links)} leftover_jsx={len(st.leftover)} {st.index_set}"
        )
        for u in st.unresolved_links:
            print(f"  unresolved link: {u}")
        for h in st.leftover:
            print(f"  leftover: {h}")
        rc |= bool(st.leftover)
    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())
