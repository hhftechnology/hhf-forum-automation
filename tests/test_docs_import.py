import json
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from hhf.discourse import DiscourseClient
from hhf.docs_import import (
    GitHub, GitHubRateLimit, MARKER_RE, DocTree, RepoCfg, backfill_dates, digest_of, external_id,
    frontmatter_date, sync_repo,
)


def test_external_id_limits_and_stability():
    for repo, path in [
        ("hhftechnology/middleware-manager", "docs/docs/content/docs/getting-started/deploy-standalone.mdx"),
        ("a/b", "x.mdx"),
    ]:
        e = external_id(repo, path)
        assert len(e) <= 50 and re.fullmatch(r"[\w-]+", e)
        assert e == external_id(repo, path)
    assert external_id("a/b", "x/y.mdx") != external_id("a/b", "x-y.mdx")


def test_tree_order_meta_sections_and_rest():
    files = {"index", "intro", "z-last", "guide/a", "guide/b", "guide/index", "api/x", "hidden"}
    metas = {
        "": {"pages": ["index", "---Basics---", "intro", "guide", "---Ref---", "api", "...", "[Ext](https://x)"]},
        "guide": {"pages": ["b", "a"]},
    }
    t = DocTree(files, metas)
    secs = t.sections()
    assert [s.title for s in secs] == [None, "Basics", "Ref"]
    assert secs[0].pages == ["index"]
    assert secs[1].pages == ["intro", "guide/b", "guide/a"]  # separator mode flattens folders
    assert secs[2].pages[0] == "api/x" and "hidden" in secs[2].pages and "z-last" in secs[2].pages
    assert t.link_targets()["guide"] == "guide/index"


def test_folder_sections_without_separators():
    t = DocTree({"index", "f/index", "f/a"}, {"": {"pages": ["index", "f"]}, "f": {"title": "Folder F"}})
    assert [(s.title, s.pages) for s in t.sections()] == [(None, ["index"]), ("Folder F", ["f/index", "f/a"])]


# -- fakes -------------------------------------------------------------------
FILES = {
    "docs/content/docs/index.mdx": "---\ntitle: Home\n---\nSee [Guide](/docs/guide) and ![i](./i.png)\n",
    "docs/content/docs/guide.mdx": "---\ntitle: Guide\ndescription: d\n---\n<Callout>hi</Callout>\n[home](./index.mdx)\n",
    "docs/content/docs/i.png": "PNGDATA",
    "docs/content/docs/meta.json": json.dumps({"pages": ["index", "guide"]}),
}


DATES = {
    "docs/content/docs/index.mdx": "2024-03-01T10:00:00Z",
    "docs/content/docs/guide.mdx": "2024-05-02T12:30:00Z",
}


class FakeGH:
    def first_commit_date(self, repo, branch, path):
        return DATES[path]

    def tree(self, repo, branch):
        return {p: f"sha-{i}" for i, p in enumerate(FILES)}

    def raw(self, repo, branch, path):
        return FILES[path].encode()

    def raw_url(self, repo, branch, path):
        return f"https://raw.test/{path}"


class FakeDiscourse:
    base_url = "https://forum.test"

    def __init__(self):
        self.topics, self.posts, self.calls, self.cats = {}, {}, [], {7: {"name": "Cat"}}
        self.created_at, self.stamps = {}, {}

    def get_topic_by_external_id(self, ext):
        t = self.topics.get(ext)
        if not t:
            return None
        return {"id": t["id"], "slug": t["slug"], "created_at": self.created_at.get(t["id"], "2026-11-07T00:00:00.000Z"),
                "post_stream": {"posts": [{"id": t["post"]}]}}

    def get_post(self, pid):
        return {"raw": self.posts[pid]}

    def change_timestamp(self, topic_id, timestamp):
        self.calls.append(("stamp", topic_id))
        self.stamps[topic_id] = timestamp
        self.created_at[topic_id] = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()

    def create_topic(self, *, title, raw, category, external_id=None, tags=None, created_at=None, **_):
        self.calls.append(("create", title))
        n = len(self.topics) + 1
        if created_at:
            self.created_at[n] = created_at
        self.topics[external_id] = {"id": n, "slug": re.sub(r"\W+", "-", title.lower()), "post": 100 + n}
        self.posts[100 + n] = raw
        assert category == 7
        return {"topic_id": n, "topic_slug": self.topics[external_id]["slug"], "id": 100 + n}

    def edit_first_post(self, post_id, raw, *, topic_id=None, title=None, edit_reason=None):
        self.calls.append(("edit", post_id))
        self.posts[post_id] = raw

    def upload_file(self, filename, content):
        self.calls.append(("upload", filename))
        return {"url": "/uploads/default/original/1X/abc.png"}

    def get_category(self, cid):
        return self.cats[cid]

    def update_category(self, cid, **fields):
        self.calls.append(("update_category", fields))
        self.cats[cid].update(fields)


CFG = RepoCfg("o/proj", "docs/content/docs", 7, label="Proj", tags=["docs"])


def test_sync_creates_links_and_sets_index_then_is_idempotent(tmp_path):
    dc = FakeDiscourse()
    st = sync_repo(CFG, FakeGH(), dc, dry_run=False, out_dir=tmp_path)
    assert st.created == 2 and st.index_set
    guide_raw = dc.posts[dc.topics[external_id("o/proj", "docs/content/docs/guide.mdx")]["post"]]
    assert "[home](/t/proj-home/1)" in guide_raw
    assert "> [!NOTE]" in guide_raw
    home_raw = dc.posts[dc.topics[external_id("o/proj", "docs/content/docs/index.mdx")]["post"]]
    assert "/uploads/default/original/1X/abc.png" in home_raw
    m = MARKER_RE.search(guide_raw)
    body = guide_raw[: guide_raw.index("<!-- hhf")].rstrip() + "\n"
    assert m and m.group(1) == digest_of("Proj: Guide", body)
    index_raw = dc.posts[dc.topics[external_id("o/proj", "__doc_index__")]["post"]]
    assert "- [Home](/t/proj-home/1)" in index_raw and "- [Guide](/t/proj-guide/2)" in index_raw
    cat_calls = [c for c in dc.calls if c[0] == "update_category"]
    assert cat_calls == [("update_category", {"doc_index_topic_id": 3})]

    dc.calls.clear()
    st2 = sync_repo(CFG, FakeGH(), dc, dry_run=False, out_dir=tmp_path)
    assert st2.created == 0 and st2.updated == 0 and st2.unchanged == 2
    assert [c for c in dc.calls if c[0] in ("edit", "create", "update_category")] == []


def test_edit_only_when_content_changes(tmp_path):
    dc = FakeDiscourse()
    sync_repo(CFG, FakeGH(), dc, dry_run=False, out_dir=tmp_path)
    dc.calls.clear()
    FILES["docs/content/docs/guide.mdx"] += "more\n"
    try:
        st = sync_repo(CFG, FakeGH(), dc, dry_run=False, out_dir=tmp_path)
    finally:
        FILES["docs/content/docs/guide.mdx"] = FILES["docs/content/docs/guide.mdx"][: -len("more\n")]
    assert st.updated == 1 and [c[0] for c in dc.calls].count("edit") == 1


def test_only_changed_skips_when_blobs_match(tmp_path):
    dc = FakeDiscourse()
    sync_repo(CFG, FakeGH(), dc, dry_run=False, out_dir=tmp_path)
    dc.calls.clear()
    st = sync_repo(CFG, FakeGH(), dc, dry_run=False, only_changed=True, out_dir=tmp_path)
    assert st.skipped == 2 and dc.calls == []


def test_dry_run_writes_out_and_never_touches_client(tmp_path):
    st = sync_repo(CFG, FakeGH(), None, dry_run=True, out_dir=tmp_path)
    assert st.pages == 2 and st.leftover == [] and st.unresolved_links == []
    assert (tmp_path / "proj" / "guide.md").exists() and (tmp_path / "proj" / "_index.md").exists()
    assert "raw.test/docs/content/docs/i.png" in (tmp_path / "proj" / "index.md").read_text()


def test_missing_category_id_is_an_error_when_writing(tmp_path):
    cfg = RepoCfg("o/proj", "docs/content/docs", None)
    with pytest.raises(SystemExit):
        sync_repo(cfg, FakeGH(), FakeDiscourse(), dry_run=False, out_dir=tmp_path)


# -- discourse client -----------------------------------------------------------
def test_client_retries_429_with_retry_after_and_hides_key():
    seen, sleeps = [], []

    def handler(req: httpx.Request):
        seen.append(req)
        if len(seen) == 1:
            return httpx.Response(429, headers={"Retry-After": "3"}, json={})
        return httpx.Response(200, json={"id": 5})

    c = DiscourseClient("https://f.test", "SECRETKEY", transport=httpx.MockTransport(handler), sleep=sleeps.append)
    assert c.request("GET", "/x.json") == {"id": 5}
    assert sleeps == [3.0] and len(seen) == 2
    assert seen[0].headers["Api-Key"] == "SECRETKEY" and seen[0].headers["Api-Username"] == "system"
    assert "SECRETKEY" not in repr(c)


def test_client_methods_hit_expected_endpoints():
    reqs = []

    def handler(req: httpx.Request):
        reqs.append((req.method, req.url.path, req.content.decode(errors="ignore")))
        if req.url.path.startswith("/t/external_id/missing"):
            return httpx.Response(404)
        if req.url.path.startswith("/c/9/show"):
            return httpx.Response(200, json={"category": {"name": "Docs"}})
        return httpx.Response(200, json={"ok": 1})

    c = DiscourseClient("https://f.test", "k", transport=httpx.MockTransport(handler))
    assert c.get_topic_by_external_id("missing") is None
    c.create_topic(title="T", raw="R", category=9, external_id="e", tags=["docs"])
    c.edit_first_post(11, "new", topic_id=3, title="T2")
    c.upload_file("a.png", b"\x89PNG")
    c.update_category(9, doc_index_topic_id=42)
    paths = [(m, p) for m, p, _ in reqs]
    assert ("POST", "/posts.json") in paths and ("PUT", "/posts/11.json") in paths
    assert ("PUT", "/t/-/3.json") in paths and ("POST", "/uploads.json") in paths
    put_cat = [b for m, p, b in reqs if p == "/categories/9.json"][0]
    assert "doc_index_topic_id=42" in put_cat and "name=Docs" in put_cat
    assert "external_id=e" in [b for m, p, b in reqs if p == "/posts.json"][0]


# -- original dates -----------------------------------------------------------------
def _commit(date):
    return {"commit": {"author": {"date": date}}}


def test_first_commit_date_follows_link_last_and_caches(tmp_path):
    reqs = []

    def handler(req: httpx.Request):
        reqs.append(str(req.url))
        if req.url.params.get("page") == "5":
            return httpx.Response(200, json=[_commit("2023-01-02T03:04:05-05:00")])
        return httpx.Response(
            200,
            json=[_commit("2025-09-09T00:00:00Z")],
            headers={"Link": '<https://api.github.com/repositories/1/commits?path=a.mdx&sha=main&per_page=1&page=2>; rel="next", '
                             '<https://api.github.com/repositories/1/commits?path=a.mdx&sha=main&per_page=1&page=5>; rel="last"'},
        )

    gh = GitHub("t", httpx.MockTransport(handler), cache_dir=tmp_path)
    assert gh.first_commit_date("o/r", "main", "a.mdx") == "2023-01-02T08:04:05Z"
    assert len(reqs) == 2
    assert "path=a.mdx" in reqs[0] and "sha=main" in reqs[0] and "per_page=1" in reqs[0]
    # cached in memory and on disk
    assert gh.first_commit_date("o/r", "main", "a.mdx") == "2023-01-02T08:04:05Z"
    gh2 = GitHub("t", httpx.MockTransport(lambda r: httpx.Response(500)), cache_dir=tmp_path)
    assert gh2.first_commit_date("o/r", "main", "a.mdx") == "2023-01-02T08:04:05Z"
    assert len(reqs) == 2


def test_first_commit_date_without_link_header_is_one_call(tmp_path):
    reqs = []

    def handler(req):
        reqs.append(req)
        return httpx.Response(200, json=[_commit("2024-02-03T04:05:06Z")])

    gh = GitHub(None, httpx.MockTransport(handler), cache_dir=tmp_path)
    assert gh.first_commit_date("o/r", "main", "b.mdx") == "2024-02-03T04:05:06Z"
    assert len(reqs) == 1


def test_github_rate_limit_is_a_clear_error(tmp_path):
    def handler(req):
        return httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"}, json={})

    gh = GitHub(None, httpx.MockTransport(handler), cache_dir=tmp_path)
    with pytest.raises(GitHubRateLimit):
        gh.first_commit_date("o/r", "main", "c.mdx")


def test_frontmatter_date_overrides_commit_date(tmp_path):
    assert frontmatter_date("---\ntitle: x\ndate: 2022-06-07\n---\nbody") == "2022-06-07T00:00:00Z"
    assert frontmatter_date("---\npublished: '2021-01-02T03:04:05+02:00'\n---\n") == "2021-01-02T01:04:05Z"
    assert frontmatter_date("---\ncreated: 2020-05-05\n---\n") == "2020-05-05T00:00:00Z"
    assert frontmatter_date("---\ntitle: x\n---\n") is None
    assert frontmatter_date("---\ndate: nonsense\n---\n") is None

    files = dict(FILES)
    files["docs/content/docs/guide.mdx"] = "---\ntitle: Guide\ndate: 2020-01-01\n---\nhello\n"

    class GH(FakeGH):
        def raw(self, repo, branch, path):
            return files[path].encode()

    dc = FakeDiscourse()
    sync_repo(CFG, GH(), dc, dry_run=False, out_dir=tmp_path)
    ext = external_id("o/proj", "docs/content/docs/guide.mdx")
    assert dc.created_at[dc.topics[ext]["id"]] == "2020-01-01T00:00:00Z"


def test_created_at_passed_on_create_and_index_gets_earliest(tmp_path):
    dc = FakeDiscourse()
    sync_repo(CFG, FakeGH(), dc, dry_run=False, out_dir=tmp_path)
    got = {ext: dc.created_at[t["id"]] for ext, t in dc.topics.items()}
    assert got[external_id("o/proj", "docs/content/docs/index.mdx")] == DATES["docs/content/docs/index.mdx"]
    assert got[external_id("o/proj", "docs/content/docs/guide.mdx")] == DATES["docs/content/docs/guide.mdx"]
    assert got[external_id("o/proj", "__doc_index__")] == "2024-03-01T10:00:00Z"


def test_client_create_topic_posts_created_at_and_change_timestamp_route():
    reqs = []

    def handler(req):
        reqs.append((req.method, req.url.path, req.content.decode()))
        return httpx.Response(200, json={})

    c = DiscourseClient("https://f.test", "k", transport=httpx.MockTransport(handler))
    c.create_topic(title="T", raw="R", category=9, created_at="2024-03-01T10:00:00Z")
    c.change_timestamp(12, 1709287200)
    assert "created_at=2024-03-01T10%3A00%3A00Z" in reqs[0][2]
    assert reqs[1][:2] == ("PUT", "/t/12/change-timestamp") and reqs[1][2] == "timestamp=1709287200"


def test_backfill_is_idempotent_and_never_edits_content(tmp_path):
    dc = FakeDiscourse()
    sync_repo(CFG, FakeGH(), dc, dry_run=False, out_dir=tmp_path)
    for tid in dc.created_at:  # simulate the existing "today" topics
        dc.created_at[tid] = "2026-11-07T08:00:00.000Z"
    dc.calls.clear()
    posts_before = dict(dc.posts)

    st = backfill_dates(CFG, FakeGH(), dc)
    assert (st.checked, st.changed, st.skipped, st.missing) == (3, 3, 0, 0)
    ext = external_id("o/proj", "docs/content/docs/guide.mdx")
    assert dc.stamps[dc.topics[ext]["id"]] == int(datetime(2024, 5, 2, 12, 30, tzinfo=timezone.utc).timestamp())
    idx = dc.topics[external_id("o/proj", "__doc_index__")]["id"]
    assert dc.stamps[idx] == int(datetime(2024, 3, 1, 10, tzinfo=timezone.utc).timestamp())

    dc.calls.clear()
    st2 = backfill_dates(CFG, FakeGH(), dc)
    assert (st2.checked, st2.changed, st2.skipped) == (3, 0, 3)
    assert dc.calls == [] and dc.posts == posts_before  # no stamps, no edits, content hash untouched


def test_backfill_skips_within_one_day_and_counts_missing(tmp_path):
    dc = FakeDiscourse()
    st = backfill_dates(CFG, FakeGH(), dc)  # nothing exists yet
    assert (st.checked, st.changed, st.missing) == (0, 0, 3)
    sync_repo(CFG, FakeGH(), dc, dry_run=False, out_dir=tmp_path)
    dc.created_at[1] = "2024-03-01T20:00:00Z"  # 10h off the target: leave alone
    st = backfill_dates(CFG, FakeGH(), dc)
    assert st.changed == 0 and st.skipped == 3
