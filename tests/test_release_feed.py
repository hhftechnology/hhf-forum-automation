import json
import sys
from pathlib import Path

import httpx

from hhf import release_feed as rf
from hhf.discourse import DiscourseClient
from hhf.webhook import DeliveryError

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import build_workflow_json as bwj  # noqa: E402


def rel(tag, pre=False):
    return {"repo": "o/r", "tag": tag, "name": tag, "url": f"https://x/{tag}", "published": None,
            "prerelease": pre, "security": False, "body": f"notes {tag}"}


class FakeClient:
    def __init__(self):
        self.posts = []

    def create_post(self, topic_id, raw):
        self.posts.append((topic_id, raw))


ENTRY = {"repo": "o/r", "category_id": 1, "topic_id": 42, "groups": [], "include_prereleases": False}


def fetcher(rows):
    return lambda repo, per_page=10: rows  # newest first, like the GitHub API


def test_new_releases_posted_oldest_first():
    c, state = FakeClient(), {"last": {"o/r": "v1"}}
    rf.run([ENTRY], state, c, dry_run=False, fetch=fetcher([rel("v3"), rel("v2"), rel("v1")]))
    assert [p[0] for p in c.posts] == [42, 42]
    assert "v2" in c.posts[0][1] and "v3" in c.posts[1][1]
    assert state["last"]["o/r"] == "v3"


def test_already_posted_skipped():
    c, state = FakeClient(), {"last": {"o/r": "v2"}}
    assert rf.run([ENTRY], state, c, dry_run=False, fetch=fetcher([rel("v2"), rel("v1")])) == 0
    assert c.posts == []


def test_first_run_records_baseline_without_posting():
    c, state = FakeClient(), {"last": {}}
    rf.run([ENTRY], state, c, dry_run=False, fetch=fetcher([rel("v2"), rel("v1")]))
    assert c.posts == [] and state["last"]["o/r"] == "v2"


def test_prereleases_filtered_unless_enabled():
    rows = [rel("v2-rc1", pre=True), rel("v1")]
    c, state = FakeClient(), {"last": {"o/r": "v1"}}
    rf.run([ENTRY], state, c, dry_run=False, fetch=fetcher(rows))
    assert c.posts == []
    rf.run([{**ENTRY, "include_prereleases": True}], state, c, dry_run=False, fetch=fetcher(rows))
    assert len(c.posts) == 1 and "(pre-release)" in c.posts[0][1]


def test_dry_run_writes_nothing(tmp_path, monkeypatch, capsys):
    cfg, st = tmp_path / "releases.yml", tmp_path / "releases.json"
    cfg.write_text("releases:\n- {repo: o/r, category_id: 1, topic_id: 42}\n", encoding="utf-8")
    st.write_text(json.dumps({"last": {"o/r": "v1"}}), encoding="utf-8")
    before = st.read_text(encoding="utf-8")
    monkeypatch.setattr(rf.releases, "latest", lambda repo, fx=None, per_page=5: [rel("v2"), rel("v1")])
    monkeypatch.setattr(rf, "DiscourseClient", lambda: (_ for _ in ()).throw(AssertionError("no client in dry-run")))
    assert rf.main(["--dry-run", "--config", str(cfg), "--state", str(st)]) == 0
    assert "post o/r v2" in capsys.readouterr().out
    assert st.read_text(encoding="utf-8") == before
    assert len(list(tmp_path.iterdir())) == 2


def test_state_saved_when_a_later_post_fails(tmp_path, monkeypatch):
    cfg, st = tmp_path / "releases.yml", tmp_path / "releases.json"
    cfg.write_text("releases:\n- {repo: o/r, category_id: 1, topic_id: 42}\n", encoding="utf-8")
    st.write_text(json.dumps({"last": {"o/r": "v1"}}), encoding="utf-8")

    class Flaky:
        n = 0

        def create_post(self, topic_id, raw):
            Flaky.n += 1
            if Flaky.n > 1:
                raise RuntimeError("boom")

    monkeypatch.setattr(rf.releases, "latest", lambda repo, fx=None, per_page=5: [rel("v3"), rel("v2"), rel("v1")])
    monkeypatch.setattr(rf, "DiscourseClient", Flaky)
    try:
        rf.main(["--config", str(cfg), "--state", str(st)])
    except RuntimeError:
        pass
    assert json.loads(st.read_text(encoding="utf-8"))["last"]["o/r"] == "v2"


def test_render_neutralizes_mentions_and_truncates():
    out = rf.render({**rel("v1"), "body": "Thanks @alice and @team-x! mail a@b.c"})
    assert "@alice" not in out and "@​alice" in out and "@​team-x" in out
    long = rf.render({**rel("v1"), "body": "x" * (rf.MAX_BODY + 500)})
    assert len(long) < rf.MAX_BODY + 300 and "[Full release notes](https://x/v1)" in long


def test_state_missing_is_empty_corrupt_raises(tmp_path):
    p = tmp_path / "s.json"
    assert rf.load_json(p) == {"last": {}}
    rf.save_json(p, {"last": {"o/r": "v1"}})
    assert rf.load_json(p) == {"last": {"o/r": "v1"}} and not (tmp_path / "s.json.tmp").exists()
    p.write_text("{trunc", encoding="utf-8")
    try:
        rf.load_json(p)
        raise AssertionError("corrupt state must not be read as empty")
    except ValueError:
        pass


def test_failed_post_stops_that_repo_only():
    class FailOnV3(FakeClient):
        def create_post(self, topic_id, raw):
            if topic_id == 42 and "v3" in raw:
                raise RuntimeError("boom")
            super().create_post(topic_id, raw)

    rows = [rel("v4"), rel("v3"), rel("v2")]
    other = {**ENTRY, "repo": "o/s", "topic_id": 43}
    c, state = FailOnV3(), {"last": {"o/r": "v2", "o/s": "v2"}}
    try:
        rf.run([ENTRY, other], state, c, dry_run=False, fetch=fetcher(rows))
        raise AssertionError("expected the run to report the failure")
    except RuntimeError as exc:
        assert "o/r" in str(exc)
    assert state["last"] == {"o/r": "v2", "o/s": "v4"}  # v3 failed: o/r not advanced, v4 not posted out of order
    assert [p[0] for p in c.posts] == [43, 43]


# -- webhook notify ----------------------------------------------------------
GROUP_ENTRY = {**ENTRY, "groups": ["releases-r"]}
RESULT = {"topic_slug": "o-r-releases", "topic_id": 42, "post_number": 5}


class PostClient(FakeClient):
    def create_post(self, topic_id, raw):
        super().create_post(topic_id, raw)
        return RESULT


def webhook_env(monkeypatch):
    monkeypatch.setenv("WORKFLOW_WEBHOOK_URL_RELEASE", "https://hook.invalid/x")
    monkeypatch.setenv("WORKFLOW_WEBHOOK_TOKEN", "s3cret")
    monkeypatch.setenv("DISCOURSE_URL", "https://forum.example")


def test_webhook_called_once_per_post(monkeypatch):
    webhook_env(monkeypatch)
    sent = []
    monkeypatch.setattr(rf, "post_webhook", sent.append)
    state = {"last": {"o/r": "v1"}}
    rf.run([GROUP_ENTRY], state, PostClient(), dry_run=False, fetch=fetcher([rel("v3"), rel("v2"), rel("v1")]))
    assert sent == [
        {"kind": "release", "repo": "o/r", "tag": t, "url": "https://forum.example/t/o-r-releases/42/5",
         "groups": ["releases-r"]} for t in ("v2", "v3")]


def test_webhook_failure_still_advances_state(monkeypatch, capsys):
    webhook_env(monkeypatch)

    def boom(payload):
        raise DeliveryError("webhook returned HTTP 500")

    monkeypatch.setattr(rf, "post_webhook", boom)
    c, state = PostClient(), {"last": {"o/r": "v1"}}
    rf.run([GROUP_ENTRY], state, c, dry_run=False, fetch=fetcher([rel("v2"), rel("v1")]))
    assert len(c.posts) == 1 and state["last"]["o/r"] == "v2"
    err = capsys.readouterr().err
    assert "warning" in err and "s3cret" not in err and "hook.invalid" not in err


def test_no_groups_or_no_env_means_no_webhook(monkeypatch):
    sent = []
    monkeypatch.setattr(rf, "post_webhook", sent.append)
    webhook_env(monkeypatch)
    rf.run([ENTRY], {"last": {"o/r": "v1"}}, PostClient(), dry_run=False, fetch=fetcher([rel("v2"), rel("v1")]))
    monkeypatch.delenv("WORKFLOW_WEBHOOK_URL_RELEASE")
    rf.run([GROUP_ENTRY], {"last": {"o/r": "v1"}}, PostClient(), dry_run=False, fetch=fetcher([rel("v2"), rel("v1")]))
    assert sent == []


# -- bootstrap -------------------------------------------------------------------
class BootClient:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def call(*a, **kw):
            self.calls.append(name)
            return {"id": 7, "topic_id": 8}
        return call

    def list_categories(self):
        self.calls.append("list_categories")
        return []


def test_bootstrap_dry_run_prints_and_calls_nothing(capsys):
    rf.bootstrap([{"repo": "o/r", "groups": ["releases-r"]}], None, dry_run=True)
    out = capsys.readouterr().out
    assert "would ensure public group 'releases-r'" in out and "would mute" in out


def test_bootstrap_real_ensures_groups_watching_and_mute():
    c = BootClient()
    rf.bootstrap([{"repo": "o/r", "groups": ["releases-r"]}], c, dry_run=False)
    for name in ("ensure_group", "watch_category_for_group", "mute_categories_by_default"):
        assert name in c.calls


def test_bootstrap_still_does_groups_for_fully_configured_entry():
    c = BootClient()
    rf.bootstrap([{**GROUP_ENTRY}], c, dry_run=False)
    assert "create_category" not in c.calls and "ensure_group" in c.calls


def make_client(handler):
    return DiscourseClient("https://forum.example", "k", transport=httpx.MockTransport(handler))


def test_list_categories_reads_all_pages():
    pages = {"1": [{"id": 1}, {"id": 2, "parent_category_id": 1}], "2": [{"id": 3}], "3": [{"id": 3}]}

    def handler(req):
        assert req.url.path == "/categories.json" and req.url.params["include_subcategories"] == "true"
        return httpx.Response(200, json={"category_list": {"categories": pages.get(req.url.params["page"], [])}})

    assert [c["id"] for c in make_client(handler).list_categories()] == [1, 2, 3]


def test_mute_categories_keeps_existing_ids():
    sent = {}

    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"site_settings": [{"setting": "default_categories_muted", "value": "3|9"}]})
        sent["body"] = req.content.decode()
        return httpx.Response(200, json={})

    make_client(handler).mute_categories_by_default([9, 12])
    assert "default_categories_muted=3%7C9%7C12" in sent["body"] and "update_existing_user=true" in sent["body"]


def test_watch_category_keeps_existing_watched():
    sent = {}

    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"group": {"id": 5, "watching_category_ids": [4, 6]}})
        sent["path"], sent["body"] = req.url.path, req.content.decode()
        return httpx.Response(200, json={})

    make_client(handler).watch_category_for_group("releases-r", 10)
    assert sent["path"] == "/groups/5.json"
    assert sent["body"].count("watching_category_ids") == 3 and "=4" in sent["body"] and "=10" in sent["body"]


# -- workflow builder ---------------------------------------------------------------
def test_release_workflow_shape():
    wf = bwj.wf_release_notify()
    assert [n["type"] for n in wf["nodes"]] == [
        "trigger:webhook", "action:split_out", "flow:loop_over_items", "action:send_personal_message"]
    pm = wf["nodes"][-1]
    assert pm["parameters"]["sender_username"] == "hhf.technoloy"  # the real account name
    c = wf["connections"]
    assert c["Webhook"]["main"][0][0]["node"] == "Split groups"
    assert c["Each group"]["main"][0] == [] and c["Each group"]["main"][1][0]["node"] == "Notify group"
    assert c["Notify group"]["main"][0][0]["node"] == "Each group"


# -- parent / name / tag_prefix ------------------------------------------------------
def test_tag_prefix_filters_and_state_is_keyed_per_entry():
    ios = {**ENTRY, "repo": "o/apple", "tag_prefix": "ios-", "topic_id": 1}
    mac = {**ENTRY, "repo": "o/apple", "tag_prefix": "mac-", "topic_id": 2}
    rows = [rel("mac-2"), rel("ios-2"), rel("ios-1"), rel("mac-1")]
    assert rf.key(ios) == "o/apple#ios-" and rf.key({**ios, "tag_prefix": None}) == "o/apple"
    c, state = FakeClient(), {"last": {"o/apple#ios-": "ios-1", "o/apple#mac-": "mac-1"}}
    assert rf.run([ios, mac], state, c, dry_run=False, fetch=fetcher(rows)) == 2
    assert [p[0] for p in c.posts] == [1, 2] and "ios-2" in c.posts[0][1] and "mac-2" in c.posts[1][1]
    assert state["last"] == {"o/apple#ios-": "ios-2", "o/apple#mac-": "mac-2"}


def test_bootstrap_multiple_parents_and_titles():
    class Multi:
        def __init__(self):
            self.cats, self.topics, self.muted = [], [], None

        def list_categories(self):
            return self.cats

        def create_category(self, name, parent_category_id=None):
            c = {"id": 100 + len(self.cats), "name": name, "parent_category_id": parent_category_id}
            self.cats.append(c)
            return c

        def find_topic_by_title(self, cat_id, title):
            return None

        def create_topic(self, title, category, raw):
            assert category in self.ever_muted, "category must be muted before its topic is created"
            self.topics.append((title, category))
            return {"topic_id": 500 + len(self.topics)}

        def set_topic_status(self, *a):
            pass

        def ensure_group(self, *a):
            pass

        def watch_category_for_group(self, *a):
            pass

        ever_muted: set = set()

        def mute_categories_by_default(self, ids):
            self.muted = ids
            self.ever_muted = self.ever_muted | set(ids)

    c = Multi()
    entries = [{"repo": "a/x", "name": "X", "parent": "P1"}, {"repo": "a/y"},
               {"repo": "a/z", "name": "Zed", "parent": "P1", "tag_prefix": "z-"}]
    rf.bootstrap(entries, c, dry_run=False)
    parents = {x["name"]: x["id"] for x in c.cats if not x["parent_category_id"]}
    assert set(parents) == {"P1", rf.PARENT_NAME}
    subs = {x["name"]: x["parent_category_id"] for x in c.cats if x["parent_category_id"]}
    assert subs == {"X": parents["P1"], "y": parents[rf.PARENT_NAME], "Zed": parents["P1"]}
    assert [t[0] for t in c.topics] == ["a/x releases", "a/y releases", "a/z Zed releases"]
    # a prefix used only to skip moving tags (n8n@) does not repeat the name in the title
    assert rf._title({"repo": "n8n-io/n8n", "name": "n8n", "tag_prefix": "n8n@"}) == "n8n-io/n8n releases"
    assert set(parents.values()) <= set(c.muted) and len(c.muted) == 5


def test_validate_rejects_bad_group_and_duplicate_key(tmp_path):
    for bad in ("Releases-X", "x" * 21, "has space", ""):
        try:
            rf.validate([{"repo": "o/r", "groups": [bad]}])
            raise AssertionError(f"accepted {bad!r}")
        except ValueError as exc:
            assert "group" in str(exc)
    try:
        rf.validate([{"repo": "o/r"}, {"repo": "o/r"}])
        raise AssertionError("duplicate accepted")
    except ValueError as exc:
        assert "duplicate" in str(exc)
    rf.validate([{"repo": "o/r", "tag_prefix": "a"}, {"repo": "o/r", "tag_prefix": "b", "groups": ["releases-ok_1"]}])
    cfg = tmp_path / "c.yml"
    cfg.write_text("releases:\n- {repo: o/r, groups: [BAD]}\n", encoding="utf-8")
    try:
        rf.main(["--dry-run", "--config", str(cfg), "--state", str(tmp_path / "s.json")])
        raise AssertionError("main accepted a bad config")
    except ValueError:
        pass
