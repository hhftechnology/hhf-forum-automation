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
