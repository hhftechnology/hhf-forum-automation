import json

from hhf import release_feed as rf


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
