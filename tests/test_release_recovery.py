import json

import httpx
import pytest

from hhf import release_feed as rf
from hhf.discourse import DiscourseClient, DiscourseError
from hhf.sources import releases
from test_release_feed import ENTRY, FakeClient, fetcher, rel


def test_complete_catchup_and_checkpoint_each_post():
    state = {"last": {"o/r": "v1"}}
    client = FakeClient()
    checkpoints = []
    rf.run([ENTRY], state, client, dry_run=False,
           fetch=fetcher([rel(f"v{i}") for i in range(26, 0, -1)]),
           checkpoint=lambda: checkpoints.append(state["last"]["o/r"]))
    assert len(client.posts) == 25 and checkpoints == [f"v{i}" for i in range(2, 27)] + ["v26"]
    assert rf.run([ENTRY], state, client, dry_run=False, fetch=fetcher([rel("v26")])) == 0


def test_empty_repository_activation_posts_its_first_future_release():
    client, state = FakeClient(), {"last": {}}
    rf.run([ENTRY], state, client, dry_run=False, fetch=fetcher([]))
    assert state["tracking"]["o/r"] == {"seen": []}
    rf.run([ENTRY], state, client, dry_run=False, fetch=fetcher([rel("v1")]))
    assert len(client.posts) == 1


def test_missing_legacy_checkpoint_is_visible_and_does_not_advance():
    client, state = FakeClient(), {"last": {"o/r": "missing"}}
    with pytest.raises(RuntimeError):
        rf.run([ENTRY], state, client, dry_run=False, fetch=fetcher([rel("v2")]))
    assert state["last"]["o/r"] == "missing" and not client.posts


def test_existing_forum_release_repairs_state_without_posting_again():
    client, state = FakeClient(), {"last": {"o/r": "v1"}}
    client.release_urls = lambda topic: {rel("v2")["url"]}
    rf.run([ENTRY], state, client, dry_run=False, fetch=fetcher([rel("v2"), rel("v1")]))
    assert state["last"]["o/r"] == "v2" and not client.posts


def test_source_pages_all_results_and_does_not_expose_token(monkeypatch):
    calls = []
    def get(url, **kwargs):
        calls.append(kwargs["params"]["page"])
        page = calls[-1]
        headers = {"link": '<https://api.github.com/repos/o/r/releases?page=2>; rel="next"'} if page == 1 else {}
        return httpx.Response(200, json=[{"id": page, "tag_name": f"v{page}", "html_url": f"https://github.com/o/r/releases/tag/v{page}"}],
                              headers=headers, request=httpx.Request("GET", url))
    monkeypatch.setattr(releases.httpx, "get", get)
    assert len(releases.latest("o/r")) == 2 and calls == [1, 2]
    monkeypatch.setattr(releases.httpx, "get", lambda url, **kwargs: httpx.Response(500, request=httpx.Request("GET", url)))
    with pytest.raises(releases.ReleaseFetchError, match="unavailable"):
        releases.latest("o/r")


def test_partial_channels_are_not_published(tmp_path):
    path = tmp_path / "channels.json"
    rf._save_channels(path, [{"repo": "o/r", "category_id": 1}, {"repo": "o/s", "category_id": 2, "topic_id": 3}])
    assert [row["repo"] for row in json.loads(path.read_text())["releases"]] == ["o/s"]


def test_large_provisioning_batch_is_bounded_without_side_effects(capsys):
    entries = [{"repo": f"o/r{i}", "app_reference": f"app-{i}"} for i in range(2000)]
    rf.bootstrap(entries, None, dry_run=True)
    assert capsys.readouterr().out.count("would create discussion") == 50
    assert all("topic_id" not in entry for entry in entries)


def test_existing_release_feed_runs_even_when_new_channel_provisioning_fails(tmp_path, monkeypatch):
    config, state, channels = tmp_path / "c.yml", tmp_path / "s.json", tmp_path / "channels.json"
    config.write_text("releases:\n- {repo: o/r, category_id: 1, topic_id: 42}\n")
    state.write_text(json.dumps({"last": {"o/r": "v1"}}))
    client = FakeClient()
    monkeypatch.setattr(rf, "DiscourseClient", lambda: client)
    monkeypatch.setattr(rf, "bootstrap", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("provisioning failed")))
    monkeypatch.setattr(rf.releases, "latest", fetcher([rel("v2"), rel("v1")]))
    with pytest.raises(RuntimeError, match="provisioning failed"):
        rf.main(["--config", str(config), "--state", str(state), "--channels", str(channels)])
    assert len(client.posts) == 1 and json.loads(state.read_text())["last"]["o/r"] == "v2"


def test_first_poll_catches_releases_published_after_channel_activation():
    entry = {**ENTRY, "activated_at": "2026-11-19T10:00:00+00:00"}
    old = {**rel("v1"), "published_at": "2026-11-18T00:00:00+00:00"}
    new = {**rel("v2"), "published_at": "2026-11-19T11:00:00+00:00"}
    client, state = FakeClient(), {"last": {}}
    rf.run([entry], state, client, dry_run=False, fetch=fetcher([new, old]))
    assert len(client.posts) == 1 and "v2" in client.posts[0][1]


def test_2000_channels_resume_in_50_channel_batches(monkeypatch):
    class Client:
        def __init__(self):
            self.categories, self.groups, self.topics, self.watching = [], {}, {}, set()
        def list_categories(self): return list(self.categories)
        def find_category(self, name, parent_category_id): return None
        def get_group(self, name): return self.groups.get(name)
        def upload_file(self, *args, **kwargs): return {"id": 1}
        def ensure_group(self, name, title, **kwargs):
            self.groups[name] = {"id": len(self.groups) + 1}
            return self.groups[name]
        def create_category(self, name, parent_category_id=None, **kwargs):
            row = {"id": len(self.categories) + 1, "name": name, "parent_category_id": parent_category_id}
            self.categories.append(row)
            return row
        def mute_categories_by_default(self, ids): pass
        def find_topic_by_title(self, category_id, title): return self.topics.get((category_id, title))
        def create_topic(self, *, category, title, raw):
            assert (category, title) not in self.topics
            self.topics[(category, title)] = len(self.topics) + 1
            return {"topic_id": self.topics[(category, title)]}
        def set_topic_status(self, *args): pass
        def watch_category_for_group(self, group, category): self.watching.add((group, category))
    monkeypatch.setattr(rf, "_icon_bytes", lambda entry, client: ("icon.png", b"fixture"))
    entries = [{"repo": f"example/app-{i}", "app_reference": f"app-{i}"} for i in range(2000)]
    client = Client()
    for completed in range(50, 2001, 50):
        rf.bootstrap(entries, client, dry_run=False)
        assert sum(bool(entry.get("topic_id")) for entry in entries) == completed
    rf.bootstrap(entries, client, dry_run=False)
    assert len(client.categories) == 2001 and len(client.groups) == 2000
    assert len(client.topics) == 4000 and len(client.watching) == 2000


def test_polling_budget_preserves_a_resumable_cursor():
    client, state = FakeClient(), {"last": {"o/r": "v1"}}
    rf.run([ENTRY], state, client, dry_run=False, budget=0, fetch=fetcher([rel("v2"), rel("v1")]))
    assert state["polling"] == {"next": "o/r", "pending": True} and not client.posts
    rf.run([ENTRY], state, client, dry_run=False, fetch=fetcher([rel("v2"), rel("v1")]))
    assert state["polling"] == {"pending": False} and len(client.posts) == 1


def test_rate_limit_defers_without_advancing_release_state():
    client, state = FakeClient(), {"last": {"o/r": "v1"}}
    def limited(*args, **kwargs): raise releases.ReleaseRateLimit("deferred")
    rf.run([ENTRY], state, client, dry_run=False, fetch=limited)
    assert state["last"]["o/r"] == "v1" and state["polling"]["pending"]
    assert not client.posts


def test_category_discovery_continues_beyond_49_pages():
    def handler(request):
        page = int(request.url.params["page"])
        rows = [{"id": page}] if page <= 75 else []
        return httpx.Response(200, json={"category_list": {"categories": rows}})
    client = DiscourseClient("https://forum.example", "fixture", transport=httpx.MockTransport(handler))
    assert len(client.list_categories()) == 75


def test_retry_recognizes_release_links_after_native_heading_anchors():
    def handler(request):
        if request.url.path == "/t/42.json":
            return httpx.Response(200, json={"post_stream": {"stream": [1]}})
        return httpx.Response(200, json={"post_stream": {"posts": [{"cooked":
            '<h2><a name="heading" href="#heading"></a><strong><a href=\'https://github.com/o/r/releases/tag/v2\'>v2</a></strong></h2>'
            '<p><a href="https://github.com/o/r/releases/tag/mentioned-only">notes</a></p>'}]}})
    client = DiscourseClient("https://forum.example", "fixture", transport=httpx.MockTransport(handler))
    urls = client.release_urls(42)
    assert "https://github.com/o/r/releases/tag/v2" in urls
    assert "https://github.com/o/r/releases/tag/mentioned-only" not in urls


def test_provisioning_and_polling_share_one_job_budget(tmp_path, monkeypatch):
    # A continuation run used to provision for 600s and then poll for another 600s, overrunning the
    # 15-minute job timeout; a timed-out job commits nothing, so every such run was lost.
    config, state, channels = tmp_path / "c.yml", tmp_path / "s.json", tmp_path / "channels.json"
    config.write_text("releases:\n- {repo: o/r, category_id: 1, topic_id: 42}\n")
    state.write_text(json.dumps({"last": {"o/r": "v1"}, "polling": {"next": "o/r", "pending": True}}))
    clock, budgets = [1000.0], {}
    monkeypatch.setattr(rf.time, "monotonic", lambda: clock[0])
    def provision(*args, budget, **kwargs):
        budgets["provision"] = budget
        clock[0] += budget  # provisioning uses its whole share
    def poll(*args, budget, **kwargs):
        budgets["poll"] = budget
        return 0
    monkeypatch.setattr(rf, "DiscourseClient", lambda: FakeClient())
    monkeypatch.setattr(rf, "bootstrap", provision)
    monkeypatch.setattr(rf, "repair_groups", lambda *args, **kwargs: clock.__setitem__(0, clock[0] + 60) or [])
    monkeypatch.setattr(rf, "run", poll)
    rf.main(["--bootstrap", "--continue-poll", "--config", str(config), "--state", str(state), "--channels", str(channels)])
    assert budgets == {"provision": rf.PROVISION_SHARE, "poll": rf.JOB_BUDGET - rf.PROVISION_SHARE - 60}
    assert sum(budgets.values()) + 60 <= rf.JOB_BUDGET < 15 * 60


def test_provision_only_run_keeps_the_full_provisioning_budget(tmp_path, monkeypatch):
    config, state, channels = tmp_path / "c.yml", tmp_path / "s.json", tmp_path / "channels.json"
    config.write_text("releases:\n- {repo: o/r, category_id: 1, topic_id: 42}\n")
    state.write_text(json.dumps({"last": {"o/r": "v1"}}))
    budgets = []
    monkeypatch.setattr(rf, "DiscourseClient", lambda: FakeClient())
    monkeypatch.setattr(rf, "bootstrap", lambda *args, budget, **kwargs: budgets.append(budget))
    monkeypatch.setattr(rf, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no poll")))
    assert rf.main(["--bootstrap", "--continue-poll", "--config", str(config), "--state", str(state), "--channels", str(channels)]) == 0
    assert budgets == [600]


def test_polling_defers_inside_a_repository_and_resumes_without_reposting(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(rf.time, "monotonic", lambda: clock[0])
    client, state = FakeClient(), {"last": {"o/r": "v1"}}
    posts = client.create_post
    def slow_post(*args, **kwargs):
        clock[0] += 100  # each post takes 100s against a 150s budget
        return posts(*args, **kwargs)
    client.create_post = slow_post
    releases_ = fetcher([rel("v4"), rel("v3"), rel("v2"), rel("v1")])
    rf.run([ENTRY], state, client, dry_run=False, budget=150, fetch=releases_)
    assert len(client.posts) == 2 and state["last"]["o/r"] == "v3"
    assert state["polling"] == {"next": "o/r", "pending": True}
    rf.run([ENTRY], state, client, dry_run=False, budget=150, fetch=releases_)
    assert len(client.posts) == 3 and state["last"]["o/r"] == "v4" and state["polling"] == {"pending": False}


def test_forum_deadline_defers_polling_and_keeps_the_cursor():
    from hhf.discourse import DeadlineReached
    entries = [ENTRY, {**ENTRY, "repo": "o/s", "topic_id": 43}]
    client, state = FakeClient(), {"last": {"o/r": "v1", "o/s": "v1"}}
    posts, calls = client.create_post, []
    def limited(topic_id, raw):
        calls.append(topic_id)
        if len(calls) == 2:
            raise DeadlineReached(429, "POST", "/posts.json", "")
        return posts(topic_id, raw)
    client.create_post = limited
    rf.run(entries, state, client, dry_run=False, fetch=fetcher([rel("v3"), rel("v2"), rel("v1")]))
    assert len(client.posts) == 1 and state["last"]["o/r"] == "v2"
    assert state["polling"] == {"next": "o/r", "pending": True}  # not advanced to o/s, not cleared
    client.create_post = posts
    rf.run(entries, state, client, dry_run=False, fetch=fetcher([rel("v3"), rel("v2"), rel("v1")]))
    assert [p[1].count("v3") > 0 for p in client.posts].count(True) == 2  # v3 for o/r, then o/s
    assert state["last"] == {"o/r": "v3", "o/s": "v3"} and len(client.posts) == 4


def test_release_history_scan_stops_at_the_client_deadline(monkeypatch):
    from hhf.discourse import DeadlineReached
    calls = []
    def handler(req):
        calls.append(req.url.path)
        return httpx.Response(200, json={"post_stream": {"stream": list(range(50))}})
    client = DiscourseClient("https://forum.example", "k", transport=httpx.MockTransport(handler))
    monkeypatch.setattr("hhf.discourse.time.monotonic", lambda: 100.0)
    client.deadline = 50.0
    with pytest.raises(DeadlineReached):
        client.release_urls(7)
    assert calls == ["/t/7.json"]


def test_deadline_during_category_discovery_is_not_a_failed_run(tmp_path, monkeypatch):
    from hhf.discourse import DeadlineReached
    config, state, channels = tmp_path / "c.yml", tmp_path / "s.json", tmp_path / "channels.json"
    config.write_text("releases:\n- {repo: o/new, app_reference: new-app}\n")
    state.write_text(json.dumps({"last": {}}))
    class Client(FakeClient):
        def list_categories(self):
            raise DeadlineReached(429, "GET", "/categories.json", "")
    monkeypatch.setattr(rf, "DiscourseClient", Client)
    assert rf.main(["--bootstrap", "--config", str(config), "--state", str(state), "--channels", str(channels)]) == 0


def test_category_left_by_a_timed_out_run_is_found_and_reused(monkeypatch):
    # /categories.json stops listing subcategories once a parent has hundreds, so a category a
    # timed-out run created (but never recorded) is missing from list_categories. Creating it
    # again fails with "Category Name has already been taken".
    class Client:
        def __init__(self):
            self.categories = [{"id": 1, "name": rf.PARENT_NAME, "parent_category_id": None},
                               {"id": 2, "name": "app", "parent_category_id": 1}]
            self.topics, self.created = {}, []
        def list_categories(self): return [c for c in self.categories if not c["parent_category_id"]]
        def find_category(self, name, parent_category_id):
            return next((c for c in self.categories if c["name"] == name and c["parent_category_id"] == parent_category_id), None)
        def get_group(self, name): return {"id": 5}
        def create_category(self, name, **kwargs):
            raise DiscourseError(422, "POST", "/categories.json", '{"errors": ["Category Name has already been taken"]}')
        def mute_categories_by_default(self, ids): pass
        def find_topic_by_title(self, category_id, title): return self.topics.get((category_id, title))
        def create_topic(self, *, category, title, raw):
            self.topics[(category, title)] = len(self.topics) + 10
            return {"topic_id": self.topics[(category, title)]}
        def set_topic_status(self, *args): pass
        def watch_category_for_group(self, group, category): pass
    entry = {"repo": "example/app", "app_reference": "app", "provisioning": True}
    rf.bootstrap([entry], Client(), dry_run=False)
    assert entry["category_id"] == 2 and entry["topic_id"] and entry["discussion_topic_id"]
    other = {"repo": "example/gone", "app_reference": "gone"}  # a real 422 with nothing to reuse still fails
    with pytest.raises(RuntimeError, match="example/gone"):
        rf.bootstrap([other], Client(), dry_run=False)
    assert entry["category_id"] == 2 and entry.get("topic_id") and "provisioning" not in entry


def test_find_category_matches_exact_name_under_the_parent():
    from urllib.parse import parse_qs
    seen = []
    pages = {"1": [{"id": 3, "name": "Mumble Server", "parent_category_id": 129},
                   {"id": 4, "name": "Mumble", "parent_category_id": 7}],
             "2": [{"id": 5, "name": "Mumble", "parent_category_id": 129}]}
    def handler(req):
        form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
        seen.append((req.method, req.url.path, form))
        return httpx.Response(200, json={"categories": pages.get(form["page"], [])})
    client = DiscourseClient("https://forum.example", "k", transport=httpx.MockTransport(handler))
    assert client.find_category("Mumble", 129)["id"] == 5  # exact match on the second page
    method, path, form = seen[0]
    assert (method, path) == ("POST", "/categories/search.json")
    assert form["term"] == "Mumble" and form["parent_category_id"] == "129"
    seen.clear()
    assert client.find_category("Other", 129) is None and len(seen) == 3  # stops at an empty page


def test_find_topic_by_title_accepts_discourse_capitalisation():
    topics = [{"id": 6776, "title": "Mumble-voip/mumble releases"}, {"id": 6777, "title": "Mumble-voip/mumble discussion"}]
    client = DiscourseClient("https://forum.example", "k", transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={"topic_list": {"topics": topics}})))
    assert client.find_topic_by_title(747, "mumble-voip/mumble releases") == 6776
    assert client.find_topic_by_title(747, "mumble-voip/mumble discussion") == 6777
    topics.append({"id": 9, "title": "MUMBLE-VOIP/MUMBLE RELEASES"})  # ambiguous: no guess
    assert client.find_topic_by_title(747, "mumble-voip/mumble releases") is None
