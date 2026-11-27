"""The forum origin sometimes stalls past the client timeout (run 149: ReadTimeout on /t/<id>.json).
A stalled call is retried, then skipped, and never crashes the whole release run."""

import httpx
import pytest

from hhf import release_feed as rf
from hhf.discourse import DeadlineReached, DiscourseClient, ForumUnavailable
from test_release_feed import ENTRY, FakeClient, GroupRepairClient, fetcher, rel


def client_for(handler, **kw):
    slept = []
    c = DiscourseClient("https://forum.example", "k", sleep=slept.append, transport=httpx.MockTransport(handler), **kw)
    return c, slept


def test_read_timeout_on_a_get_is_retried_then_answers():
    calls = []

    def handler(req):
        calls.append(req.url.path)
        if len(calls) < 3:
            raise httpx.ReadTimeout("The read operation timed out", request=req)
        return httpx.Response(200, json={"ok": True})

    c, slept = client_for(handler)
    assert c.request("GET", "/t/5553.json") == {"ok": True}
    assert len(calls) == 3 and slept == [5.0, 10.0]


def test_get_that_keeps_timing_out_raises_forum_unavailable_without_the_key():
    def handler(req):
        raise httpx.ReadTimeout("The read operation timed out", request=req)

    slept = []
    c = DiscourseClient("https://forum.example", "SECRETKEY", sleep=slept.append, transport=httpx.MockTransport(handler))
    with pytest.raises(ForumUnavailable) as err:
        c.request("GET", "/t/5553.json")
    assert isinstance(err.value, RuntimeError) and err.value.status == 0
    assert "ReadTimeout" in str(err.value) and "SECRETKEY" not in str(err.value) + repr(err.value)
    assert len(slept) == c.transport_retries


def test_post_that_timed_out_is_not_resent():
    calls = []

    def handler(req):
        calls.append(req.method)
        raise httpx.ReadTimeout("The read operation timed out", request=req)

    c, slept = client_for(handler)
    with pytest.raises(ForumUnavailable):
        c.create_post(42, "body")
    assert calls == ["POST"] and slept == []  # the post may exist; release_urls reconciles it next run


def test_post_that_never_connected_is_retried():
    calls = []

    def handler(req):
        calls.append(req.method)
        if len(calls) == 1:
            raise httpx.ConnectError("connection refused", request=req)
        return httpx.Response(200, json={"id": 1})

    c, _ = client_for(handler)
    assert c.create_post(42, "body") == {"id": 1} and calls == ["POST", "POST"]


def test_transport_retry_that_would_pass_the_deadline_defers(monkeypatch):
    def handler(req):
        raise httpx.ReadTimeout("The read operation timed out", request=req)

    c, slept = client_for(handler)
    monkeypatch.setattr("hhf.discourse.time.monotonic", lambda: 100.0)
    c.deadline = 120.0  # 5s backoff + 30s timeout would pass it
    with pytest.raises(DeadlineReached):
        c.request("GET", "/t/1.json")
    assert slept == []


def test_run_skips_a_repository_whose_topic_does_not_answer_and_polls_the_rest():
    entries = [ENTRY, {**ENTRY, "repo": "o/s", "topic_id": 43}]
    client, state = FakeClient(), {"last": {"o/r": "v1", "o/s": "v1"}}

    def urls(topic_id):
        if topic_id == ENTRY["topic_id"]:
            raise ForumUnavailable(0, "GET", f"/t/{topic_id}.json", "no answer from the forum (ReadTimeout)")
        return set()

    client.release_urls = urls
    with pytest.raises(RuntimeError, match="o/r"):  # still red, after the other repositories ran
        rf.run(entries, state, client, dry_run=False, fetch=fetcher([rel("v2"), rel("v1")]))
    assert [p[0] for p in client.posts] == [43]
    assert state["last"] == {"o/r": "v1", "o/s": "v2"} and state["polling"] == {"pending": False}
    assert "v2" not in state["tracking"]["o/r"]["seen"]  # unposted, so the next cycle posts it


def test_run_stops_when_the_forum_is_down_and_resumes_there():
    entries = [{**ENTRY, "repo": f"o/{n}", "topic_id": 40 + i} for i, n in enumerate("abcde")]
    client, state = FakeClient(), {"last": {e["repo"]: "v1" for e in entries}}
    asked = []

    def down(topic_id):
        asked.append(topic_id)
        raise ForumUnavailable(0, "GET", f"/t/{topic_id}.json", "no answer from the forum (ReadTimeout)")

    client.release_urls = down
    with pytest.raises(RuntimeError):
        rf.run(entries, state, client, dry_run=False, fetch=fetcher([rel("v2"), rel("v1")]))
    assert asked == [40, 41, 42] and state["polling"] == {"next": "o/c", "pending": True}


def test_repair_makes_groups_messageable_by_admins():
    client = GroupRepairClient([
        {"id": 1, "name": "releases-a", "full_name": "A releases", "flair_url": "x", "messageable_level": 0},
        {"id": 2, "name": "releases-b", "full_name": "B releases", "flair_url": "x", "messageable_level": 1},
    ])
    entries = [{"repo": "o/a", "name": "A", "groups": ["releases-a"], "topic_id": 5},
               {"repo": "o/b", "name": "B", "groups": ["releases-b"], "topic_id": 6}]
    assert rf.repair_groups(entries, client, dry_run=False) == []
    assert client.updates == [(1, {"messageable_level": 1})]


def test_new_groups_are_created_messageable_by_admins():
    sent = {}

    def handler(req):
        if req.method == "GET":
            return httpx.Response(404, json={})
        sent.update(dict(httpx.QueryParams(req.content.decode())))
        return httpx.Response(200, json={"basic_group": {"id": 5}})

    c, _ = client_for(handler)
    c.ensure_group("releases-x", "X releases")
    assert sent["group[messageable_level]"] == "1"
