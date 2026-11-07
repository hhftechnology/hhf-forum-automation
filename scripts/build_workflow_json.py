"""Generate importable discourse-workflows JSON (same shape as the plugin's config/templates/*.json).

    python scripts/build_workflow_json.py --advisory-category 120 --briefing-category 121 \
        --repo OWNER/REPO --out docs/workflows

The plugin has no file-import button; POST the files to
/admin/plugins/discourse-workflows/workflows.json (see docs/forum-workflows.md).
Credentials are instance-specific, so attach them in the editor after import.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def node(id_, type_, name, x, y, params, version="1.0"):
    return {"id": id_, "type": type_, "typeVersion": version, "name": name, "parameters": params,
            "credentials": {}, "webhookId": None, "position": {"x": x, "y": y}}


_n = [0]


def cond(left, op, right, typ="string"):
    _n[0] += 1
    return {"id": f"cond-{_n[0]:03d}", "operator": {"type": typ, "operation": op, "singleValue": False},
            "leftValue": left, "rightValue": right}


def link(*targets):
    return {"main": [[{"node": t, "type": "main", "index": 0} for t in port] for port in targets]}


def wf_drafts(adv_cat: int, brief_cat: int, staff_group: str) -> dict:
    nodes = [
        node("webhook", "trigger:webhook", "Webhook", 0, 0, {
            "path": "hhf-drafts", "http_method": "POST", "authentication": "bearer_auth",
            "response_mode": "on_received", "response_code": "200"}),
        node("if-weekly", "condition:if", "Is weekly advisory", 240, 0, {
            "combinator": "and", "conditions": [cond("={{ $json.body.kind }}", "equals", "weekly_advisory")]}),
        node("if-daily", "condition:if", "Is daily briefing", 480, 120, {
            "combinator": "and", "conditions": [cond("={{ $json.body.kind }}", "equals", "daily_briefing")]}),
        node("create-advisory", "action:topic", "Create advisory draft", 480, -120, {
            "operation": "create", "title": "={{ $json.body.title }}", "raw": "={{ $json.body.raw }}",
            "category_id": adv_cat, "actor_username": "system"}, "2.0"),
        node("create-briefing", "action:topic", "Create briefing draft", 720, 120, {
            "operation": "create", "title": "={{ $json.body.title }}", "raw": "={{ $json.body.raw }}",
            "category_id": brief_cat, "actor_username": "system"}, "2.0"),
        node("tags", "action:topic_tags", "Topic tags", 960, 0, {
            "mode": "modify", "topic_id": "={{ $json.topic.id }}",
            "add_tag_names": "={{ $(\"Webhook\").item.json.body.tags }}", "actor_username": "system"}, "2.0"),
        node("pm", "action:send_personal_message", "Notify staff", 1200, 0, {
            "recipient_group_names": [staff_group], "sender_username": "system",
            "title": "={{ \"Draft ready for review: \" + $(\"Webhook\").item.json.body.title }}",
            "raw": "=A new draft was created from the {{ $(\"Webhook\").item.json.body.kind }} automation (external id {{ $(\"Webhook\").item.json.body.external_id }}).\n\nTopic: /t/{{ $json.topic_id }}\n\nReview it, edit if needed, then publish it: weekly advisories go to Security Advisory (86), daily briefings are published from the blog editor."}),
    ]
    conns = {
        "Webhook": link(["Is weekly advisory"]),
        "Is weekly advisory": link(["Create advisory draft"], ["Is daily briefing"]),
        "Is daily briefing": link(["Create briefing draft"], []),
        "Create advisory draft": link(["Topic tags"]),
        "Create briefing draft": link(["Topic tags"]),
        "Topic tags": link(["Notify staff"]),
    }
    return {"name": "HHF: automation drafts to review queue",
            "description": "Receives weekly advisory / daily briefing JSON, creates a draft topic, tags it and PMs staff.",
            "nodes": nodes, "connections": conns}


def wf_announce(src_cat: int, news_cat: int) -> dict:
    nodes = [
        node("moved", "trigger:topic_category_changed", "Topic moved", 0, 0, {}),
        node("check", "condition:if", "Moved into source category", 240, 0, {
            "combinator": "and", "conditions": [cond("={{ $json.topic.category_id }}", "equals", str(src_cat), "number")]}),
        node("published", "trigger:topic_published", "Topic published", 0, 160, {"category_ids": [src_cat]}),
        node("announce", "action:topic", "Announce in News", 480, 80, {
            "operation": "create", "title": "={{ \"New: \" + $json.topic.title }}",
            "raw": "=A new post is available: [{{ $json.topic.title }}]({{ $json.topic.url }})",
            "category_id": news_cat, "actor_username": "system"}, "2.0"),
    ]
    conns = {"Topic moved": link(["Moved into source category"]),
             "Moved into source category": link(["Announce in News"], []),
             "Topic published": link(["Announce in News"])}
    return {"name": "HHF: announce published automation posts", "description": "Posts an announcement in News when a draft reaches the published category.",
            "nodes": nodes, "connections": conns}


def wf_monitor(repo: str, staff_group: str) -> dict:
    hdr = {"values": [{"key": "Accept", "value": "application/vnd.github+json"},
                      {"key": "X-GitHub-Api-Version", "value": "2022-11-28"}]}
    def failed(_name):
        return [cond("={{ $json.workflow_runs[0].conclusion }}", "equals", v) for v in ("failure", "timed_out", "cancelled")]

    def http(id_, name, wf_file, y):
        return node(id_, "action:http_request", name, 260, y, {
            "method": "GET", "url": f"https://api.github.com/repos/{repo}/actions/workflows/{wf_file}/runs?per_page=1",
            "authentication": "none", "headers": hdr, "never_error": True})
    def chk(id_, name, y):
        return node(id_, "condition:if", name, 520, y, {"combinator": "or", "conditions": failed(name)})
    def pm(id_, name, label, y):
        return node(id_, "action:send_personal_message", name, 780, y, {
            "recipient_group_names": [staff_group], "sender_username": "system",
            "title": f"Automation failed: {label}",
            "raw": f"=The latest run of the {label} workflow ended with `{{{{ $json.workflow_runs[0].conclusion }}}}`.\n\nRun: {{{{ $json.workflow_runs[0].html_url }}}}"})
    nodes = [
        node("schedule", "trigger:schedule", "Daily 07:00", 0, 60, {"rule": {"interval": [
            {"field": "days", "daysInterval": 1, "triggerAtHour": 7, "triggerAtMinute": 0}]}}),
        http("http-weekly", "Latest weekly-advisory run", "weekly-advisory.yml", 0),
        http("http-daily", "Latest daily-briefing run", "daily-briefing.yml", 120),
        chk("if-weekly", "Weekly failed?", 0), chk("if-daily", "Daily failed?", 120),
        pm("pm-weekly", "PM staff: weekly", "weekly-advisory", 0), pm("pm-daily", "PM staff: daily", "daily-briefing", 120),
    ]
    conns = {"Daily 07:00": link(["Latest weekly-advisory run", "Latest daily-briefing run"]),
             "Latest weekly-advisory run": link(["Weekly failed?"]), "Latest daily-briefing run": link(["Daily failed?"]),
             "Weekly failed?": link(["PM staff: weekly"], []), "Daily failed?": link(["PM staff: daily"], [])}
    return {"name": "HHF: monitor automation runs", "description": "Checks the last GitHub Actions runs daily and PMs staff on failure.",
            "nodes": nodes, "connections": conns}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--advisory-category", type=int, default=0)
    ap.add_argument("--briefing-category", type=int, default=0)
    ap.add_argument("--source-category", type=int, default=86)
    ap.add_argument("--news-category", type=int, default=87)
    ap.add_argument("--repo", default="OWNER/hhf-forum-automation")
    ap.add_argument("--staff-group", default="staff")
    ap.add_argument("--out", type=Path, default=Path("docs/workflows"))
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    for fname, wf in {
        "1-drafts.json": wf_drafts(a.advisory_category, a.briefing_category, a.staff_group),
        "2-announce.json": wf_announce(a.source_category, a.news_category),
        "3-monitor.json": wf_monitor(a.repo, a.staff_group),
    }.items():
        (a.out / fname).write_text(json.dumps(wf, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("wrote", a.out / fname)


if __name__ == "__main__":
    main()
