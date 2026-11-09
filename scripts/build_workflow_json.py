"""Generate the importable discourse-workflows JSON for the release notification.

    python scripts/build_workflow_json.py --out docs/workflows

The plugin has no file-import button; POST the file to
/admin/plugins/discourse-workflows/workflows.json. Verify the loop node type id and its
parameter names against the plugin before import.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def node(id_, type_, name, x, y, params, version="1.0"):
    return {"id": id_, "type": type_, "typeVersion": version, "name": name, "parameters": params,
            "credentials": {}, "webhookId": None, "position": {"x": x, "y": y}}


def link(*targets):
    return {"main": [[{"node": t, "type": "main", "index": 0} for t in port] for port in targets]}


def wf_release_notify() -> dict:
    nodes = [
        node("webhook", "trigger:webhook", "Webhook", 0, 0, {
            "path": "hhf-release", "http_method": "POST", "authentication": "bearer_auth",
            "response_mode": "on_received", "response_code": "200"}),
        node("loop", "flow:loop_over_items", "Each group", 240, 0, {"items": "={{ $json.body.groups }}"}),
        node("pm", "action:send_personal_message", "Notify group", 480, 0, {
            "recipient_group_names": ["={{ $json }}"], "sender_username": "hhf.technology",
            "title": "={{ \"New release: \" + $(\"Webhook\").item.json.body.repo + \" \" + $(\"Webhook\").item.json.body.tag }}",
            "raw": "=A new release of {{ $(\"Webhook\").item.json.body.repo }} is out: {{ $(\"Webhook\").item.json.body.tag }}\n\n{{ $(\"Webhook\").item.json.body.url }}"}),
    ]
    conns = {"Webhook": link(["Each group"]), "Each group": link(["Notify group"])}
    return {"name": "HHF: release notify",
            "description": "Receives a release webhook and DMs each opt-in group.",
            "nodes": nodes, "connections": conns}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("docs/workflows"))
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    path = a.out / "4-release-notify.json"
    path.write_text(json.dumps(wf_release_notify(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", path)


if __name__ == "__main__":
    main()
