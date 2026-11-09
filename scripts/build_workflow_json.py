"""Generate the importable discourse-workflows JSON for the release notification.

    python scripts/build_workflow_json.py --out docs/workflows

The plugin has no file-import button; POST the file to
/admin/plugins/discourse-workflows/workflows.json (node types checked against the forum 2026-11-09).
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
        # one item per group; keep body so the PM can read repo/tag/url from the same item
        node("split", "action:split_out", "Split groups", 240, 0, {
            "field": "body.groups", "include": "all_other_fields", "destination_field_name": "group"}),
        node("loop", "flow:loop_over_items", "Each group", 480, 0, {"batch_size": 1}),
        node("pm", "action:send_personal_message", "Notify group", 720, 120, {
            "recipient_group_names": ["={{ $json.group }}"], "sender_username": "hhf.technoloy",
            "title": "=New release: {{ $json.body.repo }} {{ $json.body.tag }}",
            "raw": "=A new release of **{{ $json.body.repo }}** is out: {{ $json.body.tag }}\n\n{{ $json.body.url }}\n\n"
                   "You get this because you joined @{{ $json.group }}; leave the group to stop."}),
    ]
    # loop port (index 1) -> PM -> back into the loop; done port (index 0) ends
    conns = {"Webhook": link(["Split groups"]), "Split groups": link(["Each group"]),
             "Each group": link([], ["Notify group"]), "Notify group": link(["Each group"])}
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
