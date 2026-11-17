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


def release_payload_validator() -> str:
    return """var items = $input.all();
if (items.length !== 1) throw new Error("Expected one release webhook item");
var payload = items[0].json && items[0].json.body;
if (!payload || payload.kind !== "release") throw new Error("Invalid release payload");
if (typeof payload.repo !== "string" || !/^[A-Za-z0-9-]{1,39}\\/[A-Za-z0-9_.-]{1,100}$/.test(payload.repo)) throw new Error("Invalid repository");
if (typeof payload.tag !== "string" || payload.tag.length < 1 || payload.tag.length > 200 || /[\\x00-\\x1f\\x7f]/.test(payload.tag)) throw new Error("Invalid release tag");
var base = "https://forum.hhf.technology";
if (typeof payload.url !== "string" || payload.url.indexOf(base + "/t/") !== 0) throw new Error("Release link must be forum-local");
var parts = payload.url.slice((base + "/t/").length).split("/");
if (parts.length !== 3 || !parts[0] || parts[0].length > 200 || /[\\x00-\\x20\\x7f?#]/.test(parts[0]) ||
    !/^[0-9]{1,12}$/.test(parts[1]) || !/^[0-9]{1,12}$/.test(parts[2]) || Number(parts[1]) < 1 || Number(parts[2]) < 1) {
  throw new Error("Invalid forum release link");
}
if (!Array.isArray(payload.groups) || payload.groups.length < 1 || payload.groups.length > 20) throw new Error("Invalid release groups");
var groups = [];
payload.groups.forEach(function(group) {
  if (typeof group !== "string" || !/^[a-z0-9_-]{1,20}$/.test(group) || groups.indexOf(group) !== -1) throw new Error("Invalid release group");
  groups.push(group);
});
return [{ json: { body: { repo: payload.repo, tag: payload.tag, url: payload.url, groups: groups } } }];"""


def wf_release_notify() -> dict:
    nodes = [
        node("webhook", "trigger:webhook", "Webhook", 0, 0, {
            "path": "hhf-release", "http_method": "POST", "authentication": "bearer_auth",
            "response_mode": "on_received", "response_code": "200",
            "response_body": "Accepted; validation and delivery run asynchronously."}),
        node("validate", "action:code", "Validate release payload", 240, 0, {
            "mode": "runOnceForAllItems", "code": release_payload_validator()}),
        # one item per group; keep body so the PM can read repo/tag/url from the same item
        node("split", "action:split_out", "Split groups", 480, 0, {
            "field": "body.groups", "include": "all_other_fields", "destination_field_name": "group"}),
        node("loop", "flow:loop_over_items", "Each group", 720, 0, {"batch_size": 1}),
        node("pm", "action:send_personal_message", "Notify group", 960, 120, {
            "recipient_group_names": ["={{ $json.group }}"], "sender_username": "hhf.technoloy",
            "title": "=New release: {{ $json.body.repo }} {{ $json.body.tag }}",
            "raw": "=A new release of **{{ $json.body.repo }}** is out: {{ $json.body.tag }}\n\n{{ $json.body.url }}\n\n"
                   "You get this because you joined @{{ $json.group }}. To stop, leave the group "
                   "and set the release subcategory's bell back to Normal."}),
    ]
    # loop port (index 1) -> PM -> back into the loop; done port (index 0) ends
    conns = {"Webhook": link(["Validate release payload"]), "Validate release payload": link(["Split groups"]),
             "Split groups": link(["Each group"]),
             "Each group": link([], ["Notify group"]), "Notify group": link(["Each group"])}
    return {"name": "HHF: release notify",
            "description": "Validates a release webhook and DMs each opt-in group. HTTP 200 acknowledges receipt only.",
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
