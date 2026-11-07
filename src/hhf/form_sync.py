"""Edit the HHF onboarding questionnaire (W16 form trigger) and the existing-member PM text (W19)
from GitHub: ``forms/onboarding.yml`` is the source of truth.

    python -m hhf.form_sync                      # validate, GET live workflows, print a diff
    python -m hhf.form_sync --validate-only      # no network
    FORM_SYNC_CONFIRM=yes python -m hhf.form_sync --apply

``--apply`` saves a DRAFT only (PUT /workflows/:id with nodes+connections). It never publishes: a human
publishes in the admin UI. Only the form node's ``parameters`` (W16) and the ``var TITLE``/``var BODY`` lines
of the Candidates code node (W19) are replaced; everything else is sent back exactly as fetched.
"""
from __future__ import annotations

import argparse
import copy
import difflib
import json
import os
import re
import sys
from pathlib import Path

import yaml

from hhf.discourse import DiscourseClient

FIELD_TYPES = {"text", "textarea", "number", "email", "password", "date", "checkbox", "dropdown", "radio",
               "hiddenField", "html"}
NAME_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
SECTION_RE = re.compile(r"<h3>(.*?)</h3>(?:<p>(.*?)</p>)?\Z", re.S)
# no URLs, emails, IPs or key-looking tokens in anything shown to members
SUSPECT_RE = re.compile(
    r"https?://|www\.|\b[\w.+-]+@[\w-]+\.\w+|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:sk|ghp|gho|xox[bp]|AKIA)[-_A-Za-z0-9]{12,}",
    re.I,
)
WF_PATH = "/admin/plugins/discourse-workflows/workflows/{}.json"


class FormSyncError(ValueError):
    pass


# -- YAML <-> W16 parameters -------------------------------------------------
def load(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _texts(item: dict):
    for k in ("section", "note", "html", "label", "description", "placeholder"):
        if item.get(k):
            yield k, item[k]
    for o in item.get("options") or []:
        yield "option", o


def validate(cfg: dict) -> None:
    errs: list[str] = []
    for k in ("title", "description", "items", "workflow", "pm"):
        if not cfg.get(k):
            errs.append(f"missing top-level key {k!r}")
    for k in ("id", "node_id", "uuid", "response_mode", "authentication"):
        if not (cfg.get("workflow") or {}).get(k):
            errs.append(f"workflow.{k} missing")
    for k in ("workflow_id", "node_name", "title", "body"):
        if not (cfg.get("pm") or {}).get(k):
            errs.append(f"pm.{k} missing")
    seen: set[str] = set()
    for i, it in enumerate(cfg.get("items") or []):
        name = it.get("name")
        where = f"items[{i}] ({name})"
        if not isinstance(name, str) or not NAME_RE.match(name):
            errs.append(f"{where}: name must match [a-z][a-z0-9_]*")
        elif name in seen:
            errs.append(f"{where}: duplicate name")
        seen.add(str(name))
        if "section" in it:
            kind = "section"
        elif "html" in it:
            kind = "html"
        else:
            kind = it.get("type")
            if kind not in FIELD_TYPES or kind == "html":
                errs.append(f"{where}: unknown type {kind!r}")
            if not it.get("label"):
                errs.append(f"{where}: label required")
            opts = it.get("options") or []
            if kind in ("radio", "dropdown"):
                if not opts or len(set(opts)) != len(opts) or not all(isinstance(o, str) and o for o in opts):
                    errs.append(f"{where}: {kind} needs unique non-empty string options")
            elif opts:
                errs.append(f"{where}: options only allowed for radio/dropdown")
        for k, text in _texts(it):
            if not isinstance(text, str):
                errs.append(f"{where}: {k} must be a string")
            elif SUSPECT_RE.search(text):
                errs.append(f"{where}: {k} looks like a URL, email, IP or secret")
    pm = cfg.get("pm") or {}
    body = pm.get("body") or ""
    if "{{USERNAME}}" not in body:
        errs.append("pm.body must contain {{USERNAME}}")
    if "/workflows/form/" + str((cfg.get("workflow") or {}).get("uuid")) not in body:
        errs.append("pm.body must link to the form uuid (/workflows/form/<uuid>)")
    if errs:
        raise FormSyncError("; ".join(errs))


def _field(it: dict) -> dict:
    if "section" in it:
        html = f"<h3>{it['section']}</h3>" + (f"<p>{it['note']}</p>" if it.get("note") else "")
        return {"html": html, "field_name": it["name"], "field_type": "html", "field_label": it["name"]}
    if "html" in it:
        return {"html": it["html"], "field_name": it["name"], "field_type": "html", "field_label": it["name"]}
    f = {"field_name": it["name"], "field_type": it["type"], "field_label": it["label"]}
    if it.get("required"):
        f["required"] = True
    if it.get("options"):
        f["options"] = {"values": [{"value": o} for o in it["options"]]}
    for k in ("description", "placeholder"):
        if it.get(k):
            f[k] = it[k]
    if it["type"] == "checkbox":
        f["default_value"] = "false"
    return f


def to_params(cfg: dict) -> dict:
    """Exact W16 trigger:form ``parameters``."""
    wf = cfg["workflow"]
    return {
        "form_title": cfg["title"],
        "form_description": cfg["description"],
        "response_mode": wf["response_mode"],
        "authentication": wf["authentication"],
        "form_fields": {"values": [_field(it) for it in cfg["items"]]},
    }


def _item(f: dict) -> dict:
    name, typ = f["field_name"], f["field_type"]
    if typ == "html":
        m = SECTION_RE.match(f["html"])
        if m:
            return {"name": name, "section": m[1], **({"note": m[2]} if m[2] else {})}
        return {"name": name, "html": f["html"]}
    it = {"name": name, "type": typ, "label": f["field_label"]}
    if f.get("required"):
        it["required"] = True
    if "options" in f:
        it["options"] = [o["value"] for o in f["options"]["values"]]
    for k in ("description", "placeholder"):
        if k in f:
            it[k] = f[k]
    return it


def from_baseline(baseline: dict) -> dict:
    """Build the YAML structure from the captured baseline (one-off bootstrap and round-trip test)."""
    w16, w19, p = baseline["w16"], baseline["w19"], baseline["w16"]["form_parameters"]
    return {
        "title": p["form_title"],
        "description": p["form_description"],
        "workflow": {"id": w16["workflow_id"], "node_id": w16["form_node_id"], "uuid": w16["form_uuid"],
                     "response_mode": p["response_mode"], "authentication": p["authentication"]},
        "items": [_item(f) for f in p["form_fields"]["values"]],
        "pm": {"workflow_id": w19["workflow_id"], "node_name": w19["candidates_node_name"],
               "title": w19["pm_title"], "body": w19["pm_body"]},
    }


# -- applying to a fetched workflow ------------------------------------------
def _node(wf: dict, *, node_id: str | None = None, name: str | None = None) -> dict:
    hits = [n for n in wf["nodes"] if (n.get("id") == node_id if node_id else n.get("name") == name)]
    if len(hits) != 1:
        raise FormSyncError(f"expected exactly one node {node_id or name!r}, found {len(hits)}")
    return hits[0]


def apply_form(wf: dict, cfg: dict, *, allow_removed: bool = False) -> dict:
    """New workflow dict with ONLY the form trigger node's parameters replaced."""
    validate(cfg)
    out = copy.deepcopy(wf)
    node = _node(out, node_id=cfg["workflow"]["node_id"])
    if node.get("type") != "trigger:form":
        raise FormSyncError(f"node {node['id']} is {node.get('type')!r}, not trigger:form")
    live = {f["field_name"] for f in node["parameters"]["form_fields"]["values"] if f["field_type"] != "html"}
    gone = sorted(live - {it["name"] for it in cfg["items"]})
    if gone and not allow_removed:
        raise FormSyncError(
            f"field_name(s) live but missing from YAML (W16 code may read them): {', '.join(gone)}; "
            "pass --allow-removed after updating W16 code nodes")
    node["parameters"] = to_params(cfg)
    return out


def _js_line(var: str, value: str) -> tuple[re.Pattern, str]:
    return re.compile(rf"^([ \t]*)var {var} = .*;[ \t]*$", re.M), f"var {var} = {json.dumps(value, ensure_ascii=False)};"


def apply_pm(wf: dict, cfg: dict) -> dict:
    """New workflow dict with ONLY the TITLE/BODY lines of the Candidates code replaced."""
    validate(cfg)
    out = copy.deepcopy(wf)
    node = _node(out, name=cfg["pm"]["node_name"])
    code = node["parameters"]["code"]
    for var, key in (("TITLE", "title"), ("BODY", "body")):
        pat, line = _js_line(var, cfg["pm"][key])
        if len(pat.findall(code)) != 1:
            raise FormSyncError(f"expected exactly one `var {var} = ...;` line in {node['name']}")
        code = pat.sub(lambda m: m[1] + line, code)
    node["parameters"]["code"] = code
    return out


def read_pm(code: str) -> dict:
    """TITLE/BODY currently in the code node (inverse of apply_pm)."""
    def get(var):
        m = re.search(rf"^[ \t]*var {var} = (.*);[ \t]*$", code, re.M)
        return json.loads(m[1])
    return {"title": get("TITLE"), "body": get("BODY")}


# -- diff / apply against the live forum --------------------------------------
def _view(wf: dict, cfg: dict, kind: str) -> str:
    if kind == "form":
        n = _node(wf, node_id=cfg["workflow"]["node_id"])
        return json.dumps(n["parameters"], indent=2, ensure_ascii=False, sort_keys=True)
    n = _node(wf, name=cfg["pm"]["node_name"])
    return "\n".join(l.strip() for l in n["parameters"]["code"].splitlines() if re.match(r"\s*var (TITLE|BODY) =", l))


def diff_text(before: dict, after: dict, cfg: dict, kind: str) -> str:
    a, b = _view(before, cfg, kind).splitlines(), _view(after, cfg, kind).splitlines()
    return "\n".join(difflib.unified_diff(a, b, f"live/{kind}", f"yaml/{kind}", lineterm="", n=2))


def fetch(client: DiscourseClient, wid: int) -> dict:
    return client.request("GET", WF_PATH.format(wid))["workflow"]


def save_draft(client: DiscourseClient, wid: int, wf: dict) -> dict:
    """PUT nodes+connections: creates a new (unpublished) version. Never sends ``published``."""
    body = {"workflow": {"nodes": wf["nodes"], "connections": wf["connections"]}}
    return client.request("PUT", WF_PATH.format(wid), json=body)["workflow"]


def main(argv: list[str] | None = None, client: DiscourseClient | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default="forms/onboarding.yml")
    ap.add_argument("--validate-only", action="store_true")
    ap.add_argument("--apply", action="store_true", help="save drafts (also needs FORM_SYNC_CONFIRM=yes)")
    ap.add_argument("--allow-removed", action="store_true")
    args = ap.parse_args(argv)

    cfg = load(args.file)
    validate(cfg)
    print(f"{args.file}: valid ({len(cfg['items'])} items)")
    if args.validate_only:
        return 0
    if args.apply and os.environ.get("FORM_SYNC_CONFIRM") != "yes":
        print("refusing to apply: set FORM_SYNC_CONFIRM=yes", file=sys.stderr)
        return 2

    client = client or DiscourseClient()
    jobs = [("form", cfg["workflow"]["id"], lambda w: apply_form(w, cfg, allow_removed=args.allow_removed)),
            ("pm", cfg["pm"]["workflow_id"], lambda w: apply_pm(w, cfg))]
    plan = []
    for kind, wid, fn in jobs:  # compute everything first so a refusal aborts before any write
        live = fetch(client, wid)
        new = fn(live)
        d = diff_text(live, new, cfg, kind)
        print(f"== {kind} (workflow {wid}) ==\n{d or 'no changes'}")
        if d:
            plan.append((kind, wid, new))
    if args.apply:
        for kind, wid, new in plan:
            res = save_draft(client, wid, new)
            print(f"{kind}: draft saved, version_id={res.get('version_id')} "
                  f"has_unpublished_changes={res.get('has_unpublished_changes')} (publish in the admin UI)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
