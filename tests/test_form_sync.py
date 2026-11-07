import copy
import json
from pathlib import Path

import httpx
import pytest
import yaml

from hhf import form_sync as fs
from hhf.discourse import DiscourseClient

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads((ROOT / "tests/fixtures/w16_w19_baseline.json").read_text(encoding="utf-8"))
CFG = fs.load(ROOT / "forms/onboarding.yml")


def w16():
    return {"id": "38", "name": "W16", "connections": {"a": 1}, "version_id": "v1", "nodes": [
        {"id": "other", "type": "action:x", "name": "Other", "parameters": {"k": 1}},
        {"id": CFG["workflow"]["node_id"], "type": "trigger:form", "name": "Form", "webhookId": CFG["workflow"]["uuid"],
         "parameters": copy.deepcopy(BASE["w16"]["form_parameters"])}]}


def w19(title="old", body="old"):
    code = f'// keep\nvar BASE = "x";\n  var TITLE = {json.dumps(title)};\nvar BODY = {json.dumps(body)};\nreturn [];'
    return {"id": "41", "connections": {}, "nodes": [
        {"id": "c", "type": "action:code", "name": "Candidates", "parameters": {"code": code, "other": 1}},
        {"id": "z", "type": "action:y", "name": "Z", "parameters": {}}]}


def test_yaml_matches_baseline_exactly():
    assert fs.to_params(CFG) == BASE["w16"]["form_parameters"]
    assert fs.from_baseline(BASE) == CFG
    fs.validate(CFG)


def test_apply_form_changes_only_target_node():
    wf = w16()
    cfg = copy.deepcopy(CFG)
    cfg["items"][1]["options"][0] = "Changed"
    cfg["title"] = "New title"
    out = fs.apply_form(wf, cfg)
    assert out["nodes"][0] == wf["nodes"][0] and out["connections"] == wf["connections"]
    assert out["nodes"][1]["webhookId"] == wf["nodes"][1]["webhookId"]
    assert out["nodes"][1]["parameters"] == fs.to_params(cfg)
    assert wf == w16()  # input untouched


def test_missing_live_field_refused_unless_allowed():
    cfg = copy.deepcopy(CFG)
    cfg["items"] = [i for i in cfg["items"] if i["name"] != "s_pangolin"]
    with pytest.raises(fs.FormSyncError, match="s_pangolin"):
        fs.apply_form(w16(), cfg)
    out = fs.apply_form(w16(), cfg, allow_removed=True)
    assert "s_pangolin" not in json.dumps(out["nodes"][1]["parameters"])


@pytest.mark.parametrize("mutate,msg", [
    (lambda c: c["items"].append(dict(c["items"][1])), "duplicate"),
    (lambda c: c["items"][1].update(type="bogus"), "unknown type"),
    (lambda c: c["items"][1].update(options=[]), "needs unique"),
    (lambda c: c["items"][1].update(label="see https://x.example"), "URL"),
    (lambda c: c["items"][1].update(label="ip 10.0.0.1"), "URL"),
    (lambda c: c["pm"].update(body="Hi {{BASE_URL}}/workflows/form/" + c["workflow"]["uuid"]), "USERNAME"),
    (lambda c: c["pm"].update(body="Hi {{USERNAME}}"), "form uuid"),
    (lambda c: c["items"][1].pop("name"), "name"),
])
def test_validation_rejects(mutate, msg):
    cfg = copy.deepcopy(CFG)
    mutate(cfg)
    with pytest.raises(fs.FormSyncError, match=msg):
        fs.validate(cfg)


def test_pm_round_trip_and_untouched_rest():
    wf = w19()
    out = fs.apply_pm(wf, CFG)
    assert fs.read_pm(out["nodes"][0]["parameters"]["code"]) == {"title": CFG["pm"]["title"], "body": CFG["pm"]["body"]}
    assert fs.read_pm(out["nodes"][0]["parameters"]["code"])["body"] == BASE["w19"]["pm_body"]
    old, new = wf["nodes"][0]["parameters"]["code"].splitlines(), out["nodes"][0]["parameters"]["code"].splitlines()
    assert [i for i, (a, b) in enumerate(zip(old, new)) if a != b] == [2, 3]
    assert new[2].startswith("  var TITLE = ")  # indentation kept
    assert out["nodes"][0]["parameters"]["other"] == 1 and out["nodes"][1] == wf["nodes"][1]
    # idempotent
    assert fs.apply_pm(out, CFG) == out


def test_apply_pm_needs_exactly_one_line():
    wf = w19()
    wf["nodes"][0]["parameters"]["code"] = "return [];"
    with pytest.raises(fs.FormSyncError):
        fs.apply_pm(wf, CFG)


def test_cli_diff_then_apply_saves_draft_only(monkeypatch, capsys):
    cfg = copy.deepcopy(CFG)
    cfg["items"][1]["options"][0] = "Changed"
    path = ROOT / ".pytest_cache" / "form.yml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
    puts = []

    def handler(req: httpx.Request):
        if req.method == "GET":
            return httpx.Response(200, json={"workflow": w16() if req.url.path.endswith("/38.json") else w19()})
        puts.append((req.url.path, json.loads(req.content)))
        return httpx.Response(200, json={"workflow": {"version_id": "v2", "has_unpublished_changes": True}})

    client = DiscourseClient("https://f.example", "k", transport=httpx.MockTransport(handler))
    assert fs.main(["--file", str(path)], client) == 0
    assert not puts and "Changed" in capsys.readouterr().out
    monkeypatch.delenv("FORM_SYNC_CONFIRM", raising=False)
    assert fs.main(["--file", str(path), "--apply"], client) == 2 and not puts
    monkeypatch.setenv("FORM_SYNC_CONFIRM", "yes")
    assert fs.main(["--file", str(path), "--apply"], client) == 0
    assert [p for p, _ in puts] == [fs.WF_PATH.format(38), fs.WF_PATH.format(41)]
    assert all(set(b["workflow"]) == {"nodes", "connections"} for _, b in puts)  # never `published`
