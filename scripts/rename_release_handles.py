"""One-off: give catalogue release groups readable handles (releases-<app reference>).

Batch 1 named its groups releases-<11 hex>. This rewrites those names in config/releases.yml and
the two state files, and prints {old: new} as JSON for renaming the live groups. Groups that
already have readable names (the legacy channels) are kept. Run it with no provisioning run in
progress, rename the live groups to the printed names, then merge, so the next run finds them.

    python scripts/rename_release_handles.py [--max-len 36] [--write]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hhf.release_feed import group_handle  # noqa: E402

HASHED = re.compile(r"releases-[0-9a-f]{11}")


def plan(entries: list[dict], max_len: int) -> dict[str, str]:
    taken: dict[str, tuple[str, str]] = {}
    for e in entries:
        for g in e.get("groups") or []:
            if not HASHED.fullmatch(g):
                taken[g] = (e["repo"].lower(), e.get("tag_prefix") or "")
    renames = {}
    for e in entries:
        groups = e.get("groups") or []
        if len(groups) != 1 or not HASHED.fullmatch(groups[0]) or not e.get("app_reference"):
            continue
        new = group_handle(e["app_reference"], e["repo"], e.get("tag_prefix"), taken, max_len)
        taken[new] = (e["repo"].lower(), e.get("tag_prefix") or "")
        renames[groups[0]] = new
    if len(set(renames.values())) != len(renames):
        raise SystemExit("two channels would share a handle")
    return renames


def _replace_in_text(path: Path, renames: dict[str, str]) -> None:
    text = path.read_text(encoding="utf-8")
    text = HASHED.sub(lambda m: renames.get(m.group(0), m.group(0)), text)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-len", type=int, default=36)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    import yaml

    entries = yaml.safe_load((ROOT / "config" / "releases.yml").read_text(encoding="utf-8"))["releases"]
    renames = plan(entries, args.max_len)
    if args.write:
        for rel in ("config/releases.yml", "state/release_channels.json", "state/release_provisioning.json"):
            path = ROOT / rel
            if path.exists():
                _replace_in_text(path, renames)
    print(json.dumps(renames, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
