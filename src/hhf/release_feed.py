"""Post new GitHub releases of watched repos as replies in pinned, closed forum topics.

Config: config/releases.yml. State: state/releases.json ({"last": {repo: last posted tag}}).
Auth for the forum comes from DISCOURSE_URL / DISCOURSE_API_KEY (the key's user must be staff/bot:
only staff can reply in closed topics).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from .discourse import DiscourseClient
from .sources import releases
from .webhook import DeliveryError, configured, post_webhook

ROOT = Path(__file__).resolve().parents[2]
PARENT_NAME = "Project Releases"
FETCH = 10  # releases looked at per repo per run


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"last": {}}


def save_json(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render(rel: dict) -> str:
    head = f"## [{rel['repo']} {rel['name']}]({rel['url']})"
    if rel["prerelease"]:
        head += " (pre-release)"
    return f"{head}\n\n{rel.get('body') or '_No release notes._'}"


def _rows(entry: dict, fetch) -> list[dict]:
    """Non-draft releases (newest first), pre-releases only when the entry opts in."""
    return [r for r in fetch(entry["repo"], per_page=FETCH)
            if r["tag"] and (entry.get("include_prereleases") or not r["prerelease"])]


def new_releases(rows: list[dict], last: str) -> list[dict]:
    """Releases newer than ``last``, oldest first."""
    tags = [r["tag"] for r in rows]
    # last tag fell out of the window: post only the newest, never a backfill
    rows = rows[: tags.index(last)] if last in tags else rows[:1]
    return rows[::-1]


def post_url(result: dict) -> str:
    base = os.environ.get("DISCOURSE_URL", "").rstrip("/")
    return f"{base}/t/{result['topic_slug']}/{result['topic_id']}/{result['post_number']}"


def notify(repo: str, tag: str, groups: list[str], result: dict) -> None:
    """Tell the workflow to DM the groups. A failure only warns: the post exists and state advances."""
    try:
        post_webhook({"kind": "release", "repo": repo, "tag": tag, "url": post_url(result), "groups": groups})
    except Exception as exc:  # never print exc for non-DeliveryError: it could carry the URL
        detail = exc if isinstance(exc, DeliveryError) else type(exc).__name__
        print(f"warning: notify failed for {repo} {tag}: {detail}", file=sys.stderr)


def run(entries: list[dict], state: dict, client, *, dry_run: bool, fetch=None) -> int:
    """Post new releases, updating ``state`` in place. Returns the number of posts (planned if dry)."""
    fetch = fetch or releases.latest
    can_notify = configured("release")
    if not can_notify and any(e.get("groups") for e in entries):
        print("WORKFLOW_WEBHOOK_URL_RELEASE / WORKFLOW_WEBHOOK_TOKEN not set: no DMs will be sent")
    n = 0
    failed: list[str] = []
    for e in entries:
        repo = e["repo"]
        if not e.get("topic_id"):
            print(f"skip {repo}: no topic_id (run --bootstrap)")
            continue
        last = state["last"].get(repo)
        rows = _rows(e, fetch)
        if last is None:
            if rows:
                print(f"baseline {repo}: {rows[0]['tag']} (not posted)")
                state["last"][repo] = rows[0]["tag"]
            continue
        groups = e.get("groups") or []
        for rel in new_releases(rows, last):
            print(f"post {repo} {rel['tag']} -> topic {e['topic_id']}")
            n += 1
            if dry_run and groups:
                print(f"  would DM groups: {', '.join(groups)}")
            if not dry_run:
                try:
                    result = client.create_post(e["topic_id"], render(rel))
                except Exception as exc:  # stop this repo (keeps release order), go on with the others
                    print(f"error: posting {repo} {rel['tag']} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
                    failed.append(repo)
                    break
                state["last"][repo] = rel["tag"]  # per post, so a mid-run failure never re-posts
                if groups and can_notify:
                    notify(repo, rel["tag"], groups, result)
    if failed:  # after all repos, so the job still fails visibly; main() saves state first
        raise RuntimeError(f"posting failed for: {', '.join(failed)}")
    return n


def topic_text(repo: str, groups: list[str]) -> str:
    text = f"New releases of [{repo}](https://github.com/{repo}/releases) are posted here automatically."
    if groups:
        links = " or ".join(f"[@{g}](/g/{g})" for g in groups)
        text += f"\n\nJoin {links} to get a DM and a bell for every release."
    return text


def bootstrap(entries: list[dict], client, *, dry_run: bool) -> None:
    """Idempotently create the category, subcategories, topics, groups and defaults; print ids for the config.

    Releases stay out of Latest (categories muted by default); joining a repo's group turns on Watching.
    In dry-run, ``client`` is not used (may be None).
    """
    if dry_run:
        print(f"would ensure category {PARENT_NAME} (everyone read-only, staff create)")
        for e in entries:
            repo, name = e["repo"], e["repo"].split("/")[-1]
            print(f"would ensure {PARENT_NAME}/{name} + closed pinned topic '{repo} releases'")
            for g in e.get("groups") or []:
                print(f"would ensure public group '{g}' and set it to Watching on {PARENT_NAME}/{name}")
        print(f"would mute {PARENT_NAME} and {len(entries)} subcategories by default")
        return
    cats = client.list_categories()
    parent = next((c for c in cats if c["name"] == PARENT_NAME and not c.get("parent_category_id")), None)
    muted: list[int] = [parent["id"]] if parent else []
    watch: list[tuple[str, int]] = []
    for e in entries:
        repo, name, groups = e["repo"], e["repo"].split("/")[-1], e.get("groups") or []
        cat_id = e.get("category_id") or next(
            (c["id"] for c in cats if c["name"] == name and parent and c.get("parent_category_id") == parent["id"]), None)
        if not cat_id:
            if not parent:
                parent = client.create_category(PARENT_NAME)
                cats.append(parent)
                muted.append(parent["id"])
            cat_id = client.create_category(name, parent_category_id=parent["id"])["id"]
        topic_id = e.get("topic_id") or client.find_topic_by_title(cat_id, f"{repo} releases")
        if not topic_id:
            topic_id = client.create_topic(
                title=f"{repo} releases", category=cat_id, raw=topic_text(repo, groups))["topic_id"]
            client.set_topic_status(topic_id, "pinned", True)
            client.set_topic_status(topic_id, "closed", True)
        for g in groups:
            client.ensure_group(g, f"{repo} releases")
            watch.append((g, cat_id))
        muted.append(cat_id)
        print(f"{repo}: category_id: {cat_id}  topic_id: {topic_id}")
    # mute first, then group Watching, so the mute backfill can never override a member's Watching
    client.mute_categories_by_default(muted)
    for g, cat_id in watch:
        client.watch_category_for_group(g, cat_id)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Post new GitHub releases to the forum")
    ap.add_argument("--dry-run", action="store_true", help="print planned actions, write nothing")
    ap.add_argument("--bootstrap", action="store_true", help="create missing subcategories/topics (explicit opt-in)")
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "releases.yml")
    ap.add_argument("--state", type=Path, default=ROOT / "state" / "releases.json")
    args = ap.parse_args(argv)

    entries = (yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}).get("releases") or []
    client = None if args.dry_run else DiscourseClient()
    if args.bootstrap:
        bootstrap(entries, client, dry_run=args.dry_run)
        return 0
    state = load_json(args.state)
    state.setdefault("last", {})
    try:
        run(entries, state, client, dry_run=args.dry_run)
    finally:  # keep tags of posts already made even if a later post fails
        if not args.dry_run:
            save_json(args.state, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
