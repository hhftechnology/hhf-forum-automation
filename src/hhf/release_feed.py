"""Post new GitHub releases of watched repos as replies in pinned, closed forum topics.

Config: config/releases.yml. State: state/releases.json ({"last": {key: last posted tag}}, see key()).
Auth for the forum comes from DISCOURSE_URL / DISCOURSE_API_KEY (the key's user must be staff/bot:
only staff can reply in closed topics).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import yaml

from .discourse import DiscourseClient
from .sources import releases
from .webhook import DeliveryError, configured, post_webhook

ROOT = Path(__file__).resolve().parents[2]
PARENT_NAME = "Project Releases"
FETCH = 10  # releases looked at per repo per run


MAX_BODY = 20000  # well under Discourse's default max_post_length (32000), so long changelogs never block a repo


def load_json(path: Path) -> dict:
    """Missing file = empty state. A corrupt file raises: treating it as empty would silently re-baseline every repo."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"last": {}}


def save_json(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)  # atomic: a crash never leaves truncated JSON


def render(rel: dict) -> str:
    head = f"## [{rel['repo']} {rel['name']}]({rel['url']})"
    if rel["prerelease"]:
        head += " (pre-release)"
    body = rel.get("body") or "_No release notes._"
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY].rstrip() + f"\n\n…\n\n[Full release notes]({rel['url']})"
    # GitHub @handles would ping unrelated forum users or groups; a zero-width space stops mention parsing
    body = re.sub(r"@(?=[\w-])", "@​", body)
    return f"{head}\n\n{body}"


def key(e: dict) -> str:
    """State key: the repo, or repo#tag_prefix when several entries share a repo."""
    return f"{e['repo']}#{e['tag_prefix']}" if e.get("tag_prefix") else e["repo"]


def _sub(e: dict) -> str:
    return e.get("name") or e["repo"].split("/")[-1]


def _parent(e: dict) -> str:
    return e.get("parent") or PARENT_NAME


def _title(e: dict) -> str:
    """"<repo> releases"; a tag_prefix split adds the name ("fosrl/apple iOS releases") unless it only repeats the repo."""
    split = e.get("tag_prefix") and _sub(e).lower() != e["repo"].split("/")[-1].lower()
    return f"{e['repo']} {_sub(e)} releases" if split else f"{e['repo']} releases"


def validate(entries: list[dict]) -> None:
    seen: set[str] = set()
    for e in entries:
        for g in e.get("groups") or []:
            if not re.fullmatch(r"[a-z0-9_-]{1,20}", str(g)):
                raise ValueError(f"invalid group name {g!r} in {key(e)}: use 1-20 chars of [a-z0-9_-]")
        if key(e) in seen:
            raise ValueError(f"duplicate release entry {key(e)}")
        seen.add(key(e))


def _rows(entry: dict, fetch) -> list[dict]:
    """Non-draft releases (newest first), pre-releases only when the entry opts in; tag_prefix narrows by tag."""
    prefix = entry.get("tag_prefix") or ""
    return [r for r in fetch(entry["repo"], per_page=FETCH)
            if r["tag"] and r["tag"].startswith(prefix) and (entry.get("include_prereleases") or not r["prerelease"])]


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
        repo = key(e)
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
                    notify(e["repo"], rel["tag"], groups, result)
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
        parents = list(dict.fromkeys(_parent(e) for e in entries))
        for pn in parents:
            print(f"would ensure category {pn} (everyone read-only, staff create)")
        for e in entries:
            name, pn = _sub(e), _parent(e)
            print(f"would ensure {pn}/{name} + closed pinned topic '{_title(e)}'")
            for g in e.get("groups") or []:
                print(f"would ensure public group '{g}' and set it to Watching on {pn}/{name}")
        print(f"would mute {len(parents)} parent categories and {len(entries)} subcategories by default")
        return
    cats = client.list_categories()
    parents: dict[str, dict | None] = {
        pn: next((c for c in cats if c["name"] == pn and not c.get("parent_category_id")), None)
        for pn in dict.fromkeys(_parent(e) for e in entries)}
    muted: list[int] = [p["id"] for p in parents.values() if p]
    watch: list[tuple[str, int]] = []
    for e in entries:
        repo, name, pn, groups = e["repo"], _sub(e), _parent(e), e.get("groups") or []
        parent = parents[pn]
        cat_id = e.get("category_id") or next(
            (c["id"] for c in cats if c["name"] == name and parent and c.get("parent_category_id") == parent["id"]), None)
        if not cat_id:
            if not parent:
                parent = parents[pn] = client.create_category(pn)
                cats.append(parent)
                muted.append(parent["id"])
            cat_id = client.create_category(name, parent_category_id=parent["id"])["id"]
            # mute before its topic exists, so a new release topic never shows in Latest
            client.mute_categories_by_default([parent["id"], cat_id])
        title = _title(e)
        topic_id = e.get("topic_id") or client.find_topic_by_title(cat_id, title)
        if not topic_id:
            topic_id = client.create_topic(
                title=title, category=cat_id, raw=topic_text(repo, groups))["topic_id"]
            client.set_topic_status(topic_id, "pinned", True)
            client.set_topic_status(topic_id, "closed", True)
        for g in groups:
            client.ensure_group(g, title)
            watch.append((g, cat_id))
        muted.append(cat_id)
        print(f"{key(e)}: category_id: {cat_id}  topic_id: {topic_id}")
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
    validate(entries)
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
