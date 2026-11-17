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
from urllib.parse import urlparse

import httpx
import yaml

from .discourse import DiscourseClient
from .sources import releases
from .webhook import DeliveryError, configured, post_webhook

ROOT = Path(__file__).resolve().parents[2]
PARENT_NAME = "Project Releases"
FETCH = 10  # releases looked at per repo per run


MAX_BODY = 20000  # well under Discourse's default max_post_length (32000), so long changelogs never block a repo
MAX_ICON_BYTES = 5_000_000
ICON_HOSTS = {
    "forum.hhf.technology", "r2.hhf.technology", "raw.githubusercontent.com", "github.com",
    "cdn.jsdelivr.net", "gitlab.com",
}


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


def _group(e: dict) -> str:
    groups = e.get("groups") or []
    return groups[0] if groups else "releases-" + re.sub(r"[^a-z0-9_-]", "-", str(_sub(e)).lower())[:11].strip("-")


def _channel_key(e: dict) -> tuple[str, str | None]:
    return e["repo"].lower(), e.get("tag_prefix")


def _validation_key(e: dict) -> str:
    return f"{e['repo'].lower()}#{e['tag_prefix']}" if e.get("tag_prefix") else e["repo"].lower()


def validate(entries: list[dict], *, require_icon: bool = True) -> None:
    if not isinstance(entries, list):
        raise ValueError("releases must be a list")
    seen: set[str] = set()
    groups: set[str] = set()
    channel_titles: set[tuple[str, str]] = set()
    for e in entries:
        if not isinstance(e, dict):
            raise ValueError("release entries must be objects")
        if not isinstance(e.get("repo"), str) or not re.fullmatch(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}", e["repo"]):
            raise ValueError(f"invalid release repo {e.get('repo')!r}")
        if e.get("name") is not None and (not isinstance(e["name"], str) or not e["name"].strip() or len(e["name"]) > 120):
            raise ValueError(f"invalid name in {key(e)}")
        if e.get("parent") is not None and (not isinstance(e["parent"], str) or not e["parent"].strip() or len(e["parent"]) > 120):
            raise ValueError(f"invalid parent in {key(e)}")
        if e.get("tag_prefix") is not None and (not isinstance(e["tag_prefix"], str) or len(e["tag_prefix"]) > 80):
            raise ValueError(f"invalid tag_prefix in {key(e)}")
        if _validation_key(e) in seen:
            raise ValueError(f"duplicate release entry {key(e)}")
        seen.add(_validation_key(e))
        title_key = (_parent(e).casefold(), discussion_title(e).casefold())
        if title_key in channel_titles:
            raise ValueError(f"duplicate release channel title {discussion_title(e)!r} in {_parent(e)}")
        channel_titles.add(title_key)
        channel_groups = e.get("groups") or [_group(e)]
        if not isinstance(channel_groups, list) or len(channel_groups) > 20:
            raise ValueError(f"invalid groups in {key(e)}")
        for g in channel_groups:
            if not isinstance(g, str) or not re.fullmatch(r"[a-z0-9_-]{1,20}", g):
                raise ValueError(f"invalid group name {g!r} in {key(e)}: use 1-20 chars of [a-z0-9_-]")
            if (not e.get("category_id") or not e.get("topic_id")) and not re.fullmatch(r"releases-[a-z0-9_-]+", g):
                raise ValueError(f"new release group {g!r} in {key(e)} must start with 'releases-' and a slug")
            if g in groups:
                raise ValueError(f"duplicate release group {g}")
            groups.add(g)
        for field in ("category_id", "topic_id", "discussion_topic_id"):
            value = e.get(field)
            if value is not None and (type(value) is not int or value <= 0):
                raise ValueError(f"invalid {field} in {key(e)}")
        if e.get("discussion_topic_id") and e.get("discussion_topic_id") == e.get("topic_id"):
            raise ValueError(f"release and discussion topic_id must differ in {key(e)}")
        if e.get("app_reference") is not None and (
            not isinstance(e["app_reference"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", e["app_reference"])
        ):
            raise ValueError(f"invalid app_reference in {key(e)}")
        if e.get("icon_url") is not None:
            if not isinstance(e["icon_url"], str):
                raise ValueError(f"icon_url must use a trusted HTTPS host in {key(e)}")
            _icon_url(e["icon_url"], key(e))
        if require_icon and (not e.get("category_id") or not e.get("topic_id")) and not (
            e.get("app_reference") or e.get("icon_url")
        ):
            raise ValueError(f"new release channel {key(e)} requires app_reference or icon_url")


def _load_channels(path: Path) -> list[dict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if not isinstance(document, dict) or not isinstance(document.get("releases"), list):
        raise ValueError("release channel mapping must contain a releases list")
    validate(document["releases"], require_icon=False)
    return document["releases"]


def _merge_channels(entries: list[dict], channels: list[dict]) -> None:
    by_key = {_channel_key(e): e for e in channels}
    for entry in entries:
        mapped = by_key.get(_channel_key(entry))
        if mapped:
            for field in ("category_id", "topic_id", "discussion_topic_id"):
                if not entry.get(field) and mapped.get(field):
                    entry[field] = mapped[field]
            if not entry.get("groups") and mapped.get("groups"):
                entry["groups"] = mapped["groups"]


def _save_channels(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for e in entries:
        row = {k: e[k] for k in ("repo", "category_id", "topic_id", "name", "tag_prefix", "discussion_topic_id") if k in e}
        row["groups"] = e.get("groups") or [_group(e)]
        rows.append(row)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"releases": rows}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


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


def discussion_text(repo: str, groups: list[str]) -> str:
    text = f"Discuss [{repo}](https://github.com/{repo}) and share how you use it."
    if groups:
        text += f"\n\nJoin [@{groups[0]}](/g/{groups[0]}) for release notifications."
    return text


def discussion_title(entry: dict) -> str:
    return f"{_title(entry)[:-len(' releases')]} discussion"


def _icon_url(url: str, entry_key: str) -> str:
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid icon URL in {entry_key}") from exc
    if (parsed.scheme != "https" or parsed.hostname not in ICON_HOSTS or port not in (None, 443)
            or parsed.username or parsed.password or parsed.fragment):
        raise ValueError(f"icon URL must use a trusted HTTPS host in {entry_key}")
    return url


def _icon_bytes(entry: dict, client) -> tuple[str, bytes] | None:
    if entry.get("icon_url"):
        url = entry["icon_url"]
    elif entry.get("app_reference"):
        icon_url = client.get_app_icon(entry["app_reference"])
        if not icon_url:
            raise ValueError(f"catalogue app {entry['app_reference']} has no approved icon")
        url = icon_url
    else:
        return None
    _icon_url(url, key(entry))
    with httpx.stream("GET", url, timeout=15, follow_redirects=False) as response:
        response.raise_for_status()
        length = response.headers.get("content-length")
        if length and int(length) > MAX_ICON_BYTES:
            raise ValueError(f"icon exceeds {MAX_ICON_BYTES} bytes for {key(entry)}")
        content_type = response.headers.get("content-type", "").split(";")[0]
        extensions = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif"}
        if content_type not in extensions:
            raise ValueError(f"invalid icon response for {key(entry)}")
        data = bytearray()
        for chunk in response.iter_bytes():
            if len(data) + len(chunk) > MAX_ICON_BYTES:
                raise ValueError(f"icon exceeds {MAX_ICON_BYTES} bytes for {key(entry)}")
            data.extend(chunk)
    return f"{_group(entry)}.{extensions[content_type]}", bytes(data)


def bootstrap(entries: list[dict], client, *, dry_run: bool) -> None:
    """Idempotently provision incomplete channels and print IDs for review.

    New release categories are muted by default; joining a channel group turns on Watching.
    In dry-run, ``client`` is not used (may be None).
    """
    entries = [e for e in entries if not (e.get("category_id") and e.get("topic_id"))]
    if not entries:
        return
    if dry_run:
        for e in entries:
            name, pn = _sub(e), _parent(e)
            groups = e.get("groups") or [_group(e)]
            if e.get("category_id") and e.get("topic_id"):
                continue
            print(f"would ensure category {pn} (everyone read-only, staff create)")
            print(f"would ensure {pn}/{name} + closed pinned topic '{_title(e)}'")
            for g in groups:
                print(f"would ensure public group '{g}' and set it to Watching on {pn}/{name}")
            print(f"would create discussion topic in {pn}/{name}")
        print("would mute newly created categories by default")
        return
    cats = client.list_categories()
    existing_groups: dict[str, dict | None] = {}
    icons: dict[str, tuple[str, bytes] | None] = {}
    for e in entries:
        for g in e.get("groups") or [_group(e)]:
            if g not in existing_groups:
                existing_groups[g] = client.get_group(g)
            if not existing_groups[g] and key(e) not in icons:
                icons[key(e)] = _icon_bytes(e, client)
    parents: dict[str, dict | None] = {
        pn: next((c for c in cats if c["name"] == pn and not c.get("parent_category_id")), None)
        for pn in dict.fromkeys(_parent(e) for e in entries)}
    watch: list[tuple[str, int]] = []
    for e in entries:
        repo, name, pn = e["repo"], _sub(e), _parent(e)
        groups = e.get("groups") or [_group(e)]
        title = _title(e)
        # Create groups first so the category can grant them create_post on creation.
        for g in groups:
            if not existing_groups[g]:
                icon = icons.get(key(e))
                upload_id = client.upload_file(icon[0], icon[1], upload_type="group_flair")["id"] if icon else None
                existing_groups[g] = client.ensure_group(g, title, flair_upload_id=upload_id)
        new_channel = not e.get("topic_id")
        unmapped_channel = not e.get("category_id") and new_channel
        parent = parents[pn]
        cat_id = e.get("category_id") or next(
            (c["id"] for c in cats if c["name"] == name and parent and c.get("parent_category_id") == parent["id"]), None)
        if not cat_id:
            if not parent:
                parent = parents[pn] = client.create_category(pn)
                cats.append(parent)
            category = client.create_category(name, parent_category_id=parent["id"], create_post_groups=groups)
            cat_id = category["id"]
        # Reapply after a partial create: this additive setting merge is idempotent.
        if unmapped_channel:
            client.mute_categories_by_default([parent["id"], cat_id])
        topic_id = e.get("topic_id") or client.find_topic_by_title(cat_id, title)
        if not topic_id:
            topic_id = client.create_topic(
                title=title, category=cat_id, raw=topic_text(repo, groups))["topic_id"]
        if not e.get("topic_id"):
            client.set_topic_status(topic_id, "pinned", True)
            client.set_topic_status(topic_id, "closed", True)
        e["category_id"], e["topic_id"], e["groups"] = cat_id, topic_id, groups
        # Newly provisioned channels get a separate open discussion topic; legacy channels stay as-is.
        if new_channel and not e.get("discussion_topic_id"):
            title = discussion_title(e)
            e["discussion_topic_id"] = client.find_topic_by_title(cat_id, title) or client.create_topic(
                title=title, category=cat_id, raw=discussion_text(repo, groups))["topic_id"]
        for g in groups:
            watch.append((g, cat_id))
        print(f"{key(e)}: category_id: {cat_id}  topic_id: {topic_id}")
    for g, cat_id in watch:
        client.watch_category_for_group(g, cat_id)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Post new GitHub releases to the forum")
    ap.add_argument("--dry-run", action="store_true", help="print planned actions, write nothing")
    ap.add_argument("--bootstrap", action="store_true", help="provision missing channels and exit")
    ap.add_argument("--validate-only", action="store_true", help="validate config and saved mapping without credentials")
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "releases.yml")
    ap.add_argument("--state", type=Path, default=ROOT / "state" / "releases.json")
    ap.add_argument("--channels", type=Path, default=ROOT / "state" / "release_channels.json")
    args = ap.parse_args(argv)

    entries = (yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}).get("releases") or []
    _merge_channels(entries, _load_channels(args.channels))
    validate(entries)
    if args.validate_only:
        print(f"validated {len(entries)} release channels")
        return 0
    client = None if args.dry_run else DiscourseClient()
    bootstrap(entries, client, dry_run=args.dry_run)
    if not args.dry_run:
        _save_channels(args.channels, entries)
    if args.bootstrap:
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
