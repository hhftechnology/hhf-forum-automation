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
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

from .discourse import DiscourseClient
from .sources import releases
from .webhook import DeliveryError, configured, post_webhook

ROOT = Path(__file__).resolve().parents[2]
PARENT_NAME = "Project Releases"
FETCH = 100


MAX_BODY = 20000  # well under Discourse's default max_post_length (32000), so long changelogs never block a repo
MAX_NAME = 120  # upstream release names are untrusted; a heading never needs more
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


def _no_mentions(text: str) -> str:
    """GitHub @handles would ping unrelated forum users or groups; a zero-width space stops mention parsing."""
    return re.sub(r"@(?=[\w-])", "@​", text)


def _safe_name(name) -> str:
    """Upstream release names are untrusted: one line, capped, with link and inline-markup characters escaped,
    so a name like `x](u) @group [y` can neither close the heading link early nor ping anyone."""
    name = " ".join(str(name or "").split())
    if len(name) > MAX_NAME:
        name = name[:MAX_NAME].rstrip() + "…"
    return _no_mentions(re.sub(r"([\\`*_\[\]()<>!|~])", r"\\\1", name))


def render(rel: dict) -> str:
    head = f"## [{rel['repo']} {_safe_name(rel['name'])}]({rel['url']})"
    if rel["prerelease"]:
        head += " (pre-release)"
    body = rel.get("body") or "_No release notes._"
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY].rstrip() + f"\n\n…\n\n[Full release notes]({rel['url']})"
    return f"{head}\n\n{_no_mentions(body)}"


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


def group_title(e: dict) -> str:
    """The release group's display name: the app's name, never the repo path.

    Channels under a product parent ("Pangolin Releases") carry the product too, so "Newt" reads
    "Pangolin Newt releases" and "Pangolin Node" stays "Pangolin Node releases"."""
    name = " ".join(_sub(e).split())
    product = _parent(e).strip()
    if product.casefold().endswith(" releases"):
        product = product[: -len(" releases")].strip()
    if _parent(e) != PARENT_NAME and product and not name.casefold().startswith(product.casefold()):
        name = f"{product} {name}"
    return f"{name} releases"


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
    category_names: set[tuple[str, str]] = set()
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
        if "include_prereleases" in e and type(e["include_prereleases"]) is not bool:
            raise ValueError(f"include_prereleases must be a boolean in {key(e)}")
        if _validation_key(e) in seen:
            raise ValueError(f"duplicate release entry {key(e)}")
        seen.add(_validation_key(e))
        parent_key = _parent(e).strip().casefold()
        title_key = (parent_key, discussion_title(e).casefold())
        if title_key in channel_titles:
            raise ValueError(f"duplicate release channel title {discussion_title(e)!r} in {_parent(e)}")
        channel_titles.add(title_key)
        category_key = (parent_key, _sub(e).strip().casefold())
        if category_key in category_names:
            raise ValueError(f"duplicate release category {_sub(e)!r} in {_parent(e)}")
        category_names.add(category_key)
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
            not isinstance(e["app_reference"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{1,63}", e["app_reference"])
        ):
            raise ValueError(f"invalid app_reference in {key(e)}")
        if e.get("icon_app") is not None and (
            not isinstance(e["icon_app"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{1,63}", e["icon_app"])
        ):
            raise ValueError(f"invalid icon_app in {key(e)}")
        if e.get("icon_url") is not None:
            if not isinstance(e["icon_url"], str):
                raise ValueError(f"icon_url must use a trusted HTTPS host in {key(e)}")
            _icon_url(e["icon_url"], key(e))
        if require_icon and (not e.get("category_id") or not e.get("topic_id")) and not (
            e.get("app_reference") or e.get("icon_url") or e.get("icon_app")
        ):
            raise ValueError(f"new release channel {key(e)} requires app_reference, icon_app or icon_url")


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
            for field in ("category_id", "topic_id", "discussion_topic_id", "activated_at", "provisioning_error"):
                if not entry.get(field) and mapped.get(field):
                    entry[field] = mapped[field]
            if not entry.get("groups") and mapped.get("groups"):
                entry["groups"] = mapped["groups"]


def _save_channels(path: Path, entries: list[dict], *, complete_only: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for e in entries:
        if complete_only and not (e.get("category_id") and e.get("topic_id")):
            continue
        row = {k: e[k] for k in ("repo", "category_id", "topic_id", "name", "parent", "tag_prefix", "discussion_topic_id") if k in e}
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
    if last not in tags:
        raise ValueError(f"release checkpoint {last!r} is missing; repair required")
    rows = rows[:tags.index(last)]
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


def run(entries: list[dict], state: dict, client, *, dry_run: bool, fetch=None, checkpoint=None, budget: float = 600) -> int:
    """Post new releases, updating ``state`` in place. Returns the number of posts (planned if dry)."""
    fetch = fetch or releases.latest
    can_notify = configured("release")
    if not can_notify and any(e.get("groups") for e in entries):
        print("WORKFLOW_WEBHOOK_URL_RELEASE / WORKFLOW_WEBHOOK_TOKEN not set: no DMs will be sent")
    n = 0
    failed: list[str] = []
    cursor = state.get("polling", {}).get("next")
    start = next((i for i, entry in enumerate(entries) if key(entry) == cursor), 0)
    deadline = time.monotonic() + budget
    deferred = False
    # shortcut: budget is checked between repositories; add per-request deadlines if one repository exceeds the job budget.
    for e in entries[start:]:
        repo = key(e)
        state["polling"] = {"next": repo, "pending": True}
        if time.monotonic() >= deadline:
            deferred = True
            print(f"polling deferred at {repo}; continuing next scheduled run")
            break
        if not e.get("topic_id"):
            print(f"skip {repo}: no topic_id (run --bootstrap)")
            continue
        last = state["last"].get(repo)
        try:
            rows = _rows(e, fetch)
            tracking = state.setdefault("tracking", {}).get(repo)
            identity = lambda row: str(row.get("id", row["tag"]))
            if tracking is None:
                if last is None:
                    activation = e.get("activated_at")
                    baseline = [row for row in rows if not activation or not row.get("published_at") or row["published_at"] <= activation]
                    tracking = state["tracking"][repo] = {"seen": [identity(row) for row in baseline]}
                    if baseline:
                        print(f"baseline {repo}: {baseline[0]['tag']} (not posted)")
                        state["last"][repo] = baseline[0]["tag"]
                    if checkpoint and not dry_run:
                        checkpoint()
                else:
                    pending = new_releases(rows, last)
                    pending_ids = {identity(row) for row in pending}
                    tracking = state["tracking"][repo] = {"seen": [identity(row) for row in rows if identity(row) not in pending_ids]}
            seen = set(tracking["seen"])
            pending = [row for row in rows if identity(row) not in seen]
            pending.reverse()
            if pending and all(row.get("published_at") for row in pending):
                pending.sort(key=lambda row: (row["published_at"], identity(row)))
            existing = client.release_urls(e["topic_id"]) if pending and not dry_run and hasattr(client, "release_urls") else set()
        except releases.ReleaseRateLimit:
            deferred = True
            print(f"GitHub rate limit at {repo}; continuing next scheduled run")
            break
        except (releases.ReleaseFetchError, ValueError, RuntimeError) as exc:
            print(f"error: {repo}: {exc}", file=sys.stderr)
            failed.append(repo)
            continue
        groups = e.get("groups") or []
        for rel in pending:
            print(f"post {repo} {rel['tag']} -> topic {e['topic_id']}")
            n += 1
            if dry_run and groups:
                print(f"  would DM groups: {', '.join(groups)}")
            if not dry_run:
                try:
                    result = None if rel["url"] in existing else client.create_post(e["topic_id"], render(rel))
                except Exception as exc:  # stop this repo (keeps release order), go on with the others
                    print(f"error: posting {repo} {rel['tag']} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
                    failed.append(repo)
                    break
                state["last"][repo] = rel["tag"]  # per post, so a mid-run failure never re-posts
                tracking["seen"].append(identity(rel))
                if checkpoint:
                    checkpoint()
                if result and groups and can_notify:
                    notify(e["repo"], rel["tag"], groups, result)
    if not deferred:
        state["polling"] = {"pending": False}
    if checkpoint and not dry_run:
        checkpoint()
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
    elif entry.get("app_reference") or entry.get("icon_app"):
        reference = entry.get("app_reference") or entry["icon_app"]
        icon_url = client.get_app_icon(reference)
        if not icon_url:
            raise ValueError(f"catalogue app {reference} has no approved icon")
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


def bootstrap(entries: list[dict], client, *, dry_run: bool, limit: int = 50, progress=None) -> None:
    """Idempotently provision incomplete channels and print IDs for review.

    New release categories are muted by default; joining a channel group turns on Watching.
    In dry-run, ``client`` is not used (may be None).
    """
    entries = [e for e in entries if not (e.get("category_id") and e.get("topic_id") and not e.get("provisioning"))][:limit]
    deadline = time.monotonic() + 600
    # shortcut: deadline is checked between channels; add per-request deadlines if a channel exceeds the workflow budget.
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
                print(f"would ensure public group '{g}' ({group_title(e)}) and set it to Watching on {pn}/{name}")
            print(f"would create discussion topic in {pn}/{name}")
        print("would mute newly created categories by default")
        return
    cats = client.list_categories()
    existing_groups: dict[str, dict | None] = {}
    icons: dict[str, tuple[str, bytes] | None] = {}
    parents: dict[str, dict | None] = {
        pn: next((c for c in cats if c["name"] == pn and not c.get("parent_category_id")), None)
        for pn in dict.fromkeys(_parent(e) for e in entries)}
    watch: list[tuple[str, int]] = []
    failed = []
    for e in entries:
        repo, name, pn = e["repo"], _sub(e), _parent(e)
        if time.monotonic() >= deadline:
            break
        try:
            e["provisioning"] = True
            groups = e.get("groups") or [_group(e)]
            title = _title(e)
            # Create groups first so the category can grant them create_post on creation.
            for g in groups:
                if g not in existing_groups:
                    existing_groups[g] = client.get_group(g)
                if not existing_groups[g] and key(e) not in icons:
                    icons[key(e)] = _icon_bytes(e, client)
                if not existing_groups[g]:
                    icon = icons.get(key(e))
                    upload_id = client.upload_file(icon[0], icon[1], upload_type="group_flair")["id"] if icon else None
                    existing_groups[g] = client.ensure_group(g, group_title(e), flair_upload_id=upload_id)
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
                cats.append(category)
            e["category_id"] = cat_id
            if progress:
                progress()
            # Reapply after a partial create: this additive setting merge is idempotent.
            if unmapped_channel or e.get("provisioning"):
                client.mute_categories_by_default([parent["id"], cat_id])
            topic_id = e.get("topic_id") or client.find_topic_by_title(cat_id, title)
            if not topic_id:
                topic_id = client.create_topic(
                    title=title, category=cat_id, raw=topic_text(repo, groups))["topic_id"]
            if not e.get("topic_id"):
                client.set_topic_status(topic_id, "pinned", True)
                client.set_topic_status(topic_id, "closed", True)
            e["category_id"], e["topic_id"], e["groups"] = cat_id, topic_id, groups
            if progress:
                progress()
            # Newly provisioned channels get a separate open discussion topic; legacy channels stay as-is.
            if (new_channel or e.get("provisioning")) and not e.get("discussion_topic_id"):
                title = discussion_title(e)
                e["discussion_topic_id"] = client.find_topic_by_title(cat_id, title) or client.create_topic(
                    title=title, category=cat_id, raw=discussion_text(repo, groups))["topic_id"]
            for g in groups:
                client.watch_category_for_group(g, cat_id)
            e.pop("provisioning_error", None)
            e.pop("provisioning", None)
            e.setdefault("activated_at", datetime.now(timezone.utc).isoformat())
            if progress:
                progress()
            print(f"{key(e)}: category_id: {cat_id}  topic_id: {topic_id}")
        except Exception as exc:
            e["provisioning"] = True
            e["provisioning_error"] = type(exc).__name__
            failed.append(key(e))
            if progress:
                progress()
            print(f"error: provisioning {key(e)}: {_describe(exc)}", file=sys.stderr)
    if failed:
        raise RuntimeError(f"release provisioning failed for: {", ".join(failed)}")


def repair_groups(entries: list[dict], client, *, dry_run: bool) -> list[str]:
    """Give every provisioned release group its app name and, when it has none, its app icon.

    Groups made before the naming fix were titled "<owner/repo> releases" and the oldest ones have no
    flair. This lists the groups once (a few paged requests) and only writes the ones that differ, so it
    is cheap enough to run on every full release run. Returns the groups it could not repair."""
    groups = {g["name"]: g for g in client.list_groups("releases-")}
    failed = []
    icons: dict[str, tuple[str, bytes] | None] = {}
    for e in entries:
        if e.get("provisioning") or not e.get("topic_id"):
            continue
        for g in e.get("groups") or [_group(e)]:
            group = groups.get(g)
            if not group:
                continue
            changes: dict = {}
            if group.get("full_name") != group_title(e):
                changes["full_name"] = group_title(e)
            needs_icon = not group.get("flair_url") and (e.get("icon_url") or e.get("app_reference") or e.get("icon_app"))
            if not changes and not needs_icon:
                continue
            if dry_run:
                print(f"would repair group {g}: {changes or ''}{' + icon' if needs_icon else ''}")
                continue
            try:
                if needs_icon:
                    if key(e) not in icons:
                        icons[key(e)] = _icon_bytes(e, client)
                    icon = icons[key(e)]
                    if icon:
                        changes["flair_upload_id"] = client.upload_file(icon[0], icon[1], upload_type="group_flair")["id"]
                if changes:
                    client.update_group(group["id"], **changes)
                    print(f"repaired group {g}: {', '.join(changes)}")
            except Exception as exc:  # one bad icon must not stop the other repairs
                failed.append(g)
                print(f"error: repairing group {g}: {_describe(exc)}", file=sys.stderr)
    return failed


def _describe(exc: Exception) -> str:
    status = getattr(exc, "status", None) or getattr(exc, "status_code", None)
    return f"{type(exc).__name__} {status}" if status else type(exc).__name__


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Post new GitHub releases to the forum")
    ap.add_argument("--dry-run", action="store_true", help="print planned actions, write nothing")
    ap.add_argument("--bootstrap", action="store_true", help="provision missing channels and exit")
    ap.add_argument("--validate-only", action="store_true", help="validate config and saved mapping without credentials")
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "releases.yml")
    ap.add_argument("--state", type=Path, default=ROOT / "state" / "releases.json")
    ap.add_argument("--channels", type=Path, default=ROOT / "state" / "release_channels.json")
    ap.add_argument("--provision-limit", type=int, default=50)
    ap.add_argument("--repair-groups", action="store_true",
                    help="only fix release group names and missing icons, then exit")
    ap.add_argument("--continue-poll", action="store_true", help="resume an unfinished polling cycle during provisioning runs")
    args = ap.parse_args(argv)
    if not 1 <= args.provision_limit <= 50:
        ap.error("--provision-limit must be between 1 and 50")

    entries = (yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}).get("releases") or []
    _merge_channels(entries, _load_channels(args.channels))
    progress_path = args.channels.with_name("release_provisioning.json")
    if progress_path.exists():
        progress_rows = json.loads(progress_path.read_text(encoding="utf-8"))["releases"]
        _merge_channels(entries, progress_rows)
        pending_keys = {_channel_key(row) for row in progress_rows if row.get("provisioning")}
        for entry in entries:
            if _channel_key(entry) in pending_keys:
                entry["provisioning"] = True
    validate(entries)
    if args.validate_only:
        print(f"validated {len(entries)} release channels")
        return 0
    client = None if args.dry_run else DiscourseClient()
    if args.repair_groups:
        if args.dry_run:
            print("dry run: group repair needs the forum; nothing done")
            return 0
        failed = repair_groups(entries, client, dry_run=False)
        return 1 if failed else 0
    def progress():
        save_json(progress_path, {"releases": entries})
        _save_channels(args.channels, [entry for entry in entries if not entry.get("provisioning")])
    provisioning_error = None
    try:
        bootstrap(entries, client, dry_run=args.dry_run, limit=args.provision_limit,
                  progress=None if args.dry_run else progress)
    except RuntimeError as exc:
        provisioning_error = exc
    finally:
        if not args.dry_run:
            progress()
    state = load_json(args.state)
    state.setdefault("last", {})
    if args.bootstrap and not (args.continue_poll and state.get("polling", {}).get("pending")):
        if provisioning_error:
            raise provisioning_error
        return 0
    if not args.dry_run:
        # Full runs keep group names and icons right; a failure is logged and retried next run.
        try:
            repair_groups(entries, client, dry_run=False)
        except Exception as exc:
            print(f"error: repairing release groups: {_describe(exc)}", file=sys.stderr)
    try:
        ready = [entry for entry in entries if entry.get("topic_id") and not entry.get("provisioning")]
        run(ready, state, client, dry_run=args.dry_run,
            checkpoint=lambda: save_json(args.state, state))
    finally:  # keep tags of posts already made even if a later post fails
        if not args.dry_run:
            save_json(args.state, state)
    if provisioning_error:
        raise provisioning_error
    return 0


if __name__ == "__main__":
    sys.exit(main())
