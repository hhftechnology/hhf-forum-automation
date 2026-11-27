"""Small, generic Discourse API client (shared by docs sync and form sync).

Auth comes from the environment: DISCOURSE_URL, DISCOURSE_API_KEY and
DISCOURSE_API_USERNAME (default ``system``). The key is never logged or put
in an exception message / repr.
"""

from __future__ import annotations

import json

import logging
import mimetypes
import os
import time
from html.parser import HTMLParser
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Group.messageable_level "only admins" (Group::ALIAS_LEVELS). The release-notify workflow DMs each
# group from an admin account, and Discourse refuses that for the default level, "nobody".
GROUP_MESSAGEABLE_BY_ADMINS = 1

# Discourse: Topic::EXTERNAL_ID_MAX_LENGTH = 50, format /\A[\w-]+\z/, unique case-insensitive.
EXTERNAL_ID_MAX_LENGTH = 50


class DiscourseError(RuntimeError):
    def __init__(self, status: int, method: str, path: str, body: str = ""):
        super().__init__(f"{method} {path} -> HTTP {status}: {body[:300]}")
        self.status = status
        self.method, self.path = method, path
        try:
            errors = json.loads(body).get("errors") or []
        except (ValueError, AttributeError):
            errors = []
        if not isinstance(errors, list):
            errors = []
        # Discourse's own validation messages ("Title has already been used"), never the request.
        self.errors = "; ".join(str(e) for e in errors if isinstance(e, str))[:200]


class _ReleaseHeadingLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_heading = False
        self.urls = set()

    def handle_starttag(self, tag, attrs):
        if tag == "h2":
            self.in_heading = True
        elif tag == "a" and self.in_heading:
            url = dict(attrs).get("href")
            if url:
                self.urls.add(url)

    def handle_endtag(self, tag):
        if tag == "h2":
            self.in_heading = False


class ForumUnavailable(DiscourseError):
    """The forum gave no answer (timeout, dropped connection) even after retries. Callers skip the
    item and move on; status is 0 because no HTTP response arrived."""


class DeadlineReached(DiscourseError):
    """The run's deadline cut a request short (a 429 whose wait would pass it, or a paged read that
    ran out of time). Callers treat it as "continue next run", not as a failure of this item."""


class DiscourseClient:
    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        username: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        max_retries: int = 5,
        sleep=time.sleep,
        timeout: float = 30.0,
        transport_retries: int = 2,
    ):
        self.base_url = (url or os.environ.get("DISCOURSE_URL", "")).rstrip("/")
        key = api_key or os.environ.get("DISCOURSE_API_KEY", "")
        user = username or os.environ.get("DISCOURSE_API_USERNAME") or "system"
        if not self.base_url or not key:
            raise ValueError("DISCOURSE_URL and DISCOURSE_API_KEY are required")
        self.username = user
        self.max_retries = max_retries
        self.transport_retries = transport_retries
        self._timeout = timeout
        self._sleep = sleep
        # time.monotonic() after which a 429 is raised instead of slept on, so retries cannot carry a
        # run past its job timeout (a timed-out job commits no state).
        self.deadline: float | None = None
        self._http = httpx.Client(
            base_url=self.base_url,
            headers={"Api-Key": key, "Api-Username": user, "Accept": "application/json"},
            transport=transport,
            timeout=timeout,
        )

    def __repr__(self) -> str:  # never expose the key
        return f"DiscourseClient({self.base_url!r}, user={self.username!r})"

    def close(self) -> None:
        self._http.close()

    # -- low level ---------------------------------------------------------
    def request(self, method: str, path: str, *, allow_404: bool = False, **kw: Any) -> Any:
        transport_failures = 0
        attempt = 0
        while True:
            try:
                resp = self._http.request(method, path, **kw)
            except httpx.TransportError as exc:
                # The origin sometimes stalls past the timeout (Cloudflare logs 504s for it). Retry
                # reads; retry a write only when it never reached the forum, because a POST that
                # timed out may still have created its post.
                retryable = method in _IDEMPOTENT or isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
                transport_failures += 1
                if not retryable or transport_failures > self.transport_retries:
                    raise ForumUnavailable(0, method, path, f"no answer from the forum ({type(exc).__name__})") from None
                wait = _TRANSPORT_BACKOFF * transport_failures
                if self.deadline is not None and time.monotonic() + wait + self._timeout >= self.deadline:
                    raise DeadlineReached(0, method, path, f"no answer from the forum ({type(exc).__name__}) at the run deadline") from None
                log.warning("%s on %s %s, retrying in %.0fs", type(exc).__name__, method, path, wait)
                self._sleep(wait)
                continue
            if resp.status_code == 429 and attempt < self.max_retries:
                attempt += 1
                wait = _retry_after(resp)
                if self.deadline is not None and time.monotonic() + wait >= self.deadline:
                    raise DeadlineReached(resp.status_code, method, path, resp.text)
                log.warning("429 on %s %s, sleeping %.1fs", method, path, wait)
                self._sleep(wait)
                continue
            break
        if resp.status_code == 404 and allow_404:
            return None
        if resp.status_code >= 400:
            raise DiscourseError(resp.status_code, method, path, resp.text)
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -- topics / posts ------------------------------------------------------
    def get_topic_by_external_id(self, external_id: str) -> dict | None:
        """Topic JSON (with post_stream) or None. Discourse redirects to /t/<slug>/<id>.json."""
        return self.request(
            "GET", f"/t/external_id/{external_id}.json", allow_404=True, follow_redirects=True
        )

    def get_post(self, post_id: int) -> dict:
        return self.request("GET", f"/posts/{post_id}.json")

    def create_topic(
        self,
        *,
        title: str,
        raw: str,
        category: int,
        external_id: str | None = None,
        tags: list[str] | None = None,
        **extra: Any,
    ) -> dict:
        payload: dict[str, Any] = {"title": title, "raw": raw, "category": category}
        if external_id:
            payload["external_id"] = external_id
        if tags:
            payload["tags[]"] = tags
        payload.update(extra)
        return self.request("POST", "/posts.json", data=payload)

    def edit_first_post(
        self,
        post_id: int,
        raw: str,
        *,
        topic_id: int | None = None,
        title: str | None = None,
        edit_reason: str | None = None,
    ) -> dict:
        data = {"post[raw]": raw}
        if edit_reason:
            data["post[edit_reason]"] = edit_reason
        result = self.request("PUT", f"/posts/{post_id}.json", data=data)
        if title is not None and topic_id is not None:
            self.request("PUT", f"/t/-/{topic_id}.json", data={"title": title})
        return result

    def change_timestamp(self, topic_id: int, timestamp: int | float) -> dict:
        """PUT /t/:topic_id/change-timestamp (staff only); ``timestamp`` is unix seconds and must
        not be in the future. Shifts the first post (and replies relatively) and resets bumped_at."""
        return self.request("PUT", f"/t/{topic_id}/change-timestamp", data={"timestamp": str(int(timestamp))})

    def create_post(self, topic_id: int, raw: str) -> dict:
        """Reply to an existing topic (staff can reply in closed topics)."""
        return self.request("POST", "/posts.json", data={"topic_id": topic_id, "raw": raw})

    def release_urls(self, topic_id: int) -> set[str]:
        """Exact release headings reconcile posts whose state save was interrupted."""
        topic = self.request("GET", f"/t/{topic_id}.json")
        stream = topic["post_stream"]["stream"]
        urls = set()
        for offset in range(0, len(stream), 20):
            if self.deadline is not None and time.monotonic() >= self.deadline:
                raise DeadlineReached(0, "GET", f"/t/{topic_id}/posts.json", "run deadline reached")
            posts = self.request("GET", f"/t/{topic_id}/posts.json",
                                 params={"post_ids[]": stream[offset:offset + 20]})["post_stream"]["posts"]
            for post in posts:
                if post.get("hidden") or post.get("deleted_at"):
                    continue
                parser = _ReleaseHeadingLinks()
                parser.feed(post.get("cooked", ""))
                urls.update(parser.urls)
        return urls

    def set_topic_status(self, topic_id: int, status: str, enabled: bool) -> dict:
        """status: closed | pinned | archived | visible."""
        return self.request("PUT", f"/t/{topic_id}/status.json",
                            data={"status": status, "enabled": "true" if enabled else "false"})

    def find_topic_by_title(self, category_id: int, title: str) -> int | None:
        # /c/{id}.json redirects to the slug URL, which the client does not follow
        topics = self.request("GET", "/latest.json", params={"category": category_id, "no_subcategories": "true"})["topic_list"]["topics"]
        exact = next((t["id"] for t in topics if t["title"] == title), None)
        if exact:
            return exact
        # Discourse capitalises the first letter ("Mumble-voip/mumble releases"); accept that when
        # exactly one topic in the category matches ignoring case.
        loose = [t["id"] for t in topics if t["title"].casefold() == title.casefold()]
        return loose[0] if len(loose) == 1 else None

    def list_categories(self) -> list[dict]:
        """All categories, subcategories included (flat, with parent_category_id).

        /site.json is not used: with lazy_load_categories it omits most categories. With
        include_subcategories this endpoint lists every category flat; it may paginate, so read pages
        until one adds nothing new."""
        seen: dict[int, dict] = {}
        page = 1
        while True:
            cats = self.request("GET", "/categories.json",
                                params={"include_subcategories": "true", "page": page})["category_list"]["categories"]
            new = [c for c in cats if c["id"] not in seen]
            if not new:
                break
            seen.update((c["id"], c) for c in new)
            page += 1
        return list(seen.values())

    def find_category(self, name: str, parent_category_id: int) -> dict | None:
        """The subcategory of ``parent_category_id`` named exactly ``name``, or None.

        list_categories() does not see every subcategory once a parent has hundreds of them, so a
        category a timed-out run created can be missing from it; this asks the server directly."""
        # Discourse routes category search as POST (a GET returns the category index); results are
        # prefix matches in pages of up to 25, so an exact match can sit past the first page.
        for page in range(1, 21):
            found = self.request("POST", "/categories/search.json",
                                 data={"term": name, "parent_category_id": parent_category_id,
                                       "include_subcategories": "true", "page": page})
            rows = (found.get("categories") if isinstance(found, dict) else None) or []
            for c in rows:
                if c.get("name") == name and c.get("parent_category_id") == parent_category_id:
                    return c
            if not rows:
                break
        return None

    def create_category(
        self, name: str, parent_category_id: int | None = None, *, create_post_groups: list[str] | None = None
    ) -> dict:
        """Everyone sees (read-only); staff, and so the bot, create and reply. The API user must be staff."""
        data: dict[str, Any] = {"name": name, "color": "0088CC", "text_color": "FFFFFF",
                                "permissions[everyone]": 3, "permissions[staff]": 1}
        if parent_category_id:
            data["parent_category_id"] = parent_category_id
        for group in create_post_groups or []:
            data[f"permissions[{group}]"] = 2
        return self.request("POST", "/categories.json", data=data)["category"]

    # -- groups / defaults ----------------------------------------------------
    def get_group(self, name: str) -> dict | None:
        found = self.request("GET", f"/groups/{name}.json", allow_404=True)
        return found["group"] if found else None

    def get_app_icon(self, reference: str) -> str | None:
        app = self.request("GET", f"/hhf-apps/apps/{reference}.json", allow_404=True)
        return app.get("icon_url") if app else None

    def ensure_group(self, name: str, full_name: str, *, flair_upload_id: int | None = None) -> dict:
        """Get the group, or create it public and self-join; members watch categories by default and
        admins may message it (the release DM)."""
        found = self.get_group(name)
        if found:
            return found
        data = {"group[name]": name, "group[full_name]": full_name, "group[visibility_level]": 0,
                "group[public_admission]": "true", "group[public_exit]": "true",
                "group[default_notification_level]": 3,
                "group[messageable_level]": GROUP_MESSAGEABLE_BY_ADMINS}
        if flair_upload_id:
            data["group[flair_upload_id]"] = flair_upload_id
        return self.request("POST", "/admin/groups.json", data=data)["basic_group"]

    def list_groups(self, prefix: str, *, deadline: float | None = None) -> list[dict]:
        """Every group whose name starts with ``prefix``, following /groups.json pages.

        Stops at an empty page, at a page that adds no group it has not seen (so a server that
        repeats its last page cannot keep it paging), or once ``deadline`` (time.monotonic) passes."""
        found: dict[str, dict] = {}
        for page in range(1000):
            if deadline is not None and time.monotonic() >= deadline:
                break
            rows = self.request("GET", "/groups.json", params={"filter": prefix, "page": page}).get("groups") or []
            new = [g for g in rows if g.get("name") and g["name"] not in found]
            if not new:
                break
            found.update((g["name"], g) for g in new)
        return [g for g in found.values() if g["name"].startswith(prefix)]

    def update_group(self, group_id: int, *, full_name: str | None = None, flair_upload_id: int | None = None,
                     messageable_level: int | None = None) -> None:
        data = {}
        if messageable_level is not None:
            data["group[messageable_level]"] = messageable_level
        if full_name is not None:
            data["group[full_name]"] = full_name
        if flair_upload_id is not None:
            data["group[flair_upload_id]"] = flair_upload_id
        if data:
            self.request("PUT", f"/groups/{group_id}.json", data=data)

    def watch_category_for_group(self, group_name: str, category_id: int) -> None:
        """Add the category to the group's Watching list, keeping the ones it already has."""
        group = self.request("GET", f"/groups/{group_name}.json")["group"]
        ids = list(group.get("watching_category_ids") or [])
        if category_id in ids:
            return
        self.request("PUT", f"/groups/{group['id']}.json",
                     data={"group[watching_category_ids][]": [*ids, category_id], "update_existing_users": "true"})

    def mute_categories_by_default(self, category_ids: list[int]) -> None:
        """Add the ids to the default_categories_muted site setting (pipe list), keeping the existing ones."""
        settings = self.request("GET", "/admin/site_settings.json")["site_settings"]
        current = next((s["value"] for s in settings if s["setting"] == "default_categories_muted"), "") or ""
        ids = [int(i) for i in str(current).split("|") if i]
        merged = ids + [i for i in category_ids if i not in ids]
        if merged == ids:
            return
        self.request("PUT", "/admin/site_settings/default_categories_muted.json",
                     data={"default_categories_muted": "|".join(map(str, merged)), "update_existing_user": "true"})

    # -- uploads / categories -------------------------------------------------
    def upload_file(self, filename: str, content: bytes, upload_type: str = "composer") -> dict:
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return self.request(
            "POST",
            "/uploads.json",
            data={"type": upload_type, "synchronous": "true"},
            files={"file": (filename, content, ctype)},
        )

    def get_category(self, category_id: int) -> dict:
        return self.request("GET", f"/c/{category_id}/show.json")["category"]

    def update_category(self, category_id: int, **fields: Any) -> dict:
        """PUT /categories/{id}.json. ``name`` is required by Discourse, so the
        current one is fetched when the caller does not pass it."""
        if "name" not in fields:
            fields["name"] = self.get_category(category_id)["name"]
        return self.request("PUT", f"/categories/{category_id}.json", data=fields)


# Methods that are safe to resend after a timeout. Every PUT/DELETE this client makes sets a value
# rather than adding one, so sending it twice leaves the same result.
_IDEMPOTENT = frozenset({"GET", "HEAD", "PUT", "DELETE"})
# Seconds before the first transport retry; later retries wait proportionally longer.
_TRANSPORT_BACKOFF = 5.0


def _retry_after(resp: httpx.Response) -> float:
    raw = resp.headers.get("Retry-After")
    try:
        return max(0.0, min(float(raw), 300.0)) if raw is not None else 5.0
    except ValueError:
        return 5.0
