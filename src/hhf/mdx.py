"""Fumadocs MDX -> Discourse markdown.

Pure functions, no network. Code fences and inline code are never touched.
"""

from __future__ import annotations

import posixpath
import re
import textwrap
from dataclasses import dataclass, field
from typing import Callable

import yaml

# --------------------------------------------------------------------------
# code protection
# --------------------------------------------------------------------------
_FENCE_OPEN = re.compile(r"^(\s*)(`{3,}|~{3,})")
_INLINE_CODE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.S)
_FENCE_PH = re.compile(r"^([ \t]*)\x01F(\d+)\x01[ \t]*$", re.M)
_INLINE_PH = re.compile(r"\x02I(\d+)\x02")


class _Protected:
    """Replace fenced blocks and inline code with placeholders, restore later."""

    def __init__(self, text: str):
        self.fences: list[str] = []
        self.inline: list[str] = []
        out: list[str] = []
        lines = text.split("\n")
        i = 0
        while i < len(lines):
            m = _FENCE_OPEN.match(lines[i])
            if not m:
                out.append(lines[i])
                i += 1
                continue
            indent, marker = m.group(1), m.group(2)
            j = i + 1
            close = re.compile(r"^\s*" + re.escape(marker[0]) + "{" + str(len(marker)) + r",}\s*$")
            while j < len(lines) and not close.match(lines[j]):
                j += 1
            block = lines[i : j + 1]
            block = [ln[len(indent):] if ln.startswith(indent) else ln.lstrip() for ln in block]
            self.fences.append("\n".join(block))
            out.append(f"{indent}\x01F{len(self.fences) - 1}\x01")
            i = j + 1
        text = "\n".join(out)

        def stash(m: re.Match) -> str:
            self.inline.append(m.group(0))
            return f"\x02I{len(self.inline) - 1}\x02"

        self.text = _INLINE_CODE.sub(stash, text)

    def restore(self, text: str) -> str:
        def fence(m: re.Match) -> str:
            indent = m.group(1)
            body = self.fences[int(m.group(2))]
            return "\n".join(indent + ln if ln else ln for ln in body.split("\n"))

        text = _FENCE_PH.sub(fence, text)
        return _INLINE_PH.sub(lambda m: self.inline[int(m.group(1))], text)


# --------------------------------------------------------------------------
# frontmatter
# --------------------------------------------------------------------------
_FM = re.compile(r"\A﻿?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.S)


def split_frontmatter(source: str) -> tuple[dict, str]:
    m = _FM.match(source)
    if not m:
        return {}, source
    try:
        data = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        data = {}
    return (data if isinstance(data, dict) else {}), source[m.end():]


# --------------------------------------------------------------------------
# import / export / comments
# --------------------------------------------------------------------------
_IMPORT = re.compile(r"^\s*import\s+(?:[\w*{}\s,$]+\s+from\s+)?['\"][^'\"]+['\"]\s*;?\s*$")
_EXPORT = re.compile(r"^\s*export\s+(?:default\b|const\b|let\b|var\b|function\b|async\b|\{|\*)")
_JSX_COMMENT = re.compile(r"\{/\*.*?\*/\}", re.S)


def _balance(s: str) -> int:
    return sum(s.count(c) for c in "{([") - sum(s.count(c) for c in "})]")


_CONST = re.compile(r"""^\s*export\s+const\s+(\w+)\s*=\s*(['"])(.*?)\2\s*;?\s*$""")


def strip_esm(text: str, consts: dict[str, str] | None = None) -> str:
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        ln = lines[i]
        if _IMPORT.match(ln):
            i += 1
        elif _EXPORT.match(ln):
            cm = _CONST.match(ln)
            if cm and consts is not None:
                consts[cm.group(1)] = cm.group(3)
            depth = _balance(ln)
            i += 1
            while depth > 0 and i < len(lines):
                depth += _balance(lines[i])
                i += 1
        else:
            out.append(ln)
            i += 1
    return "\n".join(out)


# --------------------------------------------------------------------------
# JSX tag scanner
# --------------------------------------------------------------------------
@dataclass
class Tag:
    name: str
    attrs: dict
    closing: bool
    selfclosing: bool
    start: int
    end: int
    raw: str


_NAME = re.compile(r"(/?)([A-Za-z][\w.:-]*)")
_ATTR = re.compile(r"[\w:@.$-]+")


def _scan_braces(s: str, i: int) -> int:
    """s[i] == '{'; return index after the matching '}' (-1 on failure)."""
    depth, quote = 0, None
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def parse_tag(s: str, i: int) -> Tag | None:
    m = _NAME.match(s, i + 1)
    if not m:
        return None
    pos, attrs = m.end(), {}
    while pos < len(s):
        while pos < len(s) and s[pos].isspace():
            pos += 1
        if pos >= len(s):
            return None
        if s[pos] == ">":
            return Tag(m.group(2), attrs, bool(m.group(1)), False, i, pos + 1, s[i : pos + 1])
        if s.startswith("/>", pos):
            return Tag(m.group(2), attrs, bool(m.group(1)), True, i, pos + 2, s[i : pos + 2])
        if m.group(1):  # closing tags take no attributes
            return None
        a = _ATTR.match(s, pos)
        if not a:
            return None
        pos, key, value = a.end(), a.group(0), True
        if pos < len(s) and s[pos] == "=":
            pos += 1
            if pos < len(s) and s[pos] in "\"'":
                end = s.find(s[pos], pos + 1)
                if end < 0:
                    return None
                value, pos = s[pos + 1 : end], end + 1
            elif pos < len(s) and s[pos] == "{":
                end = _scan_braces(s, pos)
                if end < 0:
                    return None
                value, pos = ("expr", s[pos + 1 : end - 1].strip()), end
            else:
                return None
        attrs[key] = value
    return None


def _attr_str(attrs: dict, *keys: str) -> str | None:
    for k in keys:
        v = attrs.get(k)
        if isinstance(v, str):
            return v
        if isinstance(v, tuple):
            m = re.fullmatch(r"""(["'`])(.*)\1""", v[1])
            if m:
                return m.group(2)
    return None


def _attr_list(attrs: dict, key: str) -> list[str]:
    v = attrs.get(key)
    if isinstance(v, tuple):
        return [a or b for a, b in re.findall(r"""'([^']*)'|"([^"]*)\"""", v[1])]
    return []


@dataclass
class Node:
    name: str
    attrs: dict
    children: list = field(default_factory=list)  # str | Node
    selfclosing: bool = False


KNOWN = {
    "Callout", "Tabs", "Tab", "Steps", "Step", "Cards", "Card", "Files", "Folder",
    "File", "Accordions", "Accordion",
}
_LAYOUT_HTML = {"div", "span", "section"}


def _is_jsxish(attrs: dict) -> bool:
    return any(k in ("className", "style") or isinstance(v, tuple) for k, v in attrs.items())


_DROP_ATTRS = {"style", "className", "class", "key"}


def _expr_value(expr: str, consts: dict[str, str]) -> str | None:
    m = re.fullmatch(r"""(["'])(.*)\1""", expr)
    if m:
        return m.group(2)
    m = re.fullmatch(r"`([^`]*)`", expr)
    if m:
        try:
            return re.sub(r"\$\{\s*(\w+)\s*\}", lambda x: consts[x.group(1)], m.group(1))
        except KeyError:
            return None
    return consts.get(expr)


def normalize_html(text: str, consts: dict[str, str], restore=lambda s: s) -> str:
    """Rewrite JSX-flavoured lowercase HTML tags (style={{..}}, src={`${x}/a.png`})
    as plain HTML. Layout wrappers (div/span/section) are unwrapped later."""
    out, pos, i = [], 0, 0
    while True:
        i = text.find("<", i)
        if i < 0:
            break
        t = parse_tag(text, i)
        if not t:
            i += 1
            continue
        i = t.end
        if t.closing or not t.name[0].islower() or t.name in _LAYOUT_HTML:
            continue
        if not any(k in _DROP_ATTRS or isinstance(v, tuple) for k, v in t.attrs.items()):
            continue
        attrs = []
        for k, v in t.attrs.items():
            if k in _DROP_ATTRS:
                continue
            if isinstance(v, tuple):
                v = _expr_value(restore(v[1]), consts)
                if v is None:
                    continue
            attrs.append(k if v is True else f'{k}="{v}"')
        out.append(text[pos : t.start])
        out.append(f"<{t.name}{' ' + ' '.join(attrs) if attrs else ''}{' /' if t.selfclosing else ''}>")
        pos = t.end
    out.append(text[pos:])
    return "".join(out)


def _build_tree(text: str) -> Node:
    tags: list[Tag] = []
    i = 0
    while True:
        i = text.find("<", i)
        if i < 0:
            break
        t = parse_tag(text, i)
        if t:
            tags.append(t)
            i = t.end
        else:
            i += 1
    closers = {t.name for t in tags if t.closing}

    def wanted(t: Tag) -> bool:
        if t.name in KNOWN:
            return True
        if t.name[0].isupper():
            return t.selfclosing or t.name in closers
        return t.name in _LAYOUT_HTML and (_is_jsxish(t.attrs) if not t.closing else True)

    root = Node("#root", {})
    stack = [root]
    pos = 0
    for t in tags:
        if not wanted(t):
            continue
        match_idx = None
        if t.closing:
            for k in range(len(stack) - 1, 0, -1):
                if stack[k].name == t.name:
                    match_idx = k
                    break
            if match_idx is None and t.name not in KNOWN and not t.name[0].isupper():
                continue  # closing tag of a plain HTML element we keep verbatim
        if t.start > pos:
            stack[-1].children.append(text[pos : t.start])
        pos = t.end
        if t.closing:
            if match_idx is not None:
                del stack[match_idx:]
        elif t.selfclosing:
            stack[-1].children.append(Node(t.name, t.attrs, selfclosing=True))
        else:
            n = Node(t.name, t.attrs)
            stack[-1].children.append(n)
            stack.append(n)
    if pos < len(text):
        stack[-1].children.append(text[pos:])
    return root


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------
_CALLOUT = {
    "info": "NOTE", "note": "NOTE", "default": "NOTE",
    "warn": "WARNING", "warning": "WARNING", "error": "WARNING", "danger": "WARNING",
    "caution": "WARNING", "important": "WARNING",
    "success": "TIP", "tip": "TIP",
}


def _block(s: str) -> str:
    return f"\n\n{s.strip(chr(10))}\n\n"


def _children_text(node: Node) -> str:
    """Render children; dedent plain text tokens by their common JSX indent."""
    texts = [c for c in node.children if isinstance(c, str)]
    indents = []
    for t in texts:
        for ln in t.split("\n")[1:]:
            if ln.strip():
                indents.append(len(ln) - len(ln.lstrip()))
    cut = min(indents) if indents else 0
    out = []
    for c in node.children:
        if isinstance(c, str):
            first, *rest = c.split("\n")
            rest = [ln[cut:] if ln[:cut].strip() == "" else ln.lstrip() for ln in rest]
            out.append("\n".join([first, *rest]))
        else:
            out.append(_render(c))
    return "".join(out)


def _inner(node: Node) -> str:
    return re.sub(r"\n{3,}", "\n\n", _children_text(node)).strip()


def _render(node: Node) -> str:
    n = node.name
    if n == "Callout":
        kind = _CALLOUT.get((_attr_str(node.attrs, "type") or "info").lower(), "NOTE")
        title = _attr_str(node.attrs, "title")
        head = f"> [!{kind}]" + (f" {title}" if title else "")
        body = _inner(node)
        lines = [head] + [("> " + ln).rstrip() for ln in body.split("\n")] if body else [head]
        return _block("\n".join(lines))
    if n == "Tabs":
        items = _attr_list(node.attrs, "items")
        parts, idx = [], 0
        for c in node.children:
            if isinstance(c, Node) and c.name == "Tab":
                label = (
                    _attr_str(c.attrs, "value", "label", "title")
                    or (items[idx] if idx < len(items) else f"Tab {idx + 1}")
                )
                idx += 1
                parts.append(f'[details="{label}"]\n{_inner(c)}\n[/details]')
            elif isinstance(c, Node):
                parts.append(_render(c))
        return _block("\n\n".join(parts))
    if n == "Tab":  # stray Tab outside Tabs
        label = _attr_str(node.attrs, "value", "label", "title") or "Tab"
        return _block(f'[details="{label}"]\n{_inner(node)}\n[/details]')
    if n == "Accordion":
        label = _attr_str(node.attrs, "title") or "Details"
        return _block(f'[details="{label}"]\n{_inner(node)}\n[/details]')
    if n == "Steps":
        steps = [c for c in node.children if isinstance(c, Node) and c.name == "Step"]
        if not steps:
            return _block(_inner(node))
        items = []
        for k, s in enumerate(steps, 1):
            body = _inner(s).split("\n")
            if body and body[0].startswith("#"):
                body[0] = "**" + body[0].lstrip("# ").strip() + "**"
            pad = " " * (len(str(k)) + 2)
            items.append(
                f"{k}. " + body[0] + "".join("\n" + (pad + ln if ln.strip() else "") for ln in body[1:])
            )
        return _block("\n\n".join(items))
    if n == "Step":
        return _block(_inner(node))
    if n == "Cards":
        cards = [_render(c) for c in node.children if isinstance(c, Node)]
        return _block("\n".join(c.strip() for c in cards))
    if n == "Card":
        title = _attr_str(node.attrs, "title") or ""
        href = _attr_str(node.attrs, "href")
        desc = _attr_str(node.attrs, "description") or _inner(node).replace("\n", " ")
        head = f"[{title}]({href})" if href else f"**{title}**"
        return "- " + head + (f" - {desc}" if desc else "") + "\n"
    if n == "Files":
        return _block(_inner(node))
    if n in ("Folder", "File"):
        name = _attr_str(node.attrs, "name") or ""
        if n == "File":
            return f"- {name}\n"
        kids = _inner(node)
        sub = "\n".join("  " + ln if ln.strip() else ln for ln in kids.split("\n")) if kids else ""
        return f"- **{name}/**\n" + (sub + "\n" if sub else "")
    # unknown component / layout wrapper: keep inner text
    return _children_text(node) if node.selfclosing is False else ""


# --------------------------------------------------------------------------
# images
# --------------------------------------------------------------------------
_MD_IMG = re.compile(r"!\[([^\]]*)\]\(\s*(<[^>]+>|[^)\s]+)((?:\s+\"[^\"]*\")?)\s*\)")
_HTML_IMG_SRC = re.compile(r"(<img\b[^>]*?\bsrc=)([\"'])([^\"']+)\2", re.I)


def is_relative_asset(src: str) -> bool:
    return not re.match(r"^(?:[a-z][a-z0-9+.-]*:|//|#|data:)", src, re.I)


def _rewrite_images(text: str, resolver: Callable[[str], str | None] | None, found: list[str]) -> str:
    def md(m: re.Match) -> str:
        src = m.group(2).strip("<>")
        if not is_relative_asset(src):
            return m.group(0)
        found.append(src)
        new = resolver(src) if resolver else None
        return f"![{m.group(1)}]({new or src}{m.group(3)})"

    def html(m: re.Match) -> str:
        src = m.group(3)
        if not is_relative_asset(src):
            return m.group(0)
        found.append(src)
        new = resolver(src) if resolver else None
        return f"{m.group(1)}{m.group(2)}{new or src}{m.group(2)}"

    return _HTML_IMG_SRC.sub(html, _MD_IMG.sub(md, text))


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
@dataclass
class Converted:
    title: str
    description: str
    body: str
    images: list[str]


def convert_mdx(
    source: str,
    *,
    fallback_title: str = "",
    image_resolver: Callable[[str], str | None] | None = None,
) -> Converted:
    fm, body = split_frontmatter(source.replace("\r\n", "\n"))
    title = str(fm.get("title") or "").strip()
    description = str(fm.get("description") or "").strip()

    prot = _Protected(body)
    consts: dict[str, str] = {}
    text = strip_esm(prot.text, consts)
    text = _JSX_COMMENT.sub("", text)
    text = normalize_html(text, consts, prot.restore)
    text = _render(_build_tree(text))
    images: list[str] = []
    text = _rewrite_images(text, image_resolver and (lambda s: image_resolver(prot.restore(s))), images)
    text = prot.restore(text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    # a leading H1 duplicating the topic title is redundant
    m = re.match(r"#\s+(.+?)\s*\n", text + "\n")
    if m:
        if not title:
            title = m.group(1).strip()
        if m.group(1).strip().lower() == (title or "").lower():
            text = text[m.end():].lstrip("\n")
    title = title or fallback_title
    if description:
        text = f"*{description}*\n\n{text}" if text else f"*{description}*"
    return Converted(title, description, text.strip() + "\n", images)


# -- links (second pass) -----------------------------------------------------
_MD_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*([^)\s]+)((?:\s+\"[^\"]*\")?)\s*\)")


def doc_slug(href: str, doc_path: str, docs_prefix: str = "/docs") -> tuple[str, str] | None:
    """Return (slug, fragment) for an internal docs link, else None.

    slug is relative to the docs root without extension ('' for the root)."""
    if re.match(r"^(?:[a-z][a-z0-9+.-]*:|//|#)", href, re.I):
        return None
    path, _, frag = href.partition("#")
    path = path.partition("?")[0]
    if path == docs_prefix or path.startswith(docs_prefix + "/"):
        slug = path[len(docs_prefix):]
    elif path.startswith("/"):
        return None
    else:
        if posixpath.splitext(path)[1] not in (".mdx", ".md", ""):
            return None
        base = posixpath.dirname(doc_path)
        slug = posixpath.normpath(posixpath.join(base, path))
        if slug.startswith(".."):
            return None
    slug = re.sub(r"\.mdx?$", "", slug.strip("/"))
    slug = re.sub(r"(^|/)index$", "", slug)
    return slug.strip("/"), frag


def rewrite_links(
    body: str, doc_path: str, known: dict[str, str], unresolved: list[str] | None = None
) -> str:
    """Map relative .mdx / /docs/... links to topic URLs. ``known`` maps a docs
    slug (see doc_slug) to the target topic URL."""
    prot = _Protected(body)

    def sub(m: re.Match) -> str:
        r = doc_slug(m.group(2), doc_path)
        if r is None:
            return m.group(0)
        slug, frag = r
        url = known.get(slug)
        if url is None:
            if unresolved is not None:
                unresolved.append(m.group(2))
            return m.group(0)
        return f"[{m.group(1)}]({url}{'#' + frag if frag else ''}{m.group(3)})"

    return prot.restore(_MD_LINK.sub(sub, prot.text))


_LEFTOVER = [
    re.compile(r"<[A-Z][A-Za-z0-9.]*[\s>/]"),
    re.compile(r"</[A-Z][A-Za-z0-9.]*>"),
    re.compile(r"\bclassName="),
    re.compile(r"style=\{\{"),
    re.compile(r"\{/\*"),
    re.compile(r"^\s*import\s.+from\s+['\"]", re.M),
]


def find_leftover_jsx(body: str) -> list[str]:
    prot = _Protected(body)
    hits = []
    for rx in _LEFTOVER:
        hits += [m.group(0).strip() for m in rx.finditer(prot.text)]
    return hits
