from pathlib import Path

from hhf.mdx import convert_mdx, find_leftover_jsx, rewrite_links, split_frontmatter

SAMPLE = (Path(__file__).parent / "fixtures" / "docs" / "sample.mdx").read_text()


def conv(**kw):
    return convert_mdx(SAMPLE, **kw)


def test_frontmatter_title_description_and_intro():
    fm, body = split_frontmatter(SAMPLE)
    assert fm["title"] == "Sample Page" and body.lstrip().startswith("import")
    c = conv()
    assert c.title == "Sample Page"
    assert c.body.startswith("*A short intro*")
    assert "---" not in c.body.split("\n")[0]
    # duplicate H1 dropped
    assert "# Sample Page" not in c.body


def test_esm_and_comments_stripped():
    b = conv().body
    assert "fumadocs-ui" not in b.replace("'stripped'", "")
    assert "export const" not in b
    assert "JSX comment" not in b


def test_callouts():
    b = conv().body
    assert "> [!WARNING] Careful\n> Back up first." in b
    assert "> [!NOTE]\n> Plain note" in b
    assert "> [!TIP]\n> Nice tip" in b


def test_tabs_to_details_with_code():
    b = conv().body
    assert '[details="npm"]\nUse npm.\n[/details]' in b
    assert '[details="pnpm"]\nUse pnpm.\n\n```bash\npnpm install\n```\n[/details]' in b


def test_steps_numbered_and_code_untouched():
    b = conv().body
    assert "1. **Install**" in b
    assert "2. Configure it." in b
    # code fence content inside a step stays verbatim, indented under the item
    assert "   import { not } from 'stripped'\n   <Callout>untouched</Callout>" in b


def test_cards_bullets_and_unknown_component():
    b = conv().body
    assert "- [Guide](/docs/guide/intro) - Read the guide" in b
    assert "- [Ext](https://example.com)" in b
    assert "kept inner text" in b and "<Fancy>" not in b
    assert "wrapped" in b and "<div" not in b


def test_inline_code_and_literal_angle_text_preserved():
    b = conv().body
    assert "`<Callout>`" in b
    assert "<YOUR_TOKEN>" in b


def test_images_resolver_md_and_html():
    seen = []
    c = conv(image_resolver=lambda s: seen.append(s) or f"https://raw.test/{s.lstrip('./')}")
    assert "![shot](https://raw.test/shot.png)" in c.body
    assert "./shot.png" in seen
    assert "style=" not in c.body


def test_html_img_template_src_resolved_from_export_const():
    c = conv()
    assert '<img src="https://example.test/img/a.png" alt="a" />' in c.body


def test_no_leftover_jsx():
    assert find_leftover_jsx(conv().body) == []
    assert find_leftover_jsx("<Foo bar />") != []
    assert find_leftover_jsx("```\n<Foo bar />\n```") == []


def test_link_rewrite_second_pass():
    body = conv().body
    unresolved = []
    known = {"guide/intro": "/t/guide/7", "": "/t/home/1"}
    out = rewrite_links(body, "sample.mdx", known, unresolved)
    assert "[guide](/t/guide/7#top)" in out
    assert "[home](/t/home/1)" in out
    assert "[Guide](/t/guide/7)" in out  # card link too
    assert "`<Callout>`" in out and unresolved == []
    out2 = rewrite_links("[x](/docs/nope) [e](https://a.b)", "a.mdx", known, unresolved)
    assert out2 == "[x](/docs/nope) [e](https://a.b)" and unresolved == ["/docs/nope"]


def test_relative_links_resolve_against_doc_dir():
    out = rewrite_links("[a](../b/c.mdx) [i](./index.mdx)", "x/y/z.mdx", {"x/b/c": "/t/c/1", "x/y": "/t/y/2"})
    assert out == "[a](/t/c/1) [i](/t/y/2)"
