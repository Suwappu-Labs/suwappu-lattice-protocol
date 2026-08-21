#!/usr/bin/env python3
"""Transform docs/WHITEPAPER.md into pandoc-ready Markdown for the PDF build.

The Markdown source is written for GitHub/GitBook: it opens with a centered
HTML block, carries a hand-maintained link TOC, and uses emoji as table
verdicts. None of that belongs in a typeset paper. This script rewrites those
three things and leaves everything else — prose, tables, math, code — alone.

What it does, in order:
  1. Drops the leading ``<div align="center">`` masthead (title, tagline,
     metadata table). LaTeX rebuilds it from the metadata in build.sh.
  2. Lifts the Abstract out of the body so it can go in an abstract
     environment ahead of the table of contents. Written to a side file.
  3. Drops the hand-written link TOC; LaTeX generates its own.
  4. Substitutes emoji and a few glyphs that have no place in (or no glyph
     for) a typeset paper: ✅/❌ become Yes/No, ⚠ becomes a bold Note.

Usage:  preprocess.py <in.md> <out.md> <abstract.tex>
"""

from __future__ import annotations

import re
import sys

# Emoji → typeset equivalents. The verdict marks appear in verification
# tables where "Yes"/"No" is clearer in print than a colored glyph anyway.
#
# The super/subscripts below (GF(2⁸), the c₀/d₁ chunk names) are Unicode
# characters that the text font has no glyph for; LaTeX's own super/subscript
# commands render them properly. Verified to occur only outside math mode —
# inside $...$ they would need ^{}/_{} instead.
GLYPHS = {
    "✅": r"\textbf{Yes}",
    "❌": r"\textbf{No}",
    "✓": r"\checkmark{}",
    "✗": r"$\times$",
    "⚠": r"\textbf{!}",
    "∎": r"$\square$",
    "⁸": r"\textsuperscript{8}",
    "²": r"\textsuperscript{2}",
    "³": r"\textsuperscript{3}",
    "₀": r"\textsubscript{0}",
    "₁": r"\textsubscript{1}",
    "₂": r"\textsubscript{2}",
}


def strip_masthead(text: str) -> str:
    """Remove the opening centered HTML block and its trailing rule."""
    if not text.lstrip().startswith("<div"):
        return text
    end = text.find("</div>")
    if end == -1:
        return text
    rest = text[end + len("</div>") :]
    # Drop the horizontal rule that followed the block.
    return re.sub(r"\A\s*-{3,}\s*", "", rest, count=1)


def lift_abstract(text: str) -> tuple[str, str]:
    """Pull the Abstract section out of the body.

    Returns (body_without_abstract, abstract_markdown). If the section is not
    found the body is returned unchanged and the abstract is empty — the build
    still succeeds, just without an abstract environment.
    """
    m = re.search(r"^## Abstract\s*$", text, flags=re.M)
    if not m:
        return text, ""
    start = m.start()
    # The abstract runs until the next top-level section heading.
    nxt = re.search(r"^## (?!Abstract)", text[m.end() :], flags=re.M)
    if not nxt:
        return text, ""
    end = m.end() + nxt.start()
    abstract = text[m.end() : end]
    # Trim the trailing horizontal rule that separated it from §1.
    abstract = re.sub(r"\s*-{3,}\s*\Z", "", abstract).strip()
    return text[:start] + text[end:], abstract


def strip_toc(text: str) -> str:
    """Remove the hand-maintained link TOC block."""
    m = re.search(r"^## Table of Contents\s*$", text, flags=re.M)
    if not m:
        return text
    # Runs until the first heading that is not part of the TOC scaffolding.
    nxt = re.search(r"^#{2,3} (?!Table of Contents)", text[m.end() :], flags=re.M)
    if not nxt:
        return text
    return text[: m.start()] + text[m.end() + nxt.start() :]


# CJK runs need a font the Latin text face cannot supply; wrap them in the
# preamble's \ltpcjktext{...} macro (a \command{...} form, not bare braces --
# pandoc's raw_tex extension only passes \command{...} through unescaped; a
# bare {\ltpcjk ...} group gets its braces escaped to \{ \}, which strips the
# scope and lets the font selection bleed into every paragraph after it).
CJK_RUN = re.compile(r"[　-〿぀-ヿ一-鿿＀-￯]+")

# Fenced code blocks, kept verbatim. ``` or ~~~, any info string.
FENCE = re.compile(r"^(?P<f>```+|~~~+)[^\n]*\n.*?^(?P=f)[ \t]*$", re.M | re.S)


def _substitute_prose(text: str) -> str:
    for glyph, replacement in GLYPHS.items():
        text = text.replace(glyph, replacement)
    return CJK_RUN.sub(lambda m: r"\ltpcjktext{" + m.group(0) + "}", text)


def substitute_glyphs(text: str) -> str:
    """Rewrite glyphs in prose only, never inside fenced code blocks.

    Code blocks carry published test vectors and ASCII diagrams: rewriting a
    subscript there would alter content an implementer is meant to reproduce
    byte-for-byte. It is also unnecessary — the monospace face (DejaVu Sans
    Mono) has the sub/superscript and box-drawing glyphs the text face lacks.
    """
    out, last = [], 0
    for m in FENCE.finditer(text):
        out.append(_substitute_prose(text[last : m.start()]))
        out.append(m.group(0))  # verbatim
        last = m.end()
    out.append(_substitute_prose(text[last:]))
    return "".join(out)


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst, abstract_path = sys.argv[1:4]

    text = open(src, encoding="utf-8").read()
    text = strip_masthead(text)
    text, abstract = lift_abstract(text)
    text = strip_toc(text)
    text = substitute_glyphs(text)
    abstract = substitute_glyphs(abstract)

    open(dst, "w", encoding="utf-8").write(text)
    open(abstract_path, "w", encoding="utf-8").write(abstract)

    print(f"    body     -> {dst} ({len(text.splitlines())} lines)")
    print(f"    abstract -> {abstract_path} ({len(abstract.split())} words)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
