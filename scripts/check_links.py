#!/usr/bin/env python3
"""Check that every relative link, image and `<picture>` source resolves.

Documentation drift is the cheapest kind of lie to ship: a link to
`docs/SAFETY.md` that no longer exists still renders as a link, and a reviewer
who trusts the README never clicks it. The README's visuals are HTML `<img>` and
`<picture>` tags rather than markdown images, so a checker that only understands
`[text](target)` would silently stop covering the most visible part of the page.

Runs in CI and locally with `python3 scripts/check_links.py`.

Exit codes: 0 when every reference resolves, 1 otherwise.
"""

from __future__ import annotations

import pathlib
import re
import sys

SKIP_DIRS = {".git", "target", "fuzz", "node_modules"}

# `[text](target)` and `![alt](target)`. The naive pattern is deliberate: these
# documents are hand-written and a nested-bracket link is not worth the fragility
# of a full markdown parser here.
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

# `src="..."` and `href="..."` inside raw HTML in markdown.
ATTR = re.compile(r"""\b(?:src|href)=["']([^"']+)["']""")

# A `<picture>` picks a file per colour scheme via `srcset`.
SRCSET = re.compile(r"""\bsrcset=["']([^"']+)["']""")


def is_external(target: str) -> bool:
    return (
        not target
        or "://" in target
        or target.startswith("mailto:")
        or target.startswith("#")
        or target.startswith("<")
        or target.startswith("data:")
    )


def markdown_files(root: pathlib.Path) -> list[pathlib.Path]:
    return [
        path
        for path in root.rglob("*.md")
        if not any(part in SKIP_DIRS for part in path.parts)
    ]


def references(text: str):
    """Every path a reader's browser would try to load from this document."""
    for pattern in (LINK, ATTR, SRCSET):
        for match in pattern.finditer(text):
            target = match.group(1)
            # `srcset` may carry several candidates and a descriptor.
            for candidate in target.split(","):
                yield candidate.strip().split(" ")[0]


def main() -> int:
    root = pathlib.Path(".").resolve()
    files = markdown_files(root)
    if not files:
        print("no markdown files found", file=sys.stderr)
        return 1

    broken: list[str] = []
    checked = 0
    for path in sorted(files):
        text = path.read_text(encoding="utf-8")
        for target in references(text):
            if is_external(target):
                continue
            # Only the path part; `file.md#section` links to a file.
            target = target.split("#", 1)[0]
            if not target:
                continue
            checked += 1
            if not (path.parent / target).resolve().exists():
                broken.append(f"{path.relative_to(root)}: {target} -> missing")

    if broken:
        print(f"{len(broken)} broken reference(s):", file=sys.stderr)
        for item in broken:
            print(f"  {item}", file=sys.stderr)
        return 1

    print(f"all {checked} relative references resolve across {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
