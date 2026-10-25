#!/usr/bin/env python3
"""Check that every relative link and image in the markdown docs resolves.

Documentation drift is the cheapest kind of lie to ship: a link to
`docs/SAFETY.md` that no longer exists still renders as a link, and a reviewer
who trusts the README never clicks it. This runs in CI and locally with
`python3 scripts/check_links.py`.

Exit codes: 0 when every link resolves, 1 otherwise.
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


def is_external(target: str) -> bool:
    return (
        not target
        or "://" in target
        or target.startswith("mailto:")
        or target.startswith("#")
        or target.startswith("<")
    )


def markdown_files(root: pathlib.Path) -> list[pathlib.Path]:
    return [
        path
        for path in root.rglob("*.md")
        if not any(part in SKIP_DIRS for part in path.parts)
    ]


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
        for match in LINK.finditer(text):
            target = match.group(1)
            if is_external(target):
                continue
            # Only the path part; `file.md#section` links to a file.
            target = target.split("#", 1)[0]
            if not target:
                continue
            checked += 1
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                broken.append(
                    f"{path.relative_to(root)}: {match.group(1)} -> missing"
                )

    if broken:
        print(f"{len(broken)} broken link(s):", file=sys.stderr)
        for item in broken:
            print(f"  {item}", file=sys.stderr)
        return 1

    print(f"all {checked} relative links resolve across {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
