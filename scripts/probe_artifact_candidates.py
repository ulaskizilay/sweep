#!/usr/bin/env python3
"""Read-only probe: the two artifact candidates that need a decision.

This is a maintainer tool, not part of `sweep`. It answers the question two
queue items need before either can change: how large are they on a real machine,
and how is that size distributed by age? It walks, `stat`s and reads one config
file. No writes, no sudo, no deletion, and a bounded walk so it finishes in
seconds.

The decisions are fixed before the sample arrives, so the numbers cannot be read
backwards into the answer they are supposed to inform:

- `dev.ccache` (`{cache}/ccache`) already exists as a `dir-sweep`: every `clean`
  empties it, so the next build starts cold. Switch it to `dir-age` only if the
  directory holds at least **500 MiB** and at least **25% of those bytes are
  newer than 7 days**. Below that share the hot set is too small to be worth a
  second retention policy and `dir-sweep` already matches the data. If
  `ccache.conf` declares a `max_size`, the tool bounds itself and the finding is
  "leave it alone, advise `ccache --trim`": sweep does not run a tool's own cache
  command.
- `project .cxx` (Android NDK intermediates): add a `project-artifacts` rule
  (`requires: JVM`) only if **three or more** user-project directories hold one,
  together at least **1 GiB**, and the newest file in each is older than
  **7 days**. A `.cxx` inside a package cache (`~/.pub-cache`, `~/.gradle`,
  `~/.m2`, `~/.cache`) is not a user project and does not count: the cache rule
  that owns the parent already takes it.

Output is TSV, largest first, so the whole report can be pasted into an issue.
`#` lines are the header and the totals; a reader can ignore them or keep them.

Columns:

- `bytes`   accounted bytes (`st_blocks * 512`, the number `du` reports)
- `entries` files and directories counted, excluding the root itself
- `newest`  days since the newest file below the root, as an integer
- `jvm`     a JVM manifest sits in the directory that holds the artifact
- `cache`   the artifact is inside a package or tool cache, not a user project
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

JVM_MANIFESTS = {
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "pom.xml",
}

# Trees that hold other tools' caches or installed software. They are walked only
# far enough to classify a `.cxx` found inside them, never treated as a user
# project, and never descended into for new projects.
CACHE_MARKERS = (
    "/.cache/",
    "/.gradle/",
    "/.m2/",
    "/.pub-cache/",
    "/.local/share/",
    "/.var/app/",
    "/node_modules/",
)

# Names that cannot contain a user's project. Skipping them keeps the walk to
# seconds on a machine with large toolchain and installed-software trees. Cache
# trees are *not* skipped: a `.cxx` inside one is tagged `cache=yes` instead,
# because "the only copy is a package cache" is the finding the probe has to be
# able to show.
NEVER_WALK = {
    ".cargo",
    ".git",
    ".local",
    ".rustup",
    ".var",
    "node_modules",
    "target",
}

DAY = 86_400


@dataclass
class Measure:
    bytes: int = 0
    entries: int = 0
    newest: float = 0.0
    oldest: float = 0.0
    hot: int = 0  # <= 7 days
    warm: int = 0  # 8-30 days
    cold: int = 0  # > 30 days
    truncated: bool = False


class Budget:
    def __init__(self, max_entries: int, seconds: float) -> None:
        self.left = max_entries
        self.deadline = time.monotonic() + seconds
        self.hit = False

    def charge(self) -> bool:
        if self.left <= 0 or time.monotonic() >= self.deadline:
            self.hit = True
            return False
        self.left -= 1
        return True


def measure(root: Path, budget: Budget, now: float) -> Measure:
    """Sums `st_blocks` below `root` without following a link or writing."""
    out = Measure()
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            children = list(os.scandir(directory))
        except OSError:
            continue
        for child in children:
            if not budget.charge():
                out.truncated = True
                return out
            try:
                meta = child.stat(follow_symlinks=False)
            except OSError:
                continue
            if child.is_symlink():
                continue
            size = meta.st_blocks * 512
            out.entries += 1
            out.bytes += size
            out.newest = max(out.newest, meta.st_mtime)
            out.oldest = meta.st_mtime if not out.oldest else min(out.oldest, meta.st_mtime)
            age = now - meta.st_mtime
            if age <= 7 * DAY:
                out.hot += size
            elif age <= 30 * DAY:
                out.warm += size
            else:
                out.cold += size
            if child.is_dir(follow_symlinks=False):
                stack.append(child.path)
    return out


def is_cache(path: Path) -> bool:
    value = f"{path}/"
    return any(marker in value for marker in CACHE_MARKERS)


def jvm_manifest(path: Path) -> bool:
    try:
        return any((path / name).is_file() for name in JVM_MANIFESTS)
    except OSError:
        return False


def find_cxx(home: Path, depth: int, budget: Budget) -> list[Path]:
    """Every directory named `.cxx` below `home`, at most `depth` levels down."""
    found: list[Path] = []
    stack: list[tuple[Path, int]] = [(home, 0)]
    while stack:
        directory, level = stack.pop()
        if not budget.charge():
            return found
        try:
            children = list(os.scandir(directory))
        except OSError:
            continue
        for child in children:
            if not child.is_dir(follow_symlinks=False) or child.is_symlink():
                continue
            if child.name == ".cxx":
                found.append(Path(child.path))
                continue
            if child.name in NEVER_WALK or level + 1 >= depth:
                continue
            stack.append((Path(child.path), level + 1))
    return found


def ccache_report(cache: Path, budget: Budget, now: float) -> None:
    root = cache / "ccache"
    if not root.is_dir() or root.is_symlink():
        print("# ccache: absent")
        return
    found = measure(root, budget, now)
    config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    config = Path(config_home) / "ccache" / "ccache.conf"
    max_size = ""
    try:
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == "max_size":
                max_size = value.strip()
    except OSError:
        pass
    newest = int((now - found.newest) // DAY) if found.newest else -1
    oldest = int((now - found.oldest) // DAY) if found.oldest else -1
    print(f"# ccache: {root}")
    print(f"# ccache max_size: {max_size or 'not declared'}")
    print(
        f"# ccache total: {found.bytes} bytes, {found.entries} entries, "
        f"newest {newest}d, oldest {oldest}d"
        f"{', walk truncated' if found.truncated else ''}"
    )
    print(
        f"# ccache age: hot(<=7d) {found.hot}, warm(8-30d) {found.warm}, "
        f"cold(>30d) {found.cold}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--min-bytes",
        type=int,
        default=1 << 20,
        help="skip .cxx directories smaller than this many bytes (default: 1 MiB)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=6,
        help="project-discovery depth below $HOME (default: 6, the catalog default)",
    )
    parser.add_argument(
        "--max-entries",
        type=int,
        default=2_000_000,
        help="entry budget for the whole probe (default: 2,000,000)",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=30.0,
        help="wall-clock budget for the whole probe (default: 30)",
    )
    args = parser.parse_args()

    home = Path.home()
    now = time.time()
    budget = Budget(args.max_entries, args.seconds)

    print(f"# probe: artifact candidates below {home}")
    print(
        "# thresholds: ccache >= 500 MiB and >= 25% newer than 7d; "
        ".cxx >= 3 user projects, >= 1 GiB, newest > 7d"
    )

    ccache_report(home / ".cache", budget, now)

    rows: list[tuple[Path, Measure, bool, bool]] = []
    for path in find_cxx(home, args.max_depth, budget):
        found = measure(path, budget, now)
        if found.bytes < args.min_bytes:
            continue
        rows.append((path, found, jvm_manifest(path.parent), is_cache(path)))
    rows.sort(key=lambda row: row[1].bytes, reverse=True)

    print("path\tbytes\tentries\tnewest\tjvm\tcache")
    for path, found, jvm, cache in rows:
        newest = int((now - found.newest) // DAY) if found.newest else -1
        print(
            f"{path}\t{found.bytes}\t{found.entries}\t{newest}\t"
            f"{'yes' if jvm else 'no'}\t{'yes' if cache else 'no'}"
        )

    user_projects = [row for row in rows if not row[3]]
    user_bytes = sum(row[1].bytes for row in user_projects)
    print(f"# .cxx: {len(rows)} directories >= {args.min_bytes} bytes")
    print(f"# .cxx user projects: {len(user_projects)}, {user_bytes} bytes")
    print(f"# entry budget left: {budget.left}{', walk truncated' if budget.hit else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
