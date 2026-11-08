#!/usr/bin/env python3
"""Read-only probe: application-data directories with no visible owner.

This is a maintainer tool, not part of `sweep`. It answers the question the
`if-missing-owner` design turn needs before it can name a threshold: for every
direct child of the four XDG roots and every Flatpak application id, is there an
installed application, a package, or a catalog rule that still names it?

No writes and no sudo. The output is TSV, largest first, so the whole report can
be pasted into an issue. A row with empty `exec`, `pkg`, `flatpak` and `covered`
columns has no owner evidence in this probe; it is a candidate, not a verdict.

Evidence columns:

- `exec`    the desktop entry that matched has an `Exec` binary on PATH
- `pkg`     that desktop entry is owned by an installed pacman package
- `flatpak` the data directory is a Flatpak application id that is installed
- `bin`     the directory name resolves to a command on PATH (`pnpm`, `yay`)
- `desktop` the desktop entry that matched (heuristic, shown so it can be judged)
- `covered` a catalog rule names this exact path (a blanket parent rule does
            not count: `user.cache.residual` covers `{cache}` but owns nothing)

`exec` is the strong form of "the application is installed": a stale desktop
file left behind by a removed package has no binary. `pkg` is the strong form
of "a package still ships this entry". Neither proves the *data* is disposable;
that is the design turn's job.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

XDG_ROOTS = (".config", ".local/share", ".local/state", ".cache")


def run(command: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run a read-only command, or return None when the tool is absent."""
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None


def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def exec_binary(value: str) -> str:
    """The binary an `Exec=` line would start, with field codes removed."""
    words = value.split()
    if words and words[0] == "env":
        words = words[1:]
        while words and "=" in words[0] and not words[0].startswith("/"):
            words = words[1:]
    if not words:
        return ""
    return words[0].strip('"' + "'")


@dataclass
class DesktopEntry:
    path: str
    execs: list[str]
    tokens: list[str]


def desktop_entries() -> list[DesktopEntry]:
    directories = [
        Path("/usr/share/applications"),
        Path.home() / ".local/share/applications",
        Path("/var/lib/flatpak/exports/share/applications"),
        Path.home() / ".local/share/flatpak/exports/share/applications",
    ]
    entries: list[DesktopEntry] = []
    for directory in directories:
        if not directory.is_dir():
            continue
        for entry in sorted(directory.glob("*.desktop")):
            try:
                text = entry.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            execs: list[str] = []
            tokens: list[str] = [entry.stem]
            for line in text.splitlines():
                key, separator, value = line.partition("=")
                if not separator:
                    continue
                key = key.strip()
                value = value.strip().strip('"')
                if key == "Exec":
                    binary = exec_binary(value)
                    if binary:
                        execs.append(binary)
                        tokens.append(Path(binary).name)
                elif key in {"StartupWMClass", "X-Flatpak", "Name"}:
                    tokens.append(value)
            entries.append(
                DesktopEntry(
                    path=str(entry),
                    execs=execs,
                    tokens=[token for token in tokens if token],
                )
            )
    return entries


def similarity(left: str, right: str) -> int:
    if left == right:
        return 1000
    prefix = 0
    for a, b in zip(left, right):
        if a != b:
            break
        prefix += 1
    score = prefix
    if len(left) >= 6 and left in right:
        score = max(score, len(left))
    if len(right) >= 6 and right in left:
        score = max(score, len(right))
    return score


def desktop_match(name: str, entries: list[DesktopEntry]) -> DesktopEntry | None:
    token = normalize(name)
    if not token:
        return None
    best: DesktopEntry | None = None
    best_score = 0
    for entry in entries:
        for candidate in entry.tokens:
            score = similarity(token, normalize(candidate))
            if score > best_score:
                best = entry
                best_score = score
    return best if best_score >= 5 else None


def binary_installed(binary: str) -> bool:
    if not binary:
        return False
    if os.path.isabs(binary):
        return os.access(binary, os.X_OK)
    return shutil.which(binary) is not None


def package_owner(path: str) -> str:
    result = run(["pacman", "-Qqo", path])
    if result is None or result.returncode != 0:
        return ""
    return result.stdout.strip()


def flatpak_apps(home: Path) -> set[str]:
    """Installed Flatpak application ids, read from the deployment directories.

    `flatpak list` is not used: on a machine with no user installation it can
    create `~/.local/share/flatpak` while answering, and this probe promises no
    writes.
    """
    apps: set[str] = set()
    for base in (Path("/var/lib/flatpak/app"), home / ".local/share/flatpak/app"):
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            if entry.is_dir():
                apps.add(entry.name)
    return apps


def sweep_binary(explicit: str | None) -> str:
    if explicit:
        return explicit
    found = shutil.which("sweep")
    if found:
        return found
    candidate = Path(__file__).resolve().parent.parent / "target" / "debug" / "sweep"
    return str(candidate)


def covered_roots(sweep: str) -> list[tuple[str, str]]:
    result = run([sweep, "rules", "list", "--json"])
    if result is None or result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return [
        (rule["id"], rule["resolved_root"])
        for rule in data.get("rule", [])
        if rule.get("enabled") and rule.get("resolved_root")
    ]


def covering_rule(path: Path, roots: list[tuple[str, str]]) -> str:
    """The dedicated rule for this exact path, if there is one.

    A rule whose root is a parent (`user.cache.residual` at `{cache}`,
    `user.windows-metadata` at `{home}`) is not evidence: it is the blanket
    scan this probe is trying to see past.
    """
    value = str(path)
    for rule_id, root in roots:
        if "*" in root or "?" in root:
            if fnmatch.fnmatch(value, root):
                return rule_id
        elif value == root:
            return rule_id
    return ""


def bin_evidence(name: str) -> str:
    """A command with the directory's name, for tools that ship no desktop file."""
    base = name.lower().replace(" ", "-")
    for candidate in (base, base + "-bin", base + "-launcher", base + "-agent", base + "-run"):
        found = shutil.which(candidate)
        if found:
            return found
    return ""


def directory_size(path: Path) -> int:
    result = run(["du", "-sb", str(path)])
    if result is None or result.returncode != 0:
        return 0
    try:
        return int(result.stdout.split()[0])
    except (IndexError, ValueError):
        return 0


def candidates(home: Path):
    for root in XDG_ROOTS:
        base = home / root
        if not base.is_dir():
            continue
        for entry in sorted(base.iterdir()):
            if entry.is_dir() and not entry.is_symlink():
                yield root, entry.name, entry
    flatpak_root = home / ".var/app"
    if flatpak_root.is_dir():
        for entry in sorted(flatpak_root.iterdir()):
            if entry.is_dir() and not entry.is_symlink():
                yield ".var/app", entry.name, entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--min-bytes",
        type=int,
        default=1 << 20,
        help="skip directories smaller than this many bytes (default: 1 MiB)",
    )
    parser.add_argument(
        "--sweep",
        default=None,
        help="sweep binary used to read the catalog (default: sweep on PATH, then target/debug/sweep)",
    )
    args = parser.parse_args()

    home = Path.home()
    entries = desktop_entries()
    apps = flatpak_apps(home)
    roots = covered_roots(sweep_binary(args.sweep))
    owner_cache: dict[str, str] = {}

    rows: list[tuple[Path, int, float, str, str, str, str, str, str]] = []
    for root, name, path in candidates(home):
        size = directory_size(path)
        if size < args.min_bytes:
            continue
        entry = desktop_match(name, entries)
        desktop = entry.path if entry else ""
        exec_found = ""
        package = ""
        if entry:
            for binary in entry.execs:
                if binary_installed(binary):
                    exec_found = binary
                    break
            if desktop not in owner_cache:
                owner_cache[desktop] = package_owner(desktop)
            package = owner_cache[desktop]
        flatpak = "yes" if root == ".var/app" and name in apps else ""
        binary = bin_evidence(name)
        covered = covering_rule(path, roots)
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        rows.append(
            (path, size, mtime, exec_found, package, flatpak, binary, desktop, covered)
        )

    rows.sort(key=lambda row: row[1], reverse=True)

    print(f"# probe: {len(rows)} directories >= {args.min_bytes} bytes")
    print(f"# home: {home}")
    print(
        f"# desktop entries: {len(entries)}; flatpak apps: {len(apps)}; "
        f"catalog roots: {len(roots)}"
    )
    print("path\tbytes\tmtime\texec\tpkg\tflatpak\tbin\tdesktop\tcovered")
    for path, size, mtime, exec_found, package, flatpak, binary, desktop, covered in rows:
        print(
            f"{path}\t{size}\t{int(mtime)}\t{exec_found}\t{package}\t"
            f"{flatpak}\t{binary}\t{desktop}\t{covered}"
        )

    no_evidence = sum(
        1
        for row in rows
        if not row[3] and not row[4] and not row[5] and not row[6] and not row[8]
    )
    total = sum(row[1] for row in rows)
    print(f"# no owner evidence: {no_evidence} of {len(rows)}")
    print(f"# bytes in report: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
