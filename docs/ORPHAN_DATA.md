# Orphan application data

**Status:** the report-only `status` row is implemented. No rule kind exists and
no deletion path changes: `if-missing-owner` and the `pkg:` requirement are still
refused at load, as `docs/RULES.md` says.

## The question

`clean` removes caches a rule names. It does not remove a cache whose
application is gone: `~/.cache/SomeApp` is only reached by the blanket
`user.cache.residual` scan, which is age-gated and deliberately conservative.
`uninstall` already moves exact-name leftovers to the Trash after pacman
removes a package. This note is about data left by an application that was
removed some other way, or that never had a pacman package.

The product filter applies: a target that is not named by a rule needs
evidence that it is both disposable and unowned. "No evidence" must mean
"leave it", not "probably gone".

## What the probe measured

`scripts/probe_orphan_data.py` is read-only, needs no sudo, and takes about
five seconds. On 8 November 2026 it found 79 directories of at least 1 MiB
across the four XDG roots and `~/.var/app`; 25 had no owner evidence. They
fall into three groups:

1. **Real candidates.** `~/.cache/transcribe-venv` (6.7 GiB),
   `cursor-compile-cache` (174 MiB), `prisma` (91 MiB), `next-swc` (64 MiB),
   `node-gyp` (58 MiB), `winetricks` (38 MiB), `legendary` (6.0 MiB).
2. **Shared session caches.** `fontconfig`, `gtk-4.0`, `KDE`,
   `gstreamer-1.0`, `appstream`, `mesa_shader_cache`, `kactivitymanagerd`,
   `kdeconnect.app`, `logs`. They are not one application's data; removing
   them because no application "owns" them is a category error.
3. **Library caches.** `huggingface` (6.5 GiB) and `ms-playwright` (1.5 GiB)
   have no desktop file and no command on `PATH`. They are already partly
   addressed by named rules (`model.huggingface.hub`) and exclusions; they
   are not orphan-detection targets.

The desktop match is a heuristic and it does fail: `~/.cache/Google` matched
`google-maps-geo-handler.desktop`, and `~/.cache/flatpak` matched `shelly`.
The probe prints the matched entry instead of deciding. The `status` row uses a
match only to *leave the directory alone*, which is the safe direction: a false
match hides a candidate, it never deletes one.

## What each evidence source proves

| Source | Proves | Does not prove |
|---|---|---|
| `exec` | a desktop entry names a binary that exists on `PATH` | the data is disposable |
| `pkg` | `pacman -Qqo` says a package owns that desktop entry | the package is the one that wrote this cache |
| `flatpak` | the directory is an installed Flatpak app id | the app's cache child is safe to take |
| `bin` | the directory name resolves to a command on `PATH` | the command is the owner |
| `covered` | a rule names this path or something inside it | a blanket parent rule owns it |

No single row is a verdict. `exec` is the strong form of "the application is
installed"; a stale desktop entry left by a removed package has no binary.
A missing `exec` is not proof the application is gone: a library cache has no
desktop entry at all.

## Contract for a future deletion rule

1. **Scope is `{cache}` only.** `~/.config` and `~/.local/state` are
   application state. `~/.local/share` stays with `uninstall`'s exact-name
   leftovers. The probe reads all four to make that boundary visible, not to
   widen the deletion surface.
2. **A candidate needs the absence of every evidence source**: no `exec`, no
   `pkg`, no `flatpak`, no `bin`, and no dedicated rule. Any one of them
   leaves the directory alone.
3. **Shared directories are an allowlist, not a denylist.** A new
   session-wide cache must be added deliberately; an unknown name is treated
   as application data.
4. **Library caches get a named rule, not orphan detection.** A cache with no
   desktop file and no command needs a root and an evidence sentence like
   every other rule.
5. **Retention:** at least 30 days since the newest mtime and at least 1 MiB.
   The age gate is a floor, not a use signal; a cache that is two days old is
   left even if its owner is gone.
6. **Report first.** The `status` row exists and deletes nothing. Turning that
   report into a plan is a separate decision with its own evidence.
7. **If deletion is ever added, it goes to the Trash**, like `uninstall`'s
   leftovers. The owner is gone; the files may still be the only copy of
   something the user made inside the directory.

## What the status row does now

`sweep status` has one `orphan cache` row. It is `info`, never `attention`, and
it has no `next`: no sweep command deletes an orphan cache, so naming one would
be a lie. The row walks the direct children of `$XDG_CACHE_HOME` and skips:

- every directory a catalog rule names, including a rule nested below it, so
  `{cache}/npm/_cacache` protects `npm` and `{cache}/huggingface/hub` protects
  `huggingface`;
- every name on `user.cache.residual`'s `exclude` list, which is the catalog's
  own record of subtrees kept for cost rather than because they are regenerable;
- session-wide caches (`fontconfig`, `gtk-4.0`, `KDE`, ...), because "no single
  application owns this" is a category error there;
- every directory whose name resolves to a command on `PATH`, or whose matching
  desktop entry has an `Exec`/`TryExec` binary that exists.

What remains is measured with the same walker every rule uses, capped at 2
seconds and 50,000 entries per directory and 4 seconds for the row. A walk that
does not finish is unknown, not a smaller number. The value is the total, the
number of directories and the largest name; when the row budget cuts the scan
the value starts with `at least`.

The row does not read `pacman -Qqo` or Flatpak deployments. A data directory
under `$HOME` is almost never package-owned, and the `exec` check already covers
the desktop entry a package ships. If a future deletion rule needs those sources,
it has to add them at plan time and pay the extra failure mode; the report does
not need them to be useful.

On 8 November 2026 the row found eight directories and 7.1 GiB on the
maintainer's machine: `transcribe-venv` (6.8 GiB; the probe's `du -sb` says 6.7
GiB because it counts apparent size and the row counts `st_blocks`),
`cursor-compile-cache`, `node-gyp`, `winetricks`, `com.epicgames.eglv2`,
`typescript`, `legendary` and `virt-manager`. `cursor-compile-cache` is the
known false-positive shape: Cursor is installed, but the directory name does not
match the `cursor` command. A report-only row can afford that; a deletion rule
could not.

## Why not reuse `if-missing-owner`

The loader refuses it because the engine does not read the package database.
Making it real means running `pacman -Qqo` and reading Flatpak deployments at
plan time, which adds external commands to the scan path and a new failure
mode. That is a larger change than a rule kind, and the report-only data
should justify it first.

## Open questions

- Does the shared-directory allowlist belong in the catalog (`exclude`) or in
  code?
- The row is a summary, and `scripts/probe_orphan_data.py` prints one line per
  directory for anyone who needs the list. A per-directory `status` row would
  turn a health screen into a report.
- Is there a signal for "shared" that is not a hardcoded list?
