# Orphan application data

**Status:** design note. No rule kind is implemented and no deletion path
changes. `if-missing-owner` and the `pkg:` requirement are still refused at
load, as `docs/RULES.md` says.

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
The probe prints the matched entry instead of deciding, because a false
positive here is a deletion.

## What each evidence source proves

| Source | Proves | Does not prove |
|---|---|---|
| `exec` | a desktop entry names a binary that exists on `PATH` | the data is disposable |
| `pkg` | `pacman -Qqo` says a package owns that desktop entry | the package is the one that wrote this cache |
| `flatpak` | the directory is an installed Flatpak app id | the app's cache child is safe to take |
| `bin` | the directory name resolves to a command on `PATH` | the command is the owner |
| `covered` | a rule names this exact path | a blanket parent rule owns it |

No single row is a verdict. `exec` is the strong form of "the application is
installed"; a stale desktop entry left by a removed package has no binary.
A missing `exec` is not proof the application is gone: a library cache has no
desktop entry at all.

## Proposed contract

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
6. **Output is report-only first.** A `status` row or a new `orphans`
   report-only rule, no deletion. Turning a report into a plan is a separate
   decision with its own evidence.
7. **If deletion is ever added, it goes to the Trash**, like `uninstall`'s
   leftovers. The owner is gone; the files may still be the only copy of
   something the user made inside the directory.

## Why not reuse `if-missing-owner`

The loader refuses it because the engine does not read the package database.
Making it real means running `pacman -Qqo` and reading Flatpak deployments at
plan time, which adds external commands to the scan path and a new failure
mode. That is a larger change than a rule kind, and the report-only data
should justify it first.

## Open questions

- Does the shared-directory allowlist belong in the catalog (`exclude`) or in
  code?
- Is one `status` row enough, or does the report need one row per directory?
- Is there a signal for "shared" that is not a hardcoded list?
