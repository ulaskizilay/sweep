<div align="center">

# sweep

**Terminal cleanup for Arch Linux, with exactly one way to delete a file.**

[![CI](https://github.com/ulaskizilay/sweep/actions/workflows/ci.yml/badge.svg)](https://github.com/ulaskizilay/sweep/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](rust-toolchain.toml)
[![Arch Linux](https://img.shields.io/badge/platform-Arch%20Linux-1793d1.svg)](#requirements)

<img src="docs/assets/doctor.svg" alt="sweep doctor reporting mounts, copy-on-write status and snapshot directories" width="780">

<sub>Example output. The mount list is trimmed; the flags are real.</sub>

</div>

---

## Status

> **Pre-alpha.** `doctor`, `rules`, `clean`, `purge`, `installer`, `aur` and
> `status` work. `clean` prints the plan, asks once, then deletes through the
> single funnel and writes one operation-log row per decision; `--dry-run` stops
> before the question and writes nothing at all. The catalog is 109 rules over
> seventeen sections, and the section whose loss may not be recoverable —
> downloaded model weights — is skipped unless you name it. System caches are
> swept through a second process: `sweep` never runs as root, so it plans as you
> and asks before elevating.

| Milestone | Scope | State |
|---|---|---|
| M0 | workspace, CI, `doctor` | done |
| M1 | path policy, plan, deletion funnel, operation log, filesystem facts | done |
| M2 | TOML rule engine, `rules list\|verify`, `clean --dry-run` | done |
| M3a | applying the plan: confirmation gate, operation log, exit codes | done |
| M3b | model caches: Hugging Face blob/snapshot scanner, opt-in section | done |
| M4a | system caches through `run0`/`sudo`, the privilege boundary | done |
| M4b | `paccache` keep-versions semantics, rotated logs | done |
| M5a | project artifacts: the manifest-gated `purge` | done |
| M5b | `installer`: downloaded package and image files | done |
| M5c | AUR helper caches: `aur` | done |
| M6a | `status`: a read-only health summary, text and JSON | done |
| M6b | `analyze`: the disk explorer and the large-file report | next |
| M7 | `uninstall`, `optimize`, `history`, snapshot report | planned |
| M8 | packaging, man page, completions | planned |

## Why

Every disk cleaner is a program that runs as you, walks your home directory, and
calls `rm`. The interesting question is not which folders it picks. It is what
stops it when it picks the wrong one: a bug in a glob, a symlink pointing into
`/usr`, a database someone still has open, a snapshot it cannot see.

`sweep` is built around that question. Deletion is not a helper function called
from thirty places. It is one function, reachable only by a path that passed
twenty checks, and it removes exactly one directory entry per syscall.

## How it works

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/pipeline-dark.svg">
  <img src="docs/assets/pipeline-light.svg" alt="Rules become a validated plan, and only then a single deletion syscall" width="900">
</picture>

</div>

Four properties hold by construction rather than by discipline:

- **`PlanItem` has no public constructor.** The only function that builds one is
  `Plan::push`, and it calls `validate` first. A caller cannot hand the funnel a
  path that was never validated without editing `plan.rs`.
- **One function deletes anything** (`sweep_core::funnel::apply`). Everything
  else in the codebase is read-only with respect to the filesystem.
- **Any error is a refusal.** "We could not verify it" is never "it is safe".
  A missing mount table entry, an unreadable `/proc` entry, a failed `ioctl` —
  all of them deny.
- **Deletion cannot recurse.** `unlinkat` on a non-empty directory fails with
  `ENOTEMPTY`. Recursive deletion is not a code review question, it is a syscall
  the kernel refuses.

## What it protects

Each of these is a refusal with a stable reason code, not a warning:

| Target | Why |
|---|---|
| `/usr`, `/bin`, `/lib`, `/etc`, `/boot`, `/opt`, `/var/lib`, … | package-manager ownership is not negotiable; the list is compile-time and no config can narrow it |
| `~/.ssh`, `~/.gnupg`, `~/.password-store`, keyrings | identity data is never a cache |
| `~/.cache`, `~/.config`, `~/.local/share`, `~/.local/state` themselves | deleting the base directory defeats every per-rule decision inside it |
| read-only and unknown mounts | an unknown mount means a truncated mount table, not a permission |
| `/.snapshots`, `@@snapshots`, `/timeshift` | inside a btrfs snapshot the bytes are shared and the rollback point is not replaceable |
| mount points | unmounting is not cleaning |
| files owned by another user | not yours, not ours to remove |
| sticky parents, immutable files | the kernel is already protecting them |
| files held open by a process | answered from one `/proc` pass, indexed by inode; `-wal`/`-shm` are refused when their database is open |

Symlinked ancestors are **followed and then re-checked**, not blanket-denied.
`~/.cache -> /mnt/ssd/cache` is a normal setup; refusing it would mean the tool
silently cleans nothing on a large fraction of machines. The resolved physical
path is re-tested against the same list, deny-only, and the delete happens
through a directory handle opened with `RESOLVE_NO_SYMLINKS`.

The full contract — including the eleven residual risks that are *not* solved —
is in [`docs/SAFETY.md`](docs/SAFETY.md).

## The rules

The catalog is TOML, and it is data rather than code: `rules/01-system.toml`
through `rules/17-model-caches.toml`, 109 rules over seventeen sections, 94
enabled in this build. Each rule names a root, a kind, a retention and the
sentence that justifies deleting there.

```bash
$ sweep rules list
sweep rules — 17 packs, 109 rules, 94 enabled

  section            rules  enabled
  system                 8        5
  user-essentials        5        5
  ...
  dev-tools             28       28
  ...
  model-caches           3        3  opt-in

  model-caches is opt-in: `sweep clean` leaves it alone until you name it with `--only`.

  system
    system.fontconfig.cache        dir-sweep      now  root  /var/cache/fontconfig
    system.fwupd.cache             dir-age        30d  root  /var/cache/fwupd
    system.log.rotated             file-pattern   7d   root  /var/log
    system.man.cache               dir-sweep      now  root  /var/cache/man
    system.pacman.package-cache    pkg-cache    2v/7d  root  /var/cache/pacman/pkg

  dev-tools
    dev.cargo.crate-cache          file-pattern   30d  on    /home/u/.cargo/registry/cache
    dev.go.build-cache             tool-cache     now  on    /home/u/.cache/go-build

  model-caches
    model.huggingface.hub          hf-cache       90d  on    /home/u/.cache/huggingface/hub
    model.torch.checkpoints        dir-age        90d  on    /home/u/.cache/torch/hub/checkpoints
    model.whisper.cache            dir-age        90d  on    /home/u/.cache/whisper
```

Eight kinds (`dir-sweep`, `dir-age`, `file-pattern`, `tool-cache`, `hf-cache`,
`pkg-cache`, `project-artifacts`, `report-only`) cover every target. `dir-age` keeps a whole subtree
unless *every* entry in it is idle past the cutoff and nothing in it was left
alone.

`pkg-cache` exists because the package cache has no sensible age cutoff. It
keeps the newest *N* versions of each package, compared with pacman's own
`vercmp`, so `1.10` outranks `1.9` and a machine that has not been upgraded in
months still has the archive of the kernel it is running. A version downloaded
in the last `keep_days` is kept regardless: that is a downgrade in progress.
On a stock Arch cache, `sweep clean --only system` planned the same 170 files,
byte for byte, as `paccache -d -k2` when this was verified.

Rules that are wrong do not load: a root inside `/usr`, a duplicate id, a typo
in a key. A user overlay at `~/.config/sweep/rules.d/*.toml` may add rules but
not replace a built-in one. The schema, the retention semantics and the full
list of load-time refusals are in [`docs/RULES.md`](docs/RULES.md).

### Project artifacts need a manifest, not a directory name

`sweep purge` removes the build output of the projects in your home:
`node_modules`, `target`, `.venv`, `vendor`, `dist`, `build`. The rule does not
have a list of names to delete; it has a list of manifests, and a directory is
only a target when the manifest that produces it sits beside it:

```
web/package.json      + web/node_modules       →  node_modules is a build artifact
rustproj/Cargo.toml   + rustproj/target        →  target is a build artifact
stray/node_modules                             →  no manifest, left alone
```

That gate is what makes it safe to point at `$HOME`. There is no vendor-wide
prefix, no `find -name node_modules`, and no wildcard that a typo can widen: a
`node_modules` with no `package.json` is reported as skipped, with the reason.
`.git` is never a target, and the walk never descends into an artifact, so the
`package.json` inside a published dependency does not make it a project.

One directory is all-or-nothing. If any part of a `target/` tree cannot be read,
the whole artifact stays: a half-removed tree is worse than either state.
Symbolic links inside an artifact are removed as links, never followed — that is
the one place sweep unlinks a link, and it is why the venv's `bin/python3` and
`node_modules/.bin` go with the directory.

`sweep purge` is its own command because the work is different. `clean` opens
paths the rule already names; `purge` walks your home, so it needs its own
preview and its own confirmation. A bare `sweep clean` lists the section as
`belongs to another command` instead of scanning it.

### An AUR clone is a recipe, not a cache

`sweep aur` removes the `.pkg.tar.*` archives that `paru`, `yay` and `trizen`
build under `~/.cache`, and nothing else in those directories. The clone, the
`PKGBUILD` and the sources stay.

The distinction is what the files are for. A `PKGBUILD` you edited exists
nowhere else — not in the AUR, not in the binary package — so a directory sweep
of a helper cache can destroy work that took an hour to get right. The archive
beside it is output: `makepkg` rebuilds it from the recipe that stays. Sources
are kept for a subtler reason: if upstream republished a tarball, the cached
copy is the one whose checksum still matches, so deleting it can leave a package
that no longer builds until the recipe is fixed by hand.

The clone directories are still reported, with their size and with the sentence
saying they were not taken. "There is 12 GiB here you can't have automatically,
and here is why" is a more useful answer than silence.

### An installer is not the installed program

`sweep installer` removes the archive: the `.pkg.tar.zst` downloaded instead of
using the mirror, the `.deb` for a foreign package, the `.iso` burned once, the
`.AppImage` that was copied into `/usr/local/bin`. The package database, the
unpacked files and the application's own state are untouched, so removing the
archive never uninstalls anything.

The rule is narrow on purpose. It reads `~/Downloads` two levels deep and it
matches six suffixes, because the name is the only evidence there is. It does
not take `.zip`, `.tar.gz` or `.7z` (as likely to be a source export or a backup
as an installer), and it does not take `.exe` or `.msi` (a portable Windows
program *is* that file; removing it is an uninstall, which is a different
command with a different confirmation). An `.iso` under `~/VMs` stays too: a
disk image a virtual machine is running is not a download someone forgot.

### Model weights are opt-in

`model-caches` is the one section a bare run does not scan. The rules are listed
with status `opt-in` instead of disappearing, and the summary says the section
was not scanned rather than reporting it as empty. `--only model-caches` is the
consent.

The reason is recoverability, not caution about size. A gated repository needs a
licence acceptance, a private one needs a token, and an offline machine can
reach neither, so "download it again" is not always true.

That section also needs its own kind. `huggingface_hub` stores each file once as
`blobs/<etag>` and links it into `snapshots/<revision>/<path>`, so an ordinary
cache sweep would delete the blobs and leave every snapshot dangling: the model
looks installed, fails at load time, and never re-downloads because its revision
is still in `refs/`. `hf-cache` therefore plans only blobs no snapshot link
resolves to, plus abandoned `*.incomplete` downloads, and it preserves a
repository whose snapshot tree cannot be read completely.

### Root, without becoming root

`sweep` refuses to run as root at all. That is not modesty: every path it reads
— the catalog overlay, the state directory, the log — belongs to the user, and a
process that resolves them as root is reading a different machine's worth of
configuration.

System caches still get swept, in two steps with a question in between. The user
process does the planning, because reading `/var/cache/man` needs no privilege.
Then `clean` asks a second question — `--yes` answered "delete this plan", not
"become root" — and re-executes the same binary through `run0` or `sudo` with a
fixed argument list and the plan on standard input. No shell is involved, so a
filename cannot become an argument.

The elevated child does not trust its parent: it rebuilds the list of allowed
roots from the compiled catalog, refuses a rule id it has never heard of,
re-checks each inode, re-derives each rule's *selection* (which rotated logs,
which package versions) instead of trusting the path list, and re-runs the whole
validation as root before removing anything. It also never writes the log. It prints one JSON line per item and the
user process appends them, so root never opens a file inside your home.

A pipe has nobody to ask, so a non-interactive run without `--privileged` leaves
the root-owned items alone and says so. Nothing is deleted as you by accident,
and nothing is deleted as root without a second answer.

## Requirements

- Arch Linux, or another Linux with `/proc/self/mountinfo`
- Linux 5.6+ for `openat2`; older kernels use a component-walk fallback with the
  same verdicts
- Rust 1.82+ to build

`sweep` refuses to run as root (exit code 78). It reads your config, your cache
paths and your logs; as root those resolve to a different user's tree. The
sections that genuinely need privilege will ask for it one operation at a time.

## Install

Not packaged yet.

```bash
git clone https://github.com/ulaskizilay/sweep.git
cd sweep
cargo build --release
./target/release/sweep doctor
```

## Commands

| Command | Purpose | State |
|---|---|---|
| `sweep doctor` | what sweep can see: mounts, base directories, capabilities; `--json` for scripts | works |
| `sweep rules list` / `verify` | the catalog, and whether built-ins plus your overlay compile | works |
| `sweep clean --dry-run` | the plan, per section and per rule, with the reason every skip happened | works |
| `sweep clean` | reclaim cache, log and build space; asks once, then deletes | works |
| `sweep clean --only model-caches` | the opt-in section: model blobs, checkpoint caches | works |
| `sweep clean --privileged` | also sweep root-owned system caches, through `run0` or `sudo` | works |
| `sweep purge` | `node_modules`, `target`, virtualenvs — only where a manifest says a build made them | works |
| `sweep installer` | package and image files in `~/Downloads` that were never touched again | works |
| `sweep status` | disk, inodes, memory, load, package cache, orphans, trash, last sweep; `--json` for scripts | works |
| `sweep analyze` | disk explorer, files over a gigabyte, Trash-based ad hoc cleanup | M6b |
| `sweep uninstall` / `optimize` / `history` | package removal, maintenance, past actions | M7 |
| `sweep aur` | built `.pkg.tar.*` archives in helper caches; clones and sources are reported, never taken | works |

`sweep clean` is two phases. It plans — load the catalog, scan the roots,
validate every candidate — and only then asks. The question is skipped with
`--yes`, and a run whose stdin is not a terminal refuses without it (exit 5) and
deletes nothing, so a cron job cannot answer a prompt with its own pipe. The
applied run writes one row per decision to
`~/.local/state/sweep/operations.jsonl` under a `clean-<unix>` session and exits
1 if a syscall failed, with the reason recorded for each item.

Sizes are the sum of `st_blocks`, which is what the inodes account for. On a
copy-on-write filesystem the space actually returned can be smaller when extents
are shared with a snapshot or a reflink, and the report says so when a rule root
sits on one.

`sweep doctor` is also the answer to "why did it skip everything?", so a bug
report can be its output pasted whole. `sweep rules list --verbose` answers the
narrower version: which rule, which requirement, which retention.

### Status is a snapshot, not a monitor

`sweep status` prints one screen and exits. It reads `/proc`, `statvfs`, the
package cache and the operation log, and it writes nothing at all — no state
file, no lock, no log row, so it is safe to put in a shell prompt or run every
minute from a timer if you want to. It is not a daemon, it keeps no history, and
it has no alerts.

Every row is either a number or `— not available`. A row that cannot be measured
says so instead of printing a plausible zero: a tree the walk could not finish
enumerating is "not available", never a smaller size. `--verbose` adds the reason
it could not be measured; the default keeps the screen quiet.

The actionable rows name the command that acts on them (`sweep clean --only
system` for a package cache, `sudo pacman -Rns $(pacman -Qtdq)` for orphans),
because a health summary that cannot be acted on is a dashboard. Trash appears
with its size and no command: paired `files/` + `info/` removal is not
implemented yet, so naming a sweep command there would be a promise the tool does
not keep.

`--json` prints the same facts with stable field names, one document, for a
script that should not parse the prose. The last-run row sums the newest session
in the operation log; if a session is longer than the 64 KiB tail window, the row
says `at least N items` rather than printing a short total as if it were whole.

## Development

```bash
cargo test --workspace                              # unit, property, corpus
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check                                    # advisories, licences, bans
cargo +nightly fuzz run fuzz_validate -- -max_total_time=600
cargo +nightly fuzz run fuzz_rule_toml -- -max_total_time=600
```

All of it runs in CI, on both ext4 and a real btrfs loop filesystem — a clean
pass on ext4 says nothing about a copy-on-write root, and the `FsFacts` layer
exists precisely for that difference.

| Path | Contents |
|---|---|
| `crates/sweep-core` | safety kernel: policy, validation, plan, funnel, log, syscall wrappers |
| `crates/sweep-core/src/rules` | TOML schema, load-time validation, glob, templates |
| `crates/sweep-core/src/scan.rs` | the read-only walker every rule goes through |
| `crates/sweep-cli` | argument parsing and output; no policy |
| `crates/sweep-testkit` | filesystem doubles for shapes a test process cannot create |
| `rules/` | the shipped catalog, one pack per section |
| `fuzz/` | libFuzzer targets (nightly) |
| `docs/SAFETY.md` | the safety contract |
| `docs/RULES.md` | the rule schema, kinds and load-time refusals |

`unsafe` is denied crate-wide except in `sweep-core/src/sys`, where each block
carries a `// SAFETY:` justification and wraps one syscall.

### Testing notes

- `sweep-testkit` exists because an unprivileged test process cannot create a
  read-only mount, a foreign-owned file, or an immutable inode. Those shapes are
  described in memory instead.
- `PermissiveProbe` claims every path exists, so property and corpus tests reach
  the deep checks instead of stopping at `not_found`.
- `RealProbe` must be built with `.with_open_scan()`. Without it every path is
  refused with `probe_unknown` — which is the intended fail-closed behaviour, and
  a confusing first surprise when writing a test.
- The root refusal is tested against a genuine `uid 0` process via `unshare -r`,
  not by inspecting a boolean.

## Contributing

A rule that deletes something arrives with a test proving **what it does not
delete**. The negative space is the part that matters; a rule without it is not
a rule yet.

Changes to `validate`, `funnel` or `sys` need a line-by-line review of every
added early return. An early return that skips a check still compiles, still
returns a `Deny`, and still passes an example-based test — which is why the
property and corpus suites exist.

## License

[MIT](LICENSE).
