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

> **Pre-alpha.** `doctor`, `rules` and `clean` work. `clean` prints the plan,
> asks once, then deletes through the single funnel and writes one operation-log
> row per decision; `--dry-run` stops before the question and writes nothing at
> all. What M2 proved is the other half: 106 rules across fifteen sections
> compile, produce a plan, and pass that plan through the same validation the
> real run uses.

| Milestone | Scope | State |
|---|---|---|
| M0 | workspace, CI, `doctor` | done |
| M1 | path policy, plan, deletion funnel, operation log, filesystem facts | done |
| M2 | TOML rule engine, `rules list\|verify`, `clean --dry-run` | done |
| M3a | applying the plan: confirmation gate, operation log, exit codes | done |
| M3b | model caches: Hugging Face blobs, torch checkpoints | next |
| M4 | system section, privilege boundary | planned |
| M5 | `purge`, `installer`, large files, `aur` | planned |
| M6 | TUI: `analyze`, `status` | planned |
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

The full contract — including the six residual risks that are *not* solved — is
in [`docs/SAFETY.md`](docs/SAFETY.md).

## The rules

The catalog is TOML, and it is data rather than code: `rules/01-system.toml`
through `rules/15-project-artifacts.toml`, 106 rules over fifteen sections, 81
enabled in this build. Each rule names a root, a kind, a retention and the
sentence that justifies deleting there.

```bash
$ sweep rules list
sweep rules — 15 packs, 106 rules, 81 enabled

  section            rules  enabled
  system                 8        0
  user-essentials        5        5
  ...
  dev-tools             30       28

  dev-tools
    dev.cargo.crate-cache          file-pattern   30d  on    /home/u/.cargo/registry/cache
    dev.go.build-cache             tool-cache     now  on    /home/u/.cache/go-build
    dev.huggingface.cache          report-only    90d  off   /home/u/.cache/huggingface/hub
```

Five kinds (`dir-sweep`, `dir-age`, `file-pattern`, `tool-cache`,
`report-only`) cover every target. `dir-age` keeps a whole subtree unless
*every* entry in it is idle past the cutoff and nothing in it was left alone.

Rules that are wrong do not load: a root inside `/usr`, a duplicate id, a typo
in a key. A user overlay at `~/.config/sweep/rules.d/*.toml` may add rules but
not replace a built-in one. The schema, the retention semantics and the full
list of load-time refusals are in [`docs/RULES.md`](docs/RULES.md).

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
| `sweep purge` / `installer` | project artifacts, installer leftovers | M5 |
| `sweep analyze` / `status` | disk explorer, health summary | M6 |
| `sweep uninstall` / `optimize` / `history` | package removal, maintenance, past actions | M7 |
| `sweep aur` | AUR package cleanup | M5 |

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
