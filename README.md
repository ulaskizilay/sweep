# sweep

Terminal cleanup and maintenance for Arch Linux. Reclaims cache, log and build
space through a single validated deletion path: every action is previewable,
logged, and refuses to touch package-owned or read-only paths.

> **Pre-alpha.** One command exists (`doctor`), and it is read-only. There is no
> `clean` yet, so **sweep cannot delete anything**. The safety kernel underneath
> it is finished and tested; the rules that would use it are the next milestone.
> Do not treat the command table below as a list of what works today.

```
$ sweep doctor
sweep 0.1.0
user            uid 1000
openat2         available
home            /home/u
cache           /home/u/.cache
state writable  yes
protected roots 22
mounts          6
  /boot                     vfat
  /var/cache                btrfs        [cow]
  /home                     btrfs        [cow]
  /tmp                      tmpfs
  /mnt/usb                  vfat         [ro]
  /                         btrfs        [cow,snapshots]
```

## Status

`sweep` is being built in milestones. The safety kernel is complete and tested;
the cleanup rules are not written yet, so **no command currently deletes
anything**.

| Milestone | Scope | State |
|---|---|---|
| M0 | workspace, CI, `doctor` | done |
| M1 | path policy, plan, deletion funnel, operation log, filesystem facts | done |
| M2 | TOML rule engine, `clean --dry-run` | next |
| M3 | first real sections: user caches, dev tools, browsers, app caches, model caches | planned |
| M4 | system section, privilege boundary | planned |
| M5 | `purge`, `installer`, large files, `aur` | planned |
| M6 | TUI: `analyze`, `status` | planned |
| M7 | `uninstall`, `optimize`, `history`, snapshot report | planned |
| M8 | packaging, man page, completions | planned |

## Install

Not packaged yet. From source:

```bash
cargo build --release
./target/release/sweep doctor
```

## Design

The whole program is arranged so that a deleted file can be traced back to one
decision:

```
rule (TOML) → scan → Plan::push → validate → funnel → unlinkat
```

* `PlanItem` has no public constructor; `Plan::push` validates first.
* One function deletes anything (`funnel::apply`), one entry per syscall, never
  recursively.
* Any error during validation is a refusal. "We could not verify it" is never
  "it is safe".
* `--dry-run` and a real run consume the same plan and report the same hash.

Protections are structural, not advisory: package-manager paths (`/usr`, `/etc`,
`/boot`, …), user identity paths (`~/.ssh`, `~/.gnupg`, keyrings), read-only and
unknown mounts, snapshot directories, mount points, foreign-owned files, sticky
parents, immutable files, and files held open by a process.

Full contract, including the residual risks, is in [docs/SAFETY.md](docs/SAFETY.md).

## Commands

| Command | Purpose |
|---|---|
| `doctor` | What sweep can see: mounts, base directories, capabilities |

Planned: `clean`, `purge`, `installer`, `uninstall`, `analyze`, `status`,
`optimize`, `history`, `aur`, plus a TUI.

## Development

```bash
cargo test --workspace                              # unit, property, corpus
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check                                    # advisories, licences, bans
cargo +nightly fuzz run fuzz_validate -- -max_total_time=600
```

Every one of those runs in CI, on ext4-on-a-container and on a real btrfs loop
filesystem.

Layout:

| Path | Contents |
|---|---|
| `crates/sweep-core` | safety kernel: policy, validation, plan, funnel, log, syscall wrappers |
| `crates/sweep-cli` | argument parsing and output; no policy |
| `crates/sweep-testkit` | filesystem doubles for shapes a test process cannot create |
| `fuzz/` | libFuzzer targets (nightly) |
| `docs/SAFETY.md` | the safety contract |

`unsafe` is denied crate-wide except in `sweep-core/src/sys`, where each block
carries a `// SAFETY:` justification and wraps one syscall.

### Testing notes

* `sweep-testkit` exists because a non-root test process cannot create a
  read-only mount, a foreign-owned file or an immutable inode. Those shapes are
  described in memory instead.
* `PermissiveProbe` claims every path exists, so property and corpus tests reach
  the deep checks instead of stopping at `not_found`.
* `RealProbe` must be built with `.with_open_scan()`. Without it every path is
  refused with `probe_unknown` — which is the intended fail-closed behaviour, and
  a confusing first surprise when writing a test.

## License

MIT — see [LICENSE](LICENSE). The `Copyright (c)` line still carries a
placeholder and must be filled in before the repository is published.
