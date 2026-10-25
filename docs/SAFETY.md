# Safety model

`sweep` deletes files. This document states exactly what that means: what is
guaranteed, what is merely made unlikely, and what is not claimed at all. If a
guarantee here is wrong, it is a bug of the highest severity, not a
documentation issue.

Read [Residual risks](#residual-risks) before trusting any of the rest.

---

## 1. The shape of the program

```
rule (TOML)  →  scan  →  Plan::push  →  validate  →  funnel  →  unlinkat
                             │            │           │
                             │            │           └── one entry, never recursive
                             │            └── the only decision point
                             └── the only way to create a PlanItem
```

Four structural properties hold by construction rather than by discipline:

1. **`PlanItem` has no public constructor.** Its fields are private and the
   only function that builds one is `Plan::push`, which calls `validate` first.
   A caller cannot hand the funnel a path that was not validated without editing
   `plan.rs`.
2. **Deletion happens in exactly one function** (`sweep_core::funnel::apply`).
   Everything else in the codebase is read-only with respect to the filesystem.
3. **`unsafe` is denied crate-wide**, except [`sys`], where every block carries
   a `// SAFETY:` justification and wraps exactly one syscall.
4. **Dry run and apply consume the same `Plan`** and report the same
   `Plan::hash`, so a preview cannot describe a different operation set than the
   run it previews.

---

## 2. The decision, in order

`validate` answers one question: may this path be deleted? It walks the checks
cheapest-to-most-expensive, and **any error is a refusal**. "We could not verify
it" is never "it is safe".

| # | Check | Reason code | I/O |
|---|---|---|---|
| 1 | Non-empty | `empty` | none |
| 2 | Absolute | `not_absolute` | none |
| 3 | No control byte (`< 0x20`, `0x7f`) | `control_byte` | none |
| 4 | No `..` component | `traversal` | none |
| 5 | Not the filesystem root | `root_itself` | none |
| 6 | Not under a protected root (§3) | `protected_root` | none |
| 7 | Not user identity data (§4) | `protected_identity` | none |
| 8 | Inside a declared rule root | `not_in_allowed_root` | none |
| 9 | Not the rule root itself | `allowed_root_itself` | none |
| 10 | Exists, and is not a symlink | `not_found`, `leaf_symlink` | `lstat` |
| 11 | Covered by a known mount, writable | `unknown_mount`, `read_only_mount` | mount table |
| 12 | Not inside a snapshot directory | `snapshot_path` | mount table |
| 13 | Not a mount point | `mounted` | mount table |
| 14 | Parent resolves to a permitted physical path | `symlink_ancestor_escape` | `canonicalize` |
| 15 | On the rule root's device | `other_device` | `lstat` |
| 16 | Owned by the invoking user | `foreign_owner` | `lstat` |
| 17 | Parent is not sticky | `sticky_dir` | `lstat` |
| 18 | Not marked immutable | `immutable` | `ioctl` |
| 19 | Not held open by a process | `open_by_process` | `/proc` scan |
| 20 | Open-file scan was actually performed | `probe_unknown` | — |

Checks 1–9 do no I/O, so a forbidden path costs nanoseconds. This matters because
the scanner calls `validate` once per candidate, and a large cache can hold
hundreds of thousands.

### Reason codes are an API

`Reason::code()` strings appear in `--json` output and in the operation log. They
are stable: renaming one breaks user scripts and log correlation. The closed set
is pinned by `reason_codes_are_unique` and by the fuzz target's
`REASON_CODES` table.

---

## 3. Protected roots

Package-manager ownership is not negotiable. `PROTECTED_ROOTS` in
`policy/protected.rs` is a compile-time constant that **no configuration can
narrow**:

`/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/opt`, `/etc`,
`/boot`, `/efi`, `/var/lib`, `/var/log/journal`, `/proc`, `/sys`, `/dev`, `/run`,
`/snap`, `/nix`, `/gnu`, `/lost+found`, `/timeshift`

Matching is component-wise (`is_within`), not by string prefix, so `/usrlocal`
and `/etcetera` do not match `/usr` and `/etc`. Pinned by
`prefix_lookalikes_do_not_match`.

A rule that points into a protected root fails at **load** time, before any scan.
A test asserts every table entry is absolute and carries a non-empty
justification.

---

## 4. User identity

`~/.cache` is a legitimate cleanup target. `~/.ssh` is not. The distinction is a
fixed list (`IDENTITY_DIRS`):

`.ssh`, `.gnupg`, `.password-store`, `.local/share/keyrings`,
`.local/share/pacman`, `.config/sweep`, `.local/state/sweep`

Also protected: the home directory itself, every XDG base directory
(`~/.cache`, `~/.config`, `~/.local/share`, `~/.local/state`,
`$XDG_RUNTIME_DIR`), and the tool's own runtime directory.

The base directories are protected **as targets** while their children are not:
removing `~/.cache` takes the whole tree and defeats every per-rule decision
inside it. This is why `AllowedRoot::allow_root_itself` defaults to `false` and
only tests set it.

---

## 5. Symlinked ancestors are followed, then re-checked

The naive rule — "refuse any path with a symlinked component" — breaks real
setups: `~/.cache -> /mnt/ssd/cache`, `/home -> /var/home`, `~/Documents ->
~/Sync/Documents`. Refusing them means the tool silently cleans nothing on a
large fraction of machines, which is its own failure mode.

Instead:

1. Reject the **leaf** symlink (`leaf_symlink`). A link is never the target.
2. `canonicalize` the **parent** once.
3. If the physical path differs, re-check the physical path against protected
   roots, identity paths, read-only mounts and snapshot directories.
4. Delete through a directory handle opened with `RESOLVE_NO_SYMLINKS`, so a
   later swap cannot redirect the delete.

Step 3 is **deny-only**: resolving never grants permission the literal path did
not already have. A `~/.cache` that points at `/usr/lib` is refused, not
followed. Pinned by `a_symlink_into_a_protected_tree_is_refused`.

Legitimate case: `a_symlinked_base_directory_is_followed_to_its_physical_path`
asserts the verdict carries `/real-cache/stale.bin`, not `~/.cache/stale.bin`.

---

## 6. Deletion is one syscall, and it cannot recurse

```rust
unlinkat(parent_dirfd, name, if is_dir { AT_REMOVEDIR } else { 0 })
```

Properties this buys:

* **A directory with children fails with `ENOTEMPTY`** and is reported as
  `directory_not_empty`. Accidental recursive deletion is not a code-review
  question; the kernel refuses it. Pinned by
  `a_non_empty_directory_is_refused_not_recursed` and
  `unlink_beneath_removes_one_entry_and_stops`.
* **The parent is pinned by a file descriptor**, so renaming the parent during
  the sweep cannot redirect the unlink.
* **`dev`/`ino` are re-read immediately before the syscall** and compared with
  the plan. A path replaced after planning yields `race_changed`, not a deletion.

The scanner is responsible for emitting children before parents (post-order).
That ordering is a scanner test, not a funnel guarantee — the funnel's job is to
make a wrong order harmless.

---

## 7. Directory handles never follow symlinks

`openat2(2)` with `RESOLVE_NO_SYMLINKS`. On kernels without it (< 5.6) a
component walk with `O_PATH | O_DIRECTORY | O_NOFOLLOW` per component emulates
it.

The fallback is only entered on `ENOSYS` or `EINVAL`. **Never on `EPERM`**: a
permission denial is a real failure, and falling back there would replace a
kernel-enforced guarantee with an emulation the caller did not ask for.

Both paths must reach the **same verdict**, which is not a theoretical concern —
`kernels_agree_on_every_component_shape` found a real disagreement the first time
it ran: `O_PATH|O_NOFOLLOW` reports a symlink as `ENOTDIR`, not `ELOOP`, so the
fallback was classifying a plain file in the middle of a path as a symlink
escape. It now probes the entry with `fstatat(AT_SYMLINK_NOFOLLOW)` to tell them
apart.

---

## 8. Live data

### Open files

A single `/proc/<pid>/fd` pass, indexed by `(dev, ino)`. No `lsof` fork, a few
milliseconds, and it answers "is this open right now".

If the scan was not performed at all, every path is refused
(`probe_unknown`). Failing closed is the only correct default: an unperformed
scan is indistinguishable from a path being open.

Unreadable processes are skipped. This is deliberate: we can prove a file *is*
open, never that it is not, and a permission error on another user's process must
not block cleaning the user's own cache.

### SQLite sidecars

`-wal`, `-shm` and `-journal` are meaningless without their database, and the
database may be the file that is open while the sidecar is not. The sidecar is
therefore refused when its base file is open. This is a small, exact rule rather
than a guess about file names.

### Databases are never checkpointed by sweep

Sweep never truncates, vacuums or checkpoints a database, and never unlinks a
sidecar directly. A stopped writer may hold committed recent records only in the
WAL; removing it loses writes that the application believes are durable.

---

## 9. Filesystem facts

Nothing about the filesystem is assumed at build time.

| Fact | Source | Consequence |
|---|---|---|
| Mount point, device, read-only flag | `/proc/self/mountinfo` | `unknown_mount`, `read_only_mount`, `mounted`, `other_device` |
| Copy-on-write family | fstype (`btrfs`, `zfs`, `bcachefs`, `nilfs2`) | "freed" and "reclaimed" reported separately |
| Snapshot directories | `/.snapshots`, `@@snapshots`, `/timeshift`, `/var/lib/timeshift` and per-mount equivalents | `snapshot_path` |
| Immutable flag | `FS_IOC_GETFLAGS` | `immutable` |

**Why snapshots are report-only.** On btrfs, deleting a file inside a snapshot's
ancestry frees nothing and can destroy a rollback point. Size and mtime cannot
prove a snapshot is inactive, so the whole family is refused rather than guessed
about.

**Why freed ≠ accounted.** On CoW filesystems the bytes accounted for by
`st_blocks` may be shared with snapshots or reflinks, so deleting a file can
free nothing while `st_blocks` still reports a size. Reports therefore say
**accounted**, never "freed", and add an explicit note when a rule root sits on
a copy-on-write filesystem.

`statvfs_space` and `Meta::accounted_bytes` exist for telling the two apart
without guessing, but the delta is not consumed yet: printing it next to the
accounted figure, per mount, is the remaining gap. Until then the number in the
summary is a sum of inode sizes and is labelled as one.

**Unknown paths fail closed.** `MountTable::find` matching nothing yields
`unknown_mount`. This happens with a truncated `mountinfo` or a path outside
every visible mount, and neither is a reason to proceed.

### Blob stores are scanned by reference, not by name

Some caches are not trees of files: each file is stored once under a content
address and linked into every name that uses it. The Hugging Face hub is the
first one sweep reaches — `blobs/<etag>` plus `snapshots/<revision>/<path>`
symlinks — and a name-based sweep there is actively harmful. Deleting the blobs
leaves every snapshot dangling, so the model looks installed, fails at load time,
and never re-downloads because its revision is still in `refs/`.

The scanner in `model_cache.rs` therefore starts from the *referrers*: it reads
every link below `snapshots/` with `read_link`, resolves it lexically, and only
plans a blob whose path never appears. Two consequences matter for safety:

* **Nothing is followed.** A snapshot entry pointing at `/etc/shadow` is a string
  compared against blob paths, never a file sweep opens.
* **An unreadable reference set is not an empty one.** If `snapshots/` cannot be
  read, or the tree is deeper than the scanner understands, that repository is
  preserved whole and named in the report. The retention is what makes a
  genuinely absent `snapshots/` directory safe to read as "no references".

**Why the section is opt-in.** Deleting a model blob may not be recoverable: a
gated repository needs a licence acceptance, a private one needs a token, and an
offline machine can reach neither. `clean` therefore skips `model-caches`
entirely unless the user names it with `--only`, and reports it as not scanned
rather than as empty.

---

## 10. Verification and logging

* **The funnel's dry-run mode performs no mutating syscall** (`Mode::DryRun`),
  and a plan's `plan_hash` is identical in both modes.
  `dry_run_parity_on_a_real_tree` builds a plan in two different insertion
  orders, asserts one hash, previews, then applies and checks the removed set
  matches. `clean` keeps that contract end to end: the same tree produces the
  same hash in both modes, and `--yes` is refused *together with* `--dry-run`
  rather than letting one flag silently win over the other.
* **Planning and deleting are separated by consent.** `clean` builds and
  validates the whole plan before asking anything. The prompt is skipped with
  `--yes`, refused when stdin is not a terminal, and a declined run writes
  nothing at all — no `unlinkat`, no log row, no state directory. Every item is
  re-checked against its planned `dev`/`ino` at the sink, so a tree that changed
  while the question was on screen is skipped rather than removed.
* **The operation log is append-only JSONL**, one record per line, written with a
  single `write_all`. JSON gives exact fidelity: a path containing a newline is
  stored as `\n` and cannot forge a second record. `0x7f` is escaped explicitly
  because it is legal raw inside a JSON string but is still a control byte.
* **A non-UTF-8 path is stored twice**: lossy `path` for humans and `path_hex`
  for exactness. Losing a name in the audit trail is worse than an extra field.
* **A failed log write warns once and continues.** Stopping mid-sweep because a
  disk is full leaves the tree half-cleaned with no record of which half.

---

## 11. Privilege

`sweep` **refuses to run as root** (exit code 78). A user-scoped tool that runs
as root would source user-owned state — config, rule files, cache paths — with
privilege it was not granted for.

The check runs before command dispatch, not inside each subcommand, so a new
subcommand cannot forget it. Exit code 78 means "this environment cannot run
sweep", which a script can tell apart from 2 ("the argument was wrong").

The refusal is verified against a real `uid 0` process: the test suite runs the
binary under `unshare -r`, which maps the caller to root inside a user namespace
without needing privilege. That case is the one that would otherwise only ever
be exercised by whoever ran the suite from a root shell, which is exactly
nobody.

System sections request privilege for themselves, through one narrow path, and
never persist the choice across commands. Nothing in the current milestone
performs a privileged operation; the boundary is in place before the first
section that needs it.

---

## Residual risks

These are real. They are listed because a safety document that claims perfection
is not usable for review.

### R1. The leaf can be swapped between the check and the unlink

`validate` and `apply` both `lstat` the leaf, then `openat` its parent, then
`unlinkat` by name. Between the `lstat` and the `unlinkat`, a process with write
access to that parent can replace the leaf.

*What limits it:* the parent handle is opened with `RESOLVE_NO_SYMLINKS`, so the
swap cannot redirect the delete into another directory; `dev`/`ino` are compared
before the syscall, so a replaced inode is refused as `race_changed`.
*What remains:* if the replacement is a different inode, `race_changed` catches
it — but the comparison and the `unlinkat` are still two syscalls, so a window of
nanoseconds exists. Closing it entirely requires `unlinkat` to accept an fd
rather than a name, which Linux does not offer.

*Who can exploit it:* a process with write permission on the parent directory.
Sweep already requires the target to be owned by the invoking user and the parent
to be non-sticky, so the practical attacker is the user's own process racing the
user's own cleanup.

*Reported honestly:* `Reason::RaceChanged` exists as a distinct code precisely
because this is expected to happen occasionally, not never.

### R2. An ancestor directory can be replaced with a different real directory

`canonicalize` resolves the parent, then `open_dir_nofollow` opens it. If an
ancestor is renamed *and* a different real directory is put in its place between
those two calls, the handle refers to the new directory.

*What limits it:* the leaf's `dev`/`ino` would then have to match as well. Two
independent coincidences, one of which the attacker cannot control (inode
numbers are not chosen by the attacker).

### R3. Snapshot detection is name-based

A snapshot stored somewhere other than `.snapshots`, `@@snapshots`, `timeshift`
or `/var/lib/timeshift` is not recognised. The lists are constants in
`fs_facts.rs`; widening them is a one-line change, but no list is complete.
`FsFacts` is the seam where a real tool query (snapper, `zfs list -t snapshot`)
belongs — tracked for the snapshot milestone.

### R4. Some opens are invisible

A file held open by a process whose `/proc/<pid>/fd` is unreadable is not seen.
Sweep cannot prove absence, only presence. This is why `open_by_process` is a
refusal with a named pid: the user can check.

### R5. Hardlinks are not resolved

Sweep does not currently refuse `nlink > 1`. Removing one link does not free the
data, so the *safety* impact is nil, but the *accounted* byte count over-states
what was reclaimed. This is an accounting gap, not a deletion risk.

### R6. CoW reflinks

Summed `st_blocks` over-counts shared extents on btrfs/XFS-reflink. Reports label
the figure **accounted** and note the CoW caveat when a rule root is on such a
filesystem, so nothing is claimed as freed. Printing the `statvfs` delta next to
it — rather than instead of it — is the remaining accounting task.

### R7. A paused download looks abandoned

`huggingface_hub` writes `<etag>.incomplete` while a download runs and renames it
on completion. A download paused for longer than the retention is
indistinguishable from one whose client died, so `hf-cache` will plan it. The
cost is a re-download — the partial bytes are the only thing lost — and the
90-day default is what keeps that from being a nuisance. There is no marker on
disk that separates the two cases, so this is accepted rather than solved.

---

## How to add a rule

1. Point it at a path inside a declared `AllowedRoot`. A rule outside every root
   fails at load time.
2. Never add a rule for a protected root or an identity path. It will be refused
   at run time; the test suite will also fail.
3. State what the rule **does not** delete, and test it. A rule without a test of
   its negative space is not a rule.
4. If the target can be held open, sqlite-backed, on another device, or inside a
   snapshot, add a fixture for it. `sweep-testkit` describes those shapes without
   needing root.

## How to change the kernel

Every change to `validate`, `funnel` or `sys` needs:

```bash
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo +nightly fuzz run fuzz_validate -- -max_total_time=600
```

and a line-by-line review of every added early return. An early return that skips
a check still compiles, still returns a `Deny`, and still passes an
example-based test. Proptest and the corpus test exist to make that specific
mistake fail.
