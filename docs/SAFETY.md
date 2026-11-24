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

Before any of them, the plan asks the user's ignore file
(`~/.config/sweep/ignore`, `ignored`). That check is first for two reasons: it
costs no syscall, and a path the user protected should be reported as protected,
not as whatever else it happened to trip. It is also checked again on the
resolved path, because `~/.cache` is often a symlink and a line may name either
the literal or the real path.

The ignore file can only **narrow** a plan. It never widens one: a line cannot
admit a path that `validate` would refuse, because the check runs before the
allowlist rather than instead of it. And it is read by the user process only,
so it cannot reach the elevated child — which is not a gap, because the child
acts on the plan it is sent and the parent never sends an ignored path.

### The same answer is not asked for twice

Several of those checks, the plan's final sort, and two questions the planner asked
once per item used to cost more than the work they describe, and a million-file
cache made it visible: `sweep clean --dry-run` spent two minutes and fifteen
seconds planning. The fixes changed no decision, only how many times one was
computed.

* **11–13 are one lookup.** "Which mount covers this path" and "is this path the
  mount point" are the same question: the longest matching mount point *is* the
  path when the path is a mount point. One pass over the table answers both,
  and the prefix test is a byte comparison against a mount point that the parser
  normalized, not a component walk.
* **15 reuses 10's metadata when nothing was resolved.** If no ancestor was a
  symlink, the physical path is the literal path, so the `lstat` at check 15 is
  the one at check 10 repeated. A swap between two calls of the same path is
  exactly as possible with either call, so asking once narrows no window; when
  an ancestor *was* resolved, the physical path is a different path and it is
  still `lstat`ed on its own.
* **Protected roots, identity paths and allowed roots use the same byte test.**
  `is_within_normalized` and `is_within_named` are `is_within` for paths that are
  already normalized, and a property test holds them to it over a corpus that
  contains the pairs a naive prefix gets wrong (`/home/u` and `/home/u2`,
  `a` and `a.b`). Every XDG base is normalized where it is resolved, so the
  precondition holds for the paths that reach them.
* **The candidate is normalized once.** Those byte tests require a normalized
  path, and the validator, `match_root` and `match_identity` each called
  `normalize` on the same candidate: three `PathBuf` allocations per item for a
  string that does not change, on every path a scan produces (a scan builds
  every path by joining components onto an absolute root). `normalize_cow`
  borrows when `is_normalized` says the bytes are already in that shape, and
  `match_root_normalized` / `match_identity_normalized` take that value instead
  of normalizing again. The public pair still normalizes, so no other caller
  changed. `is_normalized` is conservative: it answers `true` only when
  `normalize` would be a byte-for-byte no-op, and it refuses a `..` tail that
  `normalize` would keep, which is why the validator's traversal check still
  runs first. A test generates every noisy shape from the corpus and asserts the
  implication in one direction only — `true` implies unchanged — plus that every
  already-normal corpus path takes the borrowed branch.
* **The plan sort reads a depth it counted once.** `Plan::finish` ordered items
  deepest-first by computing `paths::depth` for both sides of every comparison,
  which re-parsed two paths tens of millions of times on a full cache. The depth
  is now recorded when the item is built, next to the private physical path, so
  it cannot drift from the path it describes. The order is unchanged, not merely
  equivalent for one sample: the ordering test also asserts that every recorded
  depth equals its path's, and `--only system` keeps the same plan hash and the
  same item count.
* **"Is a blocked entry at or under this directory" is indexed, not asked per
  pair.** The planner must not schedule a directory whose contents it only partly
  knows, so `sweep_candidates` asked `blocked_within` for every directory. That
  is one comparison per *(directory, block)* pair: `~/.cache/uv` holds 1,037,504
  directories and its walk blocks 1,022 paths, so the question was answered a
  billion times and cost sixteen seconds of a preview. `Collect::blocked_ancestors`
  builds the answer once, from the parents of each blocked path, and the planner
  does one lookup per directory. A test holds the index to `blocked_within` over
  every entry of a walk with two exclusions plus paths the walk never reached.
* **The dedup sets are hash sets.** `Plan::seen` (two rules must not schedule the
  same path) and the funnel's `settled` (a `.trashinfo` record may only follow a
  payload that was removed) were `BTreeSet<PathBuf>`, whose `Ord` compares paths
  component by component. Both are one insert per planned item, so a million-item
  plan spent eight seconds there; a hash set asks the same question in one pass.
  Neither set is ever iterated, so no output depends on their order, and the plan
  hash is unchanged: `--only system` still gives `dedc716a805a8061` with 449
  items, `--only dev-tools` `2bdfc5b39b93320b` with 1,218,377.

Measured on the same machine and catalog: `clean --dry-run` 2m15s → 1m35s after
the deduplication, and 1m50s after the sort fix on a plan that had grown by about
150,000 items in the meantime. The per-item validation of a 966,645-entry
package cache went 32s → 17s, and the plan sort 35s → 2.8s.

A later pass found the same waste outside validation, and measured it on the
release binary: `--only dev-tools` took 1m12s before it and 45s after, and the
full `clean --dry-run` 1m51s → 1m17s. The remaining per-item cost is syscalls -
`canonicalize` of the parent, `lstat`, and the immutable-flag `ioctl` - not
bookkeeping.

### Reason codes are an API

`Reason::code()` strings appear in `--json` output and in the operation log. They
are stable: renaming one breaks user scripts and log correlation. The closed set
is pinned by `reason_codes_are_unique` and by the fuzz target's
`REASON_CODES` table. `ignored` and `holds_ignored` are the two the user can act
on directly: the first names the line, the second says a directory still holds
something that line protects.

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

The downloads directory is not on that list, and it does not need to be. It is
not an XDG base: it comes from `XDG_DOWNLOAD_DIR` in `user-dirs.dirs`, and its
only role is being a rule root. A rule root is refused as a target by
`allowed_root_itself` and `root_itself`, so `~/Downloads` cannot be removed
whole. A value that is relative, a protected root, an ancestor of `$HOME`, or
the marker for a disabled directory falls back to `~/Downloads` with a warning;
a deletion root is never taken from the environment.

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

### A pair is ordered by the sink, not by the sort

Emptying the trash removes two files per entry: the payload and the
`.trashinfo` record that names it. The record must follow the payload, and
`Plan::finish` sorting deepest-first is not enough to promise that — a shallow
payload ties with its record on depth, and a refused payload would still take the
record with it.

So a record carries the payload it depends on (`PlanItem::after`), and the sink
keeps a set of the paths it removed or would remove in this run. A record whose
payload is not in that set is skipped with `payload_remains`. A preview settles
the same set with `WouldRemove`, which is what keeps dry run and apply in
agreement. Pinned by `a_trash_record_is_removed_after_its_payload`,
`a_record_whose_payload_was_not_removed_is_kept` and
`a_preview_settles_a_pair_the_same_way_the_apply_does`.

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

### A move writes its record after both handles are open

The trash is the one sink that moves instead of unlinking. `Trash::send` opens
the source's parent and the destination's `files` directory — the home trash's or
the entry's own mount's — with those same no-symlink handles, and only then
writes the `.trashinfo` record and renames. Opening a directory can
refuse but can never move anything, so doing it first means a refusal — a
symlinked ancestor, a permission denial — leaves the trash untouched instead of
a record offering to restore a payload that was never sent. A record whose
rename then fails is removed, because a payload without a record would be
invisible to every restore tool while a record without a payload is a broken
entry in all of them. Pinned by
`a_symlinked_ancestor_refuses_rather_than_redirecting` and
`a_missing_entry_is_gone_not_an_empty_trash_entry`.

`free_name` treats a name as taken when *any* directory entry carries it,
not when `exists()` says so: a dangling link is invisible to `exists()`, but
`renameat` onto it would replace the entry instead of placing the payload beside
it. Pinned by `a_dangling_link_in_the_trash_still_occupies_its_name`.

### The move refuses a name that appeared under it

Searching for a free name and moving onto it are two steps, so the name can be
taken in between by another sweep, a file manager emptying its own trash, or the
same command in another terminal. A plain `renameat` would replace whatever
arrived there, which deletes that process's payload while its `.trashinfo`
record still describes it — data lost inside the one directory the user was
told is recoverable.

The move uses `RENAME_NOREPLACE`, so that race is `EEXIST`, and the caller
removes the record it had just written and looks for the next free name, up to
eight times before refusing with nothing moved. The names tried are still
`name`, `name.1`, `name.2`, so a restore reads the same shape it always did.
Pinned by `a_move_never_replaces_a_name_that_appeared_under_it`, and the
check-then-rename window that remains where the flag is unavailable is residual
risk R13.

### A top-directory trash is borrowed, never invented

`renameat` cannot cross a mount, so an entry on another filesystem is moved into
that mount's own trash. Which directory that is follows the specification, and
every way it can be wrong is a refusal:

- `<mount>/.Trash` must be a real directory with the sticky bit. Without the bit,
  one user could rename another user's directory inside it, so it is not used.
- `<mount>/.Trash/<uid>` is created only inside such a shared directory, mode
  `0700`, and an existing one must be a directory this user owns.
- `<mount>/.Trash-<uid>` is used when it exists, must be owned by this user, and
  is **never created**: a directory in a mount's root belongs to whoever
  administers the mount.
- None of those four names may be a symbolic link. `symlink_metadata` decides, and
  the handle is opened with the same no-symlink flags as every other move, so a
  link cannot redirect the payload.
- A path inside `.Trash` or `.Trash-<uid>` is refused by name, because trashing a
  trashed payload would strand it somewhere no restore tool looks.

When no directory qualifies the refusal names the exact one to create
(`<mount>/.Trash-<uid>`, owned by the user, mode `0700`) instead of copying and
deleting, which would turn a recoverable move into an operation that can be
interrupted halfway. The mount is found through the same `/proc/self/mountinfo`
table `doctor` prints, and the comparison is a mount-point comparison rather than
a device comparison because a btrfs subvolume carries an anonymous `st_dev` that
mountinfo never mentions. Pinned by
`an_entry_on_another_mount_lands_in_that_mounts_trash`,
`a_mount_without_a_trash_directory_refuses_and_names_the_one_to_create`,
`a_shared_trash_without_the_sticky_bit_is_refused`,
`a_shared_trash_directory_owned_by_another_user_is_refused`,
`a_symlinked_trash_directory_is_refused_rather_than_followed` and
`a_path_inside_a_trash_directory_is_never_trashed_again`.

Those tests build their mount table synthetically, so they prove the decision and
not that the decision survives contact with a real mount. The happy path was
measured on a machine whose `/var/tmp` is a separate btrfs subvolume: with no
`/var/tmp/.Trash`, the explorer refused and named the directory to create; after
`mkdir -m 1777 /var/tmp/.Trash`, the same keystroke moved a 64 KiB payload to
`/var/tmp/.Trash/1000/files/payload.bin`, wrote its `.trashinfo` with the
original path and a deletion date, and appended a `TRASHED` row. The synthetic
table keeps the edge cases — wrong owner, symlink, missing sticky bit — because
an unprivileged test cannot create them; the probe only shows that the resolved
paths match what the table says.

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

`(dev, ino)` is not a unique name for a file on every filesystem. Overlayfs
reports the underlying layers' numbers, so a file in the upper layer can share
both with an unrelated file in the lower one, and the hit then refuses a file
nobody holds open. That is the safe direction - the scan can only add refusals,
never remove one - but it means the pair proves "an open handle carries this
key", not "this path is open". A test therefore states its open set
(`RealProbe::with_open_inodes`) instead of snapshotting the machine; otherwise a
collision on the runner decides what the test observes.

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
* **The interactive explorer is exercised through a real terminal.** `tests/tui.rs`
  allocates a pseudo-terminal, starts the binary inside it, types the keys a
  person would and reads the screen back, so the draw loop, the confirmation and
  the move are covered end to end rather than through the app's methods. Because
  it drives the binary instead of calling the app, it is also the only place a
  declined confirmation can be shown to leave the payload and the trash untouched
  — the app's own test can assert only that the key returns no action. Pinned by
  `the_explorer_draws_a_screen_and_quits_on_q`,
  `confirming_a_move_puts_the_entry_in_the_trash_with_its_record`,
  `keeping_the_entry_leaves_it_alone` and
  `a_bare_analyze_in_a_terminal_opens_the_explorer_over_the_home_it_was_given`.

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
never persist the choice across commands.

### The boundary is a second process, not a second identity

A system cache is root-owned, and the user process must not become root to read
it. So the work is split in two:

1. **Plan as the user.** Reading `/var/cache/man` needs no privilege. Every
   candidate is validated against an allowed root that requires its target to be
   owned by **uid 0** (`AllowedRoot::owned_by_root`), whatever uid is asking.
2. **Ask a second question.** `--yes` answers "delete this plan", not "become
   root". Elevation is its own consent: `--privileged` grants it, a terminal
   prompt asks for it, and a run whose stdin is not a terminal declines. The
   refusal is not an error: the root items are logged as `SKIPPED` /
   `not_elevated`, the user items still happen, and the summary says how many
   were left in place.
3. **Apply as root in the same binary.** The parent re-executes `sweep` through
   `run0` (preferred) or `sudo` with a **fixed argv** — `--`, the current
   executable, `__apply` — and the request on **stdin**. No shell exists between
   the two processes, so no path can be word-split, globbed or interpreted, and
   nothing on the command line can add an argument to a privileged program.

The child trusts nothing the parent says:

* It **re-derives its allowlist from the compiled catalog**, not from the
  overlay and not from the request. Only enabled `privilege = "root"` rules in
  the `system` section with a literal absolute root are included; a rule id it
  does not know refuses the whole request.
* It **re-checks `dev`/`ino`** against the plan, so a file swapped while the
  password prompt was open is skipped (`race_changed`), not removed.
* It **re-derives each rule's selection**, not just its root. A path check can
  prove `/var/log/wtmp` is inside the `system.log.rotated` root; only the rule
  knows it is not a rotated log. The child re-runs the rule's own scanner -
  the glob for `file-pattern`, the version ranking for `pkg-cache` - against the
  filesystem as it is now, and removes nothing outside the result
  (`not_selected`). A walk it cannot complete selects nothing. This also means
  a file whose age or version rank changed while the prompt was open is refused
  rather than removed: the child can only ever delete less than the parent
  planned.
* It **re-runs the full validation** as root, including the ownership pin, the
  mount checks, the snapshot refusal and the open-file scan. The parent's
  preview is not evidence; the child's own eyes are.
* It **never writes the operation log**. It prints one JSON line per item on
  stdout, and the user process appends those rows. Root therefore never opens a
  file inside the user's state directory, and the audit trail keeps one writer.
* It **refuses to run as anything but root**: typing the hidden command as a
  user exits 78 with a sentence naming what the command is, instead of a stack of
  `EACCES` failures.

Paths travel as **hex**, not text. A path is bytes; a lossy string would name a
different file, and the wire format is the one place where that mistake would be
invisible.

The trade-off is explicit: the elevated child is a little more code than a
`sudo rm` wrapper, and the alternative — one process that acquires privilege and
then keeps walking a directory tree — is a much larger privileged surface.

### A package removal is pacman's transaction

`uninstall` is the one command that changes the package database, and it does so
by not doing it. There is no `/usr` deletion path in sweep: the command asks
`pacman -Rs --print` what the transaction would be, shows exactly that, and then
runs `pacman -Rs --noconfirm` for the same names. A dependent that blocks the
removal is pacman's resolver answering, not a copy of its rules that could drift
from it.

The elevated argv is `run0 -- pacman -Rs --noconfirm <name>`. `pacman` is
**unqualified** on purpose: `run0` and `sudo` look it up in their own
root-controlled `PATH`, so a directory earlier in the invoking user's `PATH`
cannot become the package manager that runs as root. Names travel as separate
argv entries, never through a shell, and each one is checked before the argv is
built — no leading `-`, no `/`, no space, no control byte — on top of the check
that it appears in `pacman -Qe`.

A short list of packages the machine needs to boot (`base`, `pacman`, `glibc`,
`systemd`, the kernels, `filesystem`, `coreutils`, `bash`, `sudo`) is refused
with the reason. The list is deliberately small: it is the boot path and the
package manager, not every package that happens to matter to someone.

`-Rs` rather than `-Rns` keeps an edited configuration file as `.pacsave`, which
is the one thing a package manager can preserve for a file it no longer owns.

What pacman leaves in `$HOME` is the user's data, and it is the only part of
this command that sweep moves itself. Leftovers are matched by exact name in the
four XDG roots — `~/.config/<name>`, `~/.local/share/<name>`, `~/.cache/<name>`,
`~/.local/state/<name>` — with no prefix, suffix, case folding or vendor
wildcard, and they are sent to the freedesktop trash rather than deleted, through
the same code `analyze` uses. The move happens only after the removal succeeded:
a nonzero status means the package is still installed and its configuration is
still the one in use, so nothing is moved and every package in the transaction is
logged as `FAILED` / `pacman_failed`.

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

#### Why the parent is resolved per item, not per directory

Resolving the literal parent once and reusing the answer would remove the largest
remaining per-item syscall: `canonicalize` was 6.6s of a 45s
`clean --dry-run --only dev-tools`, whose 1,038,007 entries sit in 196,190
distinct parent directories.

It is not done, because the reuse would widen this risk from "between two adjacent
syscalls" to "between the first item under a directory and the plan". The
`dev`/`ino` comparison above does not narrow that wider window: the plan records
the `dev`/`ino` it read from the *resolved* path, so a stale resolution records the
stale path's own metadata, and the sink then confirms it instead of refusing it.
The coincidence this risk currently requires — a replacement directory holding an
entry with the same inode — would no longer be required.

A verified cache is possible: `lstat` the literal parent for every item and reuse
the resolved path only while its `dev`/`ino` are unchanged. That closes the
replaced-ancestor case and still removes most of the cost, but it leaves the case
where the literal parent reaches the same directory through a different chain while
the cached path reaches another one. That is a separate design with its own
sink-race tests, for about 5s of a command that runs once a week, so it stays open
rather than taken.

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

### R8. A root-only cache cannot be planned

Planning happens as the user, before any password is typed. A root cache with
`0700` permissions — `/var/cache/ldconfig` on a default Arch install — is
therefore invisible: the rule reports `permission denied`, the summary says the
cache could not be read, and nothing from it is planned. `/var/cache/ldconfig`
is disabled in the catalog for exactly that reason rather than shipped as a rule
that can never fire.

Solving this means the child would have to *propose* the items and the user
would confirm a plan built by root. That is a larger change, it weakens the
"the plan you confirmed is the plan that runs" property, and `aux-cache` is a few
hundred kilobytes — not worth the trade today. Caches that are world-readable,
which is most of them (`/var/cache/man`, `/var/cache/fontconfig`), plan normally.

### R9. The preview's open-file scan is weaker than the child's

`/proc/<pid>/fd` is readable only for the caller's own processes. The user
process therefore cannot see that a root daemon holds a file open, so a preview
may list an item the child will refuse. The direction of that error is the safe
one — the preview over-counts, the apply refuses — and the child, running as
root, performs the scan with full visibility before it removes anything.

### R10. The package cache does not know what is installed

`pkg-cache` orders versions by name and mtime, and it never reads the pacman
database. So a machine whose *installed* version is older than the newest
`keep_versions` - a deliberate downgrade, or a mirror that has moved on - can
have the installed archive planned for deletion. `paccache` behaves the same way
by default: it only consults `pacman -Q` when `-u` asks it to target uninstalled
packages.

The cost is bounded: the archive is re-downloadable from a mirror, and the
installed package itself is untouched, because the database lives in
`/var/lib/pacman` and `/var/lib` is a protected root. `keep_days` is the second
floor, so a version fetched recently survives whatever the count says. Making
this exact needs the package database, which the rule engine does not read, so
the `pkg:` requirement is refused at load rather than accepted and ignored.

### R11. A build artifact may contain a link the user meant to keep

Unlinking a link is the one removal whose meaning depends on the caller, so the
policy that permits it is chosen by the scanner, not by the rule file. Two walks
emit links: a `project-artifacts` tree, and the tree inside a `versions` entry.
Every other walk treats a link as a block, so the policy cannot reach it
(`Reason::LeafSymlink`). The plan records the fact (`PlanItem::is_symlink`), and
the funnel unlinks only an item the plan described as a link — a file that became
a link between the preview and the run is refused.

*What limits it:* the target is never opened, never followed and never removed.
`unlinkat(..., 0)` on a link removes the entry and nothing else. The policy flag
alone cannot put anything in a plan; only those two walks emit a link.
*What remains:* a link inside `node_modules` or a virtualenv that the user
deliberately created pointing at source they still want. The link itself is gone
and has to be recreated. That is the same consequence as removing the artifact
around it, since the artifact is the parent that made the link useful, but it is
a real consequence and it is why the unit is the artifact rather than the file.
A link inside a release tree is the same case at a smaller scale: it belongs to
the release being removed, and the installer writes it again with the release.

*Reported honestly:* the operation log records the link's own bytes (zero for a
link on most filesystems), not the target's size, because nothing was freed
there.

### R12. The launcher can move between the last read and the unlink

A `versions` rule decides which entry is live by reading the launcher symlink.
The plan waits for consent, and an update can unpack a new entry and re-point
the link while the question is on screen. The funnel re-checks
`st_dev`/`st_ino`, which catches a path that was swapped, but a launcher
re-point changes no inode, so it cannot catch this one.

*What limits it:* the launcher is read again after consent and before the first
unlink, and every planned item the link now names — or that sits inside the
entry it names — is withdrawn from the plan. A launcher that cannot be read at
that point withdraws everything its rule planned, because the answer the plan
was built from is gone. That leaves only the instant between the re-read and
the unlink, not the whole prompt. `--yes` closes most of what is left. The
consequence of that instant is a dangling launcher, not lost work: the removed
entry is a re-downloadable release, which is why the rule is
`recoverable = true`, and the tool's installer recreates the link on the next
run. Nothing inside the entry is user data — a `versions` root holds installed
releases, never configuration, sessions or transcripts.

*What remains:* an update that re-points the link in the microseconds between
the re-read and the unlink can still lose the release that just became current.
Closing it completely needs the installer to cooperate — a lock it takes while
it swaps the link — which no third-party tool offers, so this stays a stated
risk rather than a solved one.

### R13. A filesystem without `RENAME_NOREPLACE` reopens the name race

A move searches the trash for a free name and then renames onto it, and the two
steps cannot be one operation. `RENAME_NOREPLACE` closes the window: if anything
arrived under that name in between, the move answers `EEXIST` and the caller
looks for the next free name, so neither side loses a payload.

*What limits it:* a kernel older than 3.15 answers `ENOSYS` and a filesystem
that does not implement the flag answers `EINVAL`; both fall back to a plain
`renameat`, which silently replaces the entry that arrived first. Every
filesystem sweep is likely to meet — ext4, btrfs, xfs, tmpfs — implements the
flag, and the fallback exists so that an exotic mount can still receive a
trashed entry instead of refusing every move and losing the whole explorer
feature there.

*What remains:* on such a filesystem, a second process writing the same name into
the same trash during the same instant can still lose its payload. That is the
behaviour every plain-rename implementation has, it requires a concurrent writer
and a name collision, and it never touches a file outside the two trash
directories.

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
