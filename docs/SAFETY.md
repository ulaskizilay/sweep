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
