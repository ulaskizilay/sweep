# The rule catalog

A rule is data. It names a directory, a kind, how long an entry must be idle,
and the sentence that says why deleting there is safe. Rules never delete:
they describe what may be **scanned**, and every candidate they produce still
goes through [`validate`](SAFETY.md#the-shape-of-the-program) before the funnel
sees it.

Two properties make the catalog reviewable rather than trusted:

- **A rule that is wrong refuses to load.** A root inside `/usr`, an id that
  collides, a typo in a key name: `sweep` stops before it reads a directory.
- **A rule that loads is still checked per item.** The rule says "this tree is
  disposable". Validation re-decides, file by file, with the mount table, the
  live-handle scan and the protected-path list.

## Where rules live

| Path | Who edits it | When it is read |
|---|---|---|
| `rules/NN-<section>.toml` | the sweep repository | compiled in with `include_str!` at build time |
| `~/.config/sweep/rules.d/*.toml` | the user | every run, after the built-ins, in file-name order |

The built-in packs are **not** read from disk at runtime. Editing a file in the
source tree has no effect on an installed binary until it is rebuilt, which is
why the user overlay exists: it is the only supported way to change behaviour
without compiling.

## Schema

```toml
[[rule]]
id          = "dev.cargo.crate-cache"     # required, namespaced, unique
section     = "dev-tools"               # required, one of the fifteen sections
kind        = "dir-age"                 # required, see below
root        = "{cache}/cargo"           # required, absolute, template allowed
evidence    = "Cargo re-downloads ..."  # required for deleting kinds
recoverable = true                      # required when keep_days = 0
keep_days   = 30                        # default 0
requires    = ["bin:cargo"]             # default []
privilege   = "user"                    # required: "user" or "root"
exclude     = ["registry/src/**"]       # default [], relative globs
pattern     = ["*.log"]                 # file-pattern only
max_depth   = 8                         # default 8, 1..=32
enabled     = true                      # default true
```

Unknown keys are a parse error (`deny_unknown_fields`). This is deliberate:
`keep_day = 30` must not silently become `keep_days = 0`, which means "delete
everything that is not open right now".

A pack file may start with a `[meta]` table (`name`, `description`) for
documentation. It has no effect on behaviour.

### Sections

`system`, `user-essentials`, `app-caches`, `browsers`, `cloud-office`,
`dev-tools`, `apps`, `virtualization`, `local-data`, `orphans`, `aur`,
`firmware`, `snapshots`, `large-files`, `project-artifacts`.

The list is closed. A new section is a product decision (it needs a row in the
`clean` report), not something a pack can invent.

### Root templates

A root is absolute and may contain these variables, each standing alone as a
whole path segment:

| Variable | Resolves to |
|---|---|
| `{home}` | `$HOME` |
| `{cache}` | `$XDG_CACHE_HOME`, default `~/.cache` |
| `{config}` | `$XDG_CONFIG_HOME`, default `~/.config` |
| `{data}` | `$XDG_DATA_HOME`, default `~/.local/share` |
| `{state}` | `$XDG_STATE_HOME`, default `~/.local/state` |
| `{runtime}` | `$XDG_RUNTIME_DIR`, default `/run/user/<uid>` |

`{home}/.cargo` is valid. `{home}.cargo` is refused: it expands to
`/home/alice.cargo`, which is almost always a typo and invisible when reading
the file. `..` is refused for the same reason.

## Kinds

| Kind | Deletes | Retention |
|---|---|---|
| `dir-sweep` | every entry below the root; the root stays | must be 0: everything goes |
| `dir-age` | each top-level entry whose whole subtree is older than `keep_days` | applied |
| `file-pattern` | files below the root whose relative path matches `pattern` and are older than `keep_days` | applied |
| `tool-cache` | every entry below the root, **and then the root** | must be 0: everything goes |
| `report-only` | nothing; counts entries and bytes | informational |

A retention the kind cannot read is a load error (`ignored_keep_days`), not a
number printed by `rules list` that the run silently disobeys.

`if-missing-owner` and the `pkg:` requirement prefix are recognised as valid
spellings but refused at load: they need the package database and arrive in M5.
Refusing them beats accepting a rule that quietly does nothing.

### The `dir-age` rule, precisely

The scan is grouped by the first path component below the root. A group is
planned only when **all** of these hold:

1. every entry the walk emitted in that group is older than the cutoff;
2. the walk left nothing in that group alone — no exclusion, no other rule's
   claimed root, no symlink, no mount point, no unreadable directory, no depth
   limit, no other device.

A single fresh file keeps its whole subtree. So does a symlink, because the
newest part of the tree is then unknown, and unknown is not "old". The root
itself is never planned.

The newest mtime comes from every entry in the group *and* the cutoff comparison
is `>=`: a group with one entry exactly at the cutoff is kept, and a fresh child
keeps its parents.

### What never happens inside a rule root

- Symlinks are not followed and not deleted. They also stop their parent
  directory from being planned, because the parent cannot be emptied.
- Anything on another `st_dev` is skipped. On btrfs this is what keeps a
  subvolume from being walked as if it were part of its parent.
- A bind mount is skipped by mount-point identity even though `st_dev` matches.
- A directory that would still hold a skipped entry is not planned: the funnel
  cannot recurse, so planning it would only produce `ENOTEMPTY`.
- A scan that hits its entry or time budget plans **nothing at all** for that
  rule. A half-seen tree is exactly where "the newest file is old" is a lie.

## Patterns

`exclude` and `pattern` use a deliberately small glob language:

| Form | Matches |
|---|---|
| `*` | any run of bytes except `/` |
| `?` | one byte except `/` |
| `**` | any run of bytes including `/` |
| `a/**/b` | `a/b` too: `**/` matches zero segments |
| `logs/**` | `logs` itself and everything below it |

No character classes, no braces, no dependencies. A pattern is matched against
the path relative to the rule root, on bytes, so a non-UTF-8 name can still be
excluded. At load time, wildcards alone are refused only for a `{home}` root,
where `*` would mean deleting a home directory one file at a time. Every
shipped `file-pattern` rule is also required by the corpus test to name at
least one literal fragment.

## Load-time validation

Every check below applies to the built-in packs and to the overlay equally.

| Code | Refused when |
|---|---|
| `toml` | the file is not valid TOML, or has an unknown key |
| `no_rules` | the pack contains no `[[rule]]` |
| `read_failed` | a file in `rules.d` could not be read |
| `bad_id` | the id is empty, longer than 64 bytes, or has a character outside `[a-z0-9._-]` |
| `duplicate_id` | the id already exists — including a built-in id, so the overlay cannot replace one |
| `unknown_section` | the section is not one of the fifteen |
| `unknown_kind` | the kind is not one of the five |
| `unsupported_kind` | the kind exists but is not implemented yet (`if-missing-owner`) |
| `bad_privilege` | the value is neither `user` nor `root` |
| `template` | the root is relative, empty, contains `..` or a control byte, mixes a variable with text, or names an unknown variable |
| `protected_root` | a deleting rule resolves inside the compile-time protected list (`/usr`, `/etc`, `/var/lib`, …) |
| `bare_root` | a deleting rule resolves to a base directory, to `/`, or to a kernel pseudo-filesystem |
| `missing_evidence` | a deleting rule has no `evidence` line |
| `zero_keep_days` | `keep_days = 0` without `recoverable = true` |
| `root_privilege` | `privilege = "root"` on a deleting rule outside the `system` section |
| `missing_pattern` | `kind = "file-pattern"` with no `pattern` |
| `unused_pattern` | `pattern` on a kind that does not read it |
| `bad_pattern` | a pattern is empty, absolute, ends with `/`, has a control byte, or is wildcards only on a `{home}` root |
| `ignored_keep_days` | `dir-sweep` or `tool-cache` declares `keep_days > 0`, which that kind never reads |
| `requirement` | a `requires` entry is not `bin:<name>` or `dir:<path>` |
| `bad_depth` | `max_depth` is 0 or greater than 32 |

Two of these carry a wider meaning:

- **A base directory may only be a deleting root as `dir-age`.** `{cache}` and
  `{runtime}` are the only two that may be one at all, and `{cache}` is the
  residual sweep: applications must tolerate losing cache data, and seven idle
  days is measured rather than assumed. Without the age gate, one rule would
  mean "empty the cache, always".
- **`{home}` may only be a root for `file-pattern`, with `max_depth <= 6` and a
  pattern that names literal text.** `.xsession-errors*` is a target; `*` is a
  way to delete a home directory one file at a time.

`report-only` is exempt from most of this because it never contributes a plan
item. It may read a protected tree such as `/var/log/journal`, which is how the
journal size is reported. It may not walk `/proc`, `/sys`, `/dev` or `/`.

## The user overlay

`~/.config/sweep/rules.d/*.toml` is read after the built-in packs. It can only
**add** rules. Re-using a built-in id is a `duplicate_id` error, not an
override, because "same id, different root" is exactly how a config file would
widen what the compiled policy allows.

A rule added by the overlay is held to every check above, including the
protected-root list. There is no opt-out flag, by design: a rule that could
disable the list would only be safe until the first typo.

## Commands

```bash
sweep rules list             # the whole catalog: section, kind, retention, resolved root
sweep rules list --verbose   # ... plus requirements, patterns, excluded paths, evidence
sweep rules list --json      # the same data as one document
sweep rules verify           # compile built-ins + overlay and report every error
sweep clean --dry-run        # the plan, with per-section and per-rule detail
sweep clean --dry-run --only dev-tools
sweep clean                  # plan, ask once, delete through the funnel
sweep clean --yes            # plan and delete; the form a script can use
```

| Exit code | Meaning |
|---|---|
| 0 | the command did what it says |
| 1 | an applied run hit a syscall failure (the log has the reason per item), or the report could not be serialised |
| 2 | usage error: unknown command, flag or section |
| 3 | the catalog did not compile; the reason is printed, and `--json` carries it |
| 4 | reserved for commands a later milestone wires up |
| 5 | the run was not confirmed; nothing was deleted and nothing was recorded |
| 78 | this environment cannot run sweep (`$HOME` is not usable, or the process is root) |

`--yes` and `--dry-run` together are a usage error: they ask for opposite
things, and guessing which one wins is how a preview turns into a deletion. A
run with neither asks on the terminal and refuses on a pipe, naming `--yes`, so
an unanswered question is never an implied yes.

A confirmed run records one row per planned item in
`~/.local/state/sweep/operations.jsonl` (`REMOVED`, `SKIPPED` with a reason code,
or `FAILED`) and reports the plan hash it applied. A dry run, a declined prompt,
and a plan with nothing in it write no log at all.

## Adding a rule

1. Add it to the pack for its section, with an `evidence` line a user can read.
2. Prefer `dir-age` over `dir-sweep` when the tool tolerates stale data. A
   retention of 0 means "delete what is not open right now", and that claim
   needs `recoverable = true`. `dir-sweep` and `tool-cache` cannot carry a
   retention at all; if you want a window, that is `dir-age`.
3. Add a test that proves **what it does not delete** — a fresh file, a
   symlink, an excluded directory, a claimed root. The negative space is the
   part that matters.
4. Run `cargo test -p sweep-core --test rules_corpus`. The catalog digest will
   fail; update `EXPECTED` in the same commit so the review diff shows that the
   safety-relevant shape of the catalog moved on purpose.
5. Run `sweep rules verify` and `sweep clean --dry-run` on a real machine. A
   rule that plans nothing because a requirement is never satisfied is a rule
   that should be deleted, not documented.
6. If the rule targets a tool, check it on a machine that has the tool. A rule
   written from the documentation only is a guess.
