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
section     = "dev-tools"               # required, one of the sixteen sections
kind        = "dir-age"                 # required, see below
root        = "{cache}/cargo"           # required, absolute, template allowed
evidence    = "Cargo re-downloads ..."  # required for deleting kinds
recoverable = true                      # required when keep_days = 0
keep_days   = 30                        # default 0
keep_versions = 2                       # pkg-cache only
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
`firmware`, `snapshots`, `installers`, `project-artifacts`, `model-caches`.

The list is closed. A new section is a product decision (it needs a row in the
`clean` report), not something a pack can invent.

`system` is the only section allowed to declare `privilege = "root"`, and the
only one whose items travel through the privilege boundary. Everything else runs
as the invoking user, which is why starting the whole program as root is refused
at startup rather than checked per rule.

### Sections another command owns

Three sections belong to a command of their own rather than to `clean`: `aur`
to `sweep aur`, `installers` to `sweep installer`, and `project-artifacts` to
`sweep purge`.
`Section::command()` is the single place that maps a section to its owner, and a
bare `sweep clean` lists those rules with status `command_scoped` instead of
scanning them. Naming the section with `--only` still works - that is a user
asking for it by name, and the report says so.

The split is about the walk, not about danger. `clean` opens paths the rule
already names; `installer` reads a directory the user fills by hand, `aur` has to
explain why the clone beside the archive is kept, and `purge` walks project roots
looking for a manifest. Each needs its own preview and its own confirmation, and
none belongs in a bare `clean`.

### Opt-in sections

`model-caches` is the only opt-in section today, and `Section::is_opt_in` is the
single place that decides it. A bare `sweep clean` does not scan it at all: the
rules are listed with status `OptIn` and the summary carries a note saying the
section was not scanned and how to review it. `sweep clean --only model-caches`
is the consent. The rules stay `enabled = true`, so naming the section is enough
and there is no second switch to keep in sync with the first.

The reason is not squeamishness about size. A model blob is the one target whose
absence may not be recoverable: a gated repository needs a licence acceptance, a
private one needs a token, and an offline machine can reach neither. A default
run must not decide that for the user.

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
| `trash-empty` | each trashed payload and the `.trashinfo` record that names it, in that order | must be 0: the whole trash goes |
| `hf-cache` | blobs no `snapshots/` link resolves to, plus abandoned `*.incomplete` downloads | must be > 0 |
| `pkg-cache` | every package version outside the newest `keep_versions`, and its detached `.sig` | `keep_versions` required; `keep_days` is a recency floor |
| `project-artifacts` | build directories inside project roots, found by the manifest beside them, plus symbolic links inside them | applied; must be > 0 on a `{home}` root |
| `report-only` | nothing; counts entries and bytes | informational |

A retention the kind cannot read is a load error (`ignored_keep_days`), not a
number printed by `rules list` that the run silently disobeys.

`if-missing-owner` and the `pkg:` requirement prefix are recognised as valid
spellings but refused at load: the rule engine does not read the package
database, so it cannot tell whether an owner is installed. Refusing them beats
accepting a rule that quietly does nothing. `if-missing-owner` names
`report-only` as the supported alternative, and `pkg:` names `bin:` and `dir:`.

### The `hf-cache` rule, precisely

`huggingface_hub` stores every file once as `blobs/<etag>` and links it into
`snapshots/<revision>/<path>`. Sweeping `blobs/` as an ordinary cache leaves
every snapshot pointing at nothing: the model still looks installed, fails at
load time, and never re-downloads, because its revision is still in `refs/`. So
the kind has its own scanner (`crates/sweep-core/src/model_cache.rs`) and plans
exactly two things:

1. a complete blob that no symlink below `snapshots/` resolves to, once it is
   older than `keep_days`;
2. an `*.incomplete` download older than `keep_days`.

Links are read with `read_link` and resolved lexically. Nothing is followed, so
a snapshot entry pointing at `/etc/shadow` is a string compared against blob
paths, never a file sweep opens. A repository whose `snapshots/` tree cannot be
read completely is preserved whole and named in the report: an unreadable
reference set is not an empty one, and the cost of guessing wrong is a silently
broken model. `keep_days = 0` is refused at load (`unsafe_retention`), because
the hub writes the blob before the link that references it.

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
excluded.

`~/.config/sweep/ignore` uses the same language, but it is the user's file
rather than the catalog's: it is anchored to `$HOME` (or to `/` for a line
starting with `/` or `~`), it protects a path and everything below it, and it
applies to `clean`, `purge`, `installer` and `aur`. The README has the shape;
`crates/sweep-core/src/ignore.rs` is the reference. At load time, wildcards alone are refused only for a `{home}` root,
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
| `unknown_section` | the section is not one of the sixteen |
| `unknown_kind` | the kind is not one of the eight |
| `unsupported_kind` | the kind exists but is not implemented yet (`if-missing-owner`) |
| `bad_privilege` | the value is neither `user` nor `root` |
| `template` | the root is relative, empty, contains `..` or a control byte, mixes a variable with text, or names an unknown variable |
| `protected_root` | a deleting rule resolves inside the compile-time protected list (`/usr`, `/etc`, `/var/lib`, …) |
| `bare_root` | a deleting rule resolves to a base directory, to `/`, or to a kernel pseudo-filesystem |
| `missing_evidence` | a deleting rule has no `evidence` line |
| `zero_keep_days` | `keep_days = 0` without `recoverable = true` (`trash-empty` is exempt: its target is user data by definition) |
| `unsafe_retention` | `kind = "hf-cache"` with `keep_days = 0` (a blob with no snapshot link may be a download that has not finished), or `kind = "project-artifacts"` rooted at `{home}` with `keep_days = 0` (every build directory below `$HOME` is a project someone may be in right now) |
| `root_privilege` | `privilege = "root"` on a deleting rule outside the `system` section |
| `missing_pattern` | `kind = "file-pattern"` with no `pattern` |
| `unused_pattern` | `pattern` on a kind that does not read it |
| `bad_pattern` | a pattern is empty, absolute, ends with `/`, has a control byte, or is wildcards only on a `{home}` root |
| `missing_keep_versions` | `kind = "pkg-cache"` with no `keep_versions` |
| `unused_keep_versions` | `keep_versions` on a kind that does not read it |
| `bad_keep_versions` | `keep_versions = 0`, which would leave no version of anything in the cache |
| `ignored_keep_days` | `dir-sweep` or `tool-cache` declares `keep_days > 0`, which that kind never reads |
| `trash_layout` | `kind = "trash-empty"` with a root other than `{data}/Trash`, a non-zero `keep_days`, a `max_depth`, a `pattern`, an `exclude`, or `privilege = "root"` |
| `requirement` | a `requires` entry is not `bin:<name>` or `dir:<path>` |
| `bad_depth` | `max_depth` is 0 or greater than 32 |

Two of these carry a wider meaning:

- **A base directory may only be a deleting root as `dir-age`.** `{cache}` and
  `{runtime}` are the only two that may be one at all, and `{cache}` is the
  residual sweep: applications must tolerate losing cache data, and seven idle
  days is measured rather than assumed. Without the age gate, one rule would
  mean "empty the cache, always".
- **`{home}` may only be a root for `file-pattern` or `project-artifacts`, with
  `max_depth <= 6`, and a `file-pattern` must name literal text.**
  `.xsession-errors*` is a target; `*` is a way to delete a home directory one
  file at a time. `project-artifacts` has no pattern to widen: it never names a
  file, it finds a project by its manifest and then removes the build output
  that manifest produced, and a `{home}` root also needs `keep_days > 0`.

### The `project-artifacts` rule, precisely

A build directory is not evidence of anything on its own. `node_modules` may be
a vendored directory someone wrote by hand; `target` may be a data folder. The
rule therefore reads manifests, not names:

* a **project root** is a directory containing one of `package.json`,
  `Cargo.toml`, `go.mod`, `pyproject.toml`, `pom.xml`, `build.gradle`,
  `Gemfile`, `terragrunt.hcl`, `composer.json` or `.git`;
* an **artifact** is selected only when the manifest that produces it is in the
  same directory — `node_modules` needs `package.json`, `target` needs
  `Cargo.toml` or `pom.xml`, `.venv`/`venv` needs a Python manifest, `vendor`
  needs `go.mod`, `composer.json` or `Gemfile`, and so on;
* `.git` is never a target, and the walk never descends into an artifact, so the
  `package.json` shipped inside a dependency does not turn it into a project;
* `~/.cargo`, `~/.rustup`, `~/.cache`, `~/.local`, `node_modules` and `target`
  are never walked as project roots;
* depth is bounded by `max_depth`, links are not followed, and a mount is not
  crossed.

`keep_days` is a recency floor, not an age filter in the usual sense: installing
a dependency updates the artifact directory, so a directory older than a month
has not been touched by a build since then. `keep_days = 0` is refused on a
`{home}` root — the project you are in the middle of is the one you least want
emptied — and any positive window is allowed.

One artifact is all-or-nothing. If any entry below it cannot be read, or the
walk hits its entry or time budget, the whole artifact is left in place and
counted under "left alone", with the reason. A partially removed `target/` is
neither built nor clean, so it is the one outcome worth refusing.

Symbolic links inside an artifact are planned as links and removed as links. The
plan records that the entry was a link, and the funnel unlinks the entry itself;
the target is never opened and never followed. This is a policy flag the pipeline
sets when the run includes `project-artifacts`, not a rule key: Node's `.bin`
directory and a virtualenv's `bin/python3` are links the package manager wrote,
and a sweep that leaves them behind leaves a tree that still looks installed.
Every other section keeps the default refusal, because a link inside a cache
root (`~/.cache/foo -> /mnt/big/foo`) is usually the user's own arrangement.

### The `pkg-cache` rule, precisely

`/var/cache/pacman/pkg` has no sensible age cutoff. The archive that matters is
the newest one, whatever its date, and an age proxy deletes the only copy of the
running kernel's package on a machine that has not been upgraded in months -
which is exactly when a rollback is the thing you want. So the retention is a
version count, the way `paccache` does it.

1. Names are parsed from the right:
   `name-[epoch:]pkgver-pkgrel-arch.pkg.tar.<compression>[.sig]`. The name may
   contain hyphens; the architecture, release and version may not.
2. Versions are ordered with pacman's own algorithm
   (`crates/sweep-core/src/version.rs`), not a text sort: `1.10` outranks `1.9`,
   `1.0` outranks `1.0rc1`, and an epoch outranks everything.
3. The grouping key is `(name, arch, evr)`. One generation is one archive plus
   its detached `.sig`, and a signature never uses up a version slot.
4. The newest `keep_versions` generations of each `(name, arch)` are kept, and a
   generation modified within `keep_days` is kept regardless: a version
   downloaded yesterday is a downgrade in progress.
5. A `.sig` whose archive is gone is planned once it is older than `keep_days`.
6. Anything that does not parse - `download-XXXXXX`, `*.part`, a directory - is
   counted as unrecognised and left alone. A scan that does not complete plans
   nothing, because ordering versions from a partial listing can rank the
   newest generation against a set that is missing entries.

On a stock Arch cache this matched `paccache -d -k2` file for file - 170 paths
and the same byte total - when the handler was verified. The version comparison
itself has an automated differential test against `vercmp`, skipped where pacman
is not installed.

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
sweep clean --dry-run --only model-caches   # the opt-in section, reviewed first
sweep clean --dry-run --only system         # root-owned caches, previewed read-only
sweep clean                  # plan, ask once, delete through the funnel
sweep clean --yes            # plan and delete; the form a script can use
sweep clean --yes --privileged   # also sweep root-owned system caches
```

| Exit code | Meaning |
|---|---|
| 0 | the command did what it says |
| 1 | an applied run hit a syscall failure (the log has the reason per item), the report could not be serialised, or `--privileged` could not elevate |
| 2 | usage error: unknown command, flag or section |
| 3 | the catalog did not compile; the reason is printed, and `--json` carries it |
| 4 | reserved for commands a later milestone wires up |
| 5 | the run was not confirmed; nothing was deleted and nothing was recorded |
| 78 | this environment cannot run sweep (`$HOME` is not usable, the process is root, or `__apply` was invoked by a non-root user) |

`--yes` and `--dry-run` together are a usage error: they ask for opposite
things, and guessing which one wins is how a preview turns into a deletion. A
run with neither asks on the terminal and refuses on a pipe, naming `--yes`, so
an unanswered question is never an implied yes.

A confirmed run records one row per planned item in
`~/.local/state/sweep/operations.jsonl` (`REMOVED`, `SKIPPED` with a reason code,
or `FAILED`) and reports the plan hash it applied. A dry run, a declined prompt,
and a plan with nothing in it write no log at all.

### Rules with `privilege = "root"`

Only the `system` section may delete as root; a root rule anywhere else is a
load-time `root_privilege` error. Those rules are planned by the user process —
reading a cache needs no privilege — and then handed to an elevated child by
`sweep clean --privileged`, or after a yes at the prompt.

The child does not read this file's overlay. It compiles `rules/01-system.toml`
alone, from the binary, and accepts only enabled root rules with a **literal
absolute root**: a template would expand against whichever `$HOME` the elevated
process inherited, and the parent and child would not be agreeing about a path.
A rule whose root is a directory the user cannot read (mode `0700`) cannot be
planned at all, so it is disabled rather than shipped as a rule that always
reports `permission denied`.

## Adding a rule

1. Add it to the pack for its section, with an `evidence` line a user can read.
2. Prefer `dir-age` over `dir-sweep` when the tool tolerates stale data. A
   retention of 0 means "delete what is not open right now", and that claim
   needs `recoverable = true`. `dir-sweep` and `tool-cache` cannot carry a
   retention at all; if you want a window, that is `dir-age`. `trash-empty` is
   the one exception: the file is in the trash because the user already deleted
   it, so it declares `recoverable = false` and still empties immediately.
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
