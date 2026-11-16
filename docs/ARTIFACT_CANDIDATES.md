# Artifact candidates: ccache retention and Android `.cxx`

**Status:** the probe is implemented; no rule changed. `dev.ccache` stays
`dir-sweep`, and there is no `.cxx` rule. Both decisions have a number attached
and a sample behind them, so the next machine that disagrees with this one can
reopen them without re-deriving the question.

## The question

Two queue items were waiting on the same kind of evidence: a target that might
deserve different handling, with no measurement from a real disk.

- **`dev.ccache`** already exists in `rules/06-dev-tools.toml` as a `dir-sweep`:
  every `clean` empties `{cache}/ccache`, so the next build starts cold. The
  open question was whether `dir-age` with a 7-day floor would keep the hot set
  and still reclaim the rest. That only pays if a meaningful share of the
  directory is actually hot.
- **Android `.cxx`** is the NDK's intermediate tree. It sits beside a JVM
  manifest, so a `project-artifacts` rule would be one line in the table. What
  was missing is the magnitude: a rule for a directory that holds a few
  megabytes on every machine is surface for nothing.

## The thresholds, fixed before the sample

| Candidate | Change | Threshold |
|---|---|---|
| `dev.ccache` | `dir-sweep` → `dir-age`, `keep_days = 7` | ≥ 500 MiB **and** ≥ 25% of those bytes newer than 7 days |
| `project .cxx` | new `project-artifacts` rule, `requires: JVM` | ≥ 3 **user-project** directories, ≥ 1 GiB together, newest file > 7 days |

Below the ccache line the hot set is too small to be worth a second retention
policy: `dir-sweep` already matches the data. A `max_size` in `ccache.conf`
overrides the first line entirely - the tool bounds itself, sweep does not run a
tool's own cache command, and the finding becomes "report it, advise
`ccache --trim`".

A `.cxx` inside a package cache does not count toward the `.cxx` line. The cache
rule that owns the parent already takes the tree; a second rule on the child
would claim the same bytes twice.

## What the probe measured

`scripts/probe_artifact_candidates.py` is read-only, needs no sudo, and took
0.4 seconds on 16 November 2026. It walks `$HOME` at the catalog's default
project depth (6) and prints TSV, largest first.

- **ccache:** absent. `{cache}/ccache` does not exist on this machine, so there
  is no age distribution to read.
- **`.cxx`:** four directories, all under
  `~/.pub-cache/hosted/pub.dev/jni-*/android/.cxx`, 5.8 MiB, 5.9 MiB, 5.8 MiB
  and 2.4 MiB, newest 11, 5, 2 and 9 days old. Every one is tagged `cache=yes`
  and `jvm=yes`; **zero** are user projects. The pub.dev rule already owns their
  parent (`{home}/.pub-cache/hosted/pub.dev`), so they are reachable today and a
  `.cxx` rule would not free a byte that `dev.pub.cache` does not already free.

## What each column proves

| Column | Proves | Does not prove |
|---|---|---|
| `bytes` | accounted size (`st_blocks * 512`), the number `du` reports | the bytes are safe to remove |
| `entries` | how many files and directories make up that size | the tree is a build artifact |
| `newest` | days since the newest file below the root | the artifact is stale: a rebuild touches it |
| `jvm` | a JVM manifest sits in the directory holding it | the manifest produced this artifact |
| `cache` | the path is inside a package or tool cache | the cache rule is enabled on this machine |

`cache=yes` is the important one for `.cxx`: it is the difference between "a
user's Android project" and "a copy inside a package cache", and only the first
is a project-artifacts candidate.

## Decisions

- **`dev.ccache` stays `dir-sweep`.** The machine has no ccache, so there is no
  evidence that a hot set worth preserving exists. Reopen when a probe reports
  ≥ 500 MiB with ≥ 25% newer than 7 days, or a declared `max_size`.
- **No `.cxx` rule.** Zero user-project directories, and the four cache-side
  copies are already inside `dev.pub.cache`'s root. Reopen at ≥ 3 projects,
  ≥ 1 GiB, newest older than 7 days.
- Neither candidate gets a `status` row or a report-only rule in the meantime.
  A probe that finds nothing on one machine is not a dashboard.

## Running it

```bash
python3 scripts/probe_artifact_candidates.py                 # defaults
python3 scripts/probe_artifact_candidates.py --min-bytes 0   # every .cxx
python3 scripts/probe_artifact_candidates.py --seconds 60 --max-entries 4000000
```

The walk is bounded by `--max-entries` and `--seconds`; a budget that runs out
is reported as `walk truncated`, and a truncated size is a lower bound, not a
total. The whole output is pasteable, header lines included.
