# Packaging

A PKGBUILD lives here when someone can install it and get the same binary the
repository builds. Both packages exist.

| Directory | Package | Source |
|---|---|---|
| `sweep-cli-git/` | `sweep-cli-git` | `main`, at build time |
| `sweep-cli/` | `sweep-cli` | the `V*` tag's source tarball |

They conflict with each other on purpose: installing both would leave two owners
of `/usr/bin/sweep`, and pacman would have to pick one at the next upgrade.

## `sweep-cli`

Builds the released tag, so a version number names one commit:

```console
$ cd packaging/sweep-cli
$ makepkg -si
```

Built on 17 November 2026 without installing it: `makepkg -f --nodeps` finished
`sweep-cli 0.1.2-1` in 1m20s and produced a 1,527,205-byte
`sweep-cli-0.1.2-1-x86_64.pkg.tar.zst` holding 36 paths - the binary, the
licence, fifteen man pages and three completions. The binary extracted from that
archive prints `sweep 0.1.2` and its `rules verify` accepts the full catalog, and
`.PKGINFO` carries `conflict = sweep-cli-git`. `--nodeps` is only because this
machine installs `cargo` and `rust` through rustup rather than pacman.

`pkgver` tracks the tag the source tarball comes from, and the `sha256sums` is
that tarball's real hash rather than `SKIP`, so the build refuses a source that
is not the tag it names. Bumping either one is a release step: push the tag,
then `updpkgsums`, then `makepkg --printsrcinfo > .SRCINFO`, then commit.

GitHub generates the archive file on request and has regenerated them before, so
a `One or more files did not pass the validity check` after months of not
building this package is not a corrupted download. Re-run `updpkgsums` and treat
the new hash as a deliberate change, with its own commit and a fresh `makepkg`.
The alternative - packaging the release archive
(`sweep-<version>-x86_64-linux.tar.gz`), whose checksum is uploaded once and
cannot drift - ships a prebuilt x86_64 binary, which belongs in a `-bin` package
and would leave `aarch64` with nothing.

## Both packages, and the fakeroot trap

`build()` runs as your normal user; `package()` runs under fakeroot, where
`geteuid()` answers 0. `sweep` refuses to run as root on purpose, so generating
the completions or the man pages from `package()` fails the build with sweep's
own refusal message. That is exactly what happened on 17 November 2026, on the
first real build of these packages: `cargo test` passed, `package()` started, and
`sweep: refusing to run as root` ended the run.

So `build()` generates `gen/` as the user, and `package()` only installs files.
`crates/sweep-cli/tests/packaging.rs` holds that: it walks every
`packaging/*/PKGBUILD` and fails if `package()` calls the binary.

## `sweep-cli-git`

Builds the current `main`. The **package** version is `r<commits>.<short-sha>`,
because a tracking package cannot name a release it is not built from:

```console
$ cd packaging/sweep-cli-git
$ makepkg -si
```

Built on 17 November 2026 with `makepkg -f --nodeps`, which finished
`sweep-cli-git r84.91c25dc-1` and produced a 1,527,224-byte archive with the same
36 paths as `sweep-cli`. The binary reports the crate version the source declares,
which is what `--version` means everywhere else: the package version is the one
that names the commit, and the two differ on purpose. When the commit matters - a
bug report, a rebuild - quote the package version.

`cargo build` and `cargo test` both run with `--locked --offline`, so the
dependency versions are the ones in `Cargo.lock` and a missing crate fails the
build instead of silently changing the graph. `prepare()` fetches those crates
before the build starts.

Completions and the man pages are **generated from the built binary**, not from
copies kept in this directory:

```sh
sweep completions bash > /usr/share/bash-completion/completions/sweep
sweep completions zsh  > /usr/share/zsh/site-functions/_sweep
sweep completions fish > /usr/share/fish/vendor_completions.d/sweep.fish

sweep __manpage            > /usr/share/man/man1/sweep.1
sweep __manpage rules list > /usr/share/man/man1/sweep-rules-list.1
```

That is the reason `completions` and `__manpage` are commands rather than files
in the repository: an option that exists in `--help` exists in all of them,
because all of them read one `clap` definition. `__manpage` is hidden from
`--help` and from the generated completions, because it is a build helper and not
a thing to type.

The top page names its subcommands `sweep-clean(1)`, `sweep-rules(1)` and so on,
so every one of them needs a page: a reference to a page that is not installed is
a dead end for whoever typed `man sweep-clean`. The `PKGBUILD` therefore lists
each command and a new command needs its own `man_page` line; `__manpage <name>`
refuses a name that is not a command (exit 2) rather than writing an empty file.

## What a `V*` tag publishes

`.github/workflows/release.yml` runs on a `V*` tag and publishes one archive plus
its checksum:

```
sweep-<version>-x86_64-linux.tar.gz    bin/sweep, LICENSE, README.md,
                                       man pages, bash/zsh/fish completions
SHA256SUMS
```

The archive is x86_64 only, because that is the architecture the job builds and
the one the maintainer can run. `aarch64` is supported by the `PKGBUILD` because
Arch builds from source there; there is no prebuilt aarch64 binary to claim.

The job refuses a tag whose name disagrees with the version the binary prints,
and it runs the test suite before packaging: a tag can point at a commit whose CI
run is still going, or whose CI was cancelled by a later push.

**Two releases have published.** `V0.1.1` on 15 November 2026 at `d6e6175`, and
`V0.1.2` on 17 November 2026 at `91c25dc`. Both archives were fetched without
credentials while the repository was public, matched `SHA256SUMS`, held 32
entries (binary, `LICENSE`, `README.md`, fifteen man pages, three completions)
and printed their own version. A download now needs an account with access, and
the assets themselves did not change. `V0.1.2`'s archive is
`sweep-0.1.2-x86_64-linux.tar.gz`, sha256
`8e5bcb2499f497a5fac3618dfdfc6703bedf71fee8a57cef4a0162b383ea10fb`.

The earlier `V0.1.0` tag published nothing: it reached the test gate and stopped,
because a property test symlinked into `/usr/lib/firmware` and answered
`not_found` on a runner without `linux-firmware`. That was a defect in the test,
not in the runner - it proved the host rather than the guard.

Before that, the packaging half was rehearsed by hand on 14 November 2026 at
`98e55b3`: `cargo test --workspace --all-targets` and
`cargo build --release --locked` passed, the version check read `0.1.0` from the
binary, and the assembled tree held the same contents. If the job fails, the
same steps run by hand:

```bash
cargo build --release --locked
cargo test --workspace --all-targets
./target/release/sweep --version          # must match the tag
# assemble the same tree, then:
tar -C dist -czf sweep-<version>-x86_64-linux.tar.gz sweep-<version>-x86_64-linux
sha256sum ./*.tar.gz > SHA256SUMS
```

## Why there is no AUR package

The AUR builds a package on the user's machine from a source anyone can fetch.
This repository is private, so neither `sweep-cli` (the tag's archive) nor
`sweep-cli-git` (a clone) can be fetched by a stranger, and publishing either
PKGBUILD there would produce a package that fails at `makepkg -s` for every user
of the AUR. Both files stay in the tree because they build the same binary
locally, from a clone the building account already has access to.

An AUR entry is still possible, and it needs a publicly reachable source first:
reopening the repository, a public mirror of the tag archive, or a source
tarball hosted somewhere that answers an anonymous request. Nothing else in the
PKGBUILDs has to change - `sweep-cli` already pins the tag archive's real
checksum and `sweep-cli-git` carries `sha256sums = SKIP`, which is correct for a
git source - so the step is the source URL, not the packaging.

Before the repository turned private, the submission was rehearsed and refused
(`aur@aur.archlinux.org: Permission denied (publickey)`) because the local key is
not registered with the AUR account. Neither `.SRCINFO` is hand-edited: both are
generated by `makepkg --printsrcinfo`. `namcap` is not installed on this machine,
so the packages were reviewed by reading their `.PKGINFO` and file lists instead,
which is what the two paragraphs above record.