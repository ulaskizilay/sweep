# Packaging

A PKGBUILD lives here when someone can install it and get the same binary the
repository builds. Two packages are planned; one exists.

| Directory | Package | Source |
|---|---|---|
| `sweep-cli-git/` | `sweep-cli-git` | `main`, at build time |
| *(later)* `sweep-cli/` | `sweep-cli` | a `V*` tag |

## `sweep-cli-git`

Builds the current `main`. The **package** version is `r<commits>.<short-sha>`,
because a tracking package cannot name a release it is not built from:

```console
$ cd packaging/sweep-cli-git
$ makepkg -si
$ pacman -Q sweep-cli-git
sweep-cli-git r<commits>.<short-sha>-1
$ sweep --version
sweep 0.1.1
```

The two differ on purpose: `sweep --version` reports the crate version the source
declares, which is what `--version` means everywhere else. When the commit
matters - a bug report, a rebuild - the package version is the one that names it.

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

**The job has published once.** `V0.1.1` was tagged on 15 November 2026 at
`d6e6175` and published the archive and `SHA256SUMS`; the downloaded archive
matched its checksum, held 32 entries (binary, `LICENSE`, `README.md`, fifteen
man pages, three completions) and printed `sweep 0.1.1`. The earlier `V0.1.0`
tag published nothing: it reached the test gate and stopped, because a property
test symlinked into `/usr/lib/firmware` and answered `not_found` on a runner
without `linux-firmware`. That was a defect in the test, not in the runner - it
proved the host rather than the guard.

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

## `sweep-cli` (not yet)

The stable package is created at the first `V*` tag, from the **tag tarball**, not
from the release archive above:

1. Push the tag, then download `$url/archive/refs/tags/$tag.tar.gz` and take its
   `sha256sum`. GitHub generates that file, so the checksum only exists once the
   tag does.
2. Add `packaging/sweep-cli/PKGBUILD` with `source=("$url/archive/refs/tags/$tag.tar.gz")`
   and that real `sha256sums`, not `SKIP`.
3. Run `updpkgsums` in that directory, then `makepkg --printsrcinfo > .SRCINFO`.
4. Submit with `pkgrel=1`.

While the repository is private, step 1 needs an authenticated download and so
does building the package: `makepkg` would be fetching a URL only the maintainer
can read. That makes the stable package maintainer-only until the repository is
public, and AUR submission is impossible before then. The tag itself is still
worth cutting: it is the baseline the next change is reviewed against.

Nothing here should be hand-edited: both `.SRCINFO` files are generated by
`makepkg --printsrcinfo`, and `namcap PKGBUILD` runs clean before a submission.
