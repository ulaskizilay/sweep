//! Build artifacts inside project directories, found by manifest.
//!
//! `node_modules` is not a cache because it is called `node_modules`. A
//! directory with that name can be a vendored dependency tree the user edits, a
//! fixture, or a directory that happens to share the name. What makes the real
//! one disposable is the `package.json` beside it: that file is the recipe, and
//! the artifact is what the recipe produced.
//!
//! So discovery has two halves and both have to agree:
//!
//! 1. **A directory is a project root only if a manifest is present** -
//!    `package.json`, `Cargo.toml`, `go.mod`, `pyproject.toml`, `pom.xml`,
//!    `build.gradle`, `Gemfile`, `composer.json`, `.git` and friends.
//! 2. **An artifact is selected only if the manifest that produces it is
//!    present**: `target` needs `Cargo.toml` or `pom.xml`, `.venv` needs a Python
//!    manifest, `vendor` needs `go.mod`, `composer.json` or `Gemfile`.
//!
//! A name without its manifest is reported as skipped, not silently ignored:
//! "there is a `node_modules` here but no `package.json`, so sweep left it
//! alone" is the sentence that keeps a user from trusting the wrong thing.
//!
//! Three structural protections:
//!
//! * **Nothing is followed.** A symlinked artifact or project directory is
//!   skipped; a `node_modules` that points into `/` is not a directory to sweep.
//! * **The walk never descends into an artifact or `.git`.** Descending into
//!   `node_modules` would find the `package.json` that many published packages
//!   ship with, and "the project inside the artifact" is not a project the user
//!   opened.
//! * **A walk that did not complete plans nothing.** Partial knowledge of a
//!   project tree is not enough to decide what its build left behind.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use crate::probe::FsProbe;
use crate::scan::{Budget, Limits, Stop};

/// One build artifact a project left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub path: PathBuf,
    /// The directory name that was recognised (`node_modules`, `target`, ...).
    pub name: &'static str,
    /// Bytes accounted for the directory itself; the sweep plans its entries.
    pub bytes: u64,
}

/// One directory that carries a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub root: PathBuf,
    /// The manifest that identified it, for the report.
    pub manifest: String,
}

/// An artifact-shaped directory that was not selected, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: &'static str,
}

/// Everything one discovery walk found.
#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub stop: Stop,
    pub missing_root: bool,
    pub root_is_symlink: bool,
    pub not_a_directory: bool,
    pub root_unreadable: bool,
    pub projects: Vec<Project>,
    pub artifacts: Vec<Artifact>,
    pub skipped: Vec<Skipped>,
    /// Directories visited, for the report when a walk is slow.
    pub directories: usize,
    pub bytes_visited: u64,
}

impl Discovery {
    /// True when the walk saw the whole tree below the root.
    pub fn complete(&self) -> bool {
        self.stop == Stop::Complete
            && !self.missing_root
            && !self.root_is_symlink
            && !self.not_a_directory
            && !self.root_unreadable
    }

    pub fn artifact_paths(&self) -> Vec<&Path> {
        self.artifacts
            .iter()
            .map(|artifact| artifact.path.as_path())
            .collect()
    }
}

/// What one artifact directory needs beside it to be disposable.
struct Spec {
    name: &'static str,
    /// Any one of these manifests justifies removing the directory.
    requires: &'static [&'static str],
}

/// Python project manifests. Any one of them means a virtualenv beside it is a
/// virtualenv, not a directory someone named `.venv`.
const PYTHON: &[&str] = &[
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "poetry.lock",
];

/// JavaScript and TypeScript project manifests.
const NODE: &[&str] = &["package.json"];

/// Java and Kotlin build manifests.
const JVM: &[&str] = &[
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "pom.xml",
];

/// The artifact table.
///
/// Ordered by name for readability, not by preference: the first matching entry
/// wins, and no two entries share a name. A name is deliberately absent when the
/// name alone is ambiguous - `bin`, `out`, `build` for anything other than a
/// manifest that produces exactly that output, and `coverage`, which is a
/// source directory in plenty of Go repositories and an output directory in a
/// JavaScript one.
///
/// The manifest gate is per directory, and that is what keeps `__pycache__` out
/// of this table: Python writes it beside every module, so the only `__pycache__`
/// a manifest sits beside is the one at the project root. Listing it would
/// report one skipped entry per package in every Python tree and take the
/// bytecode directories that matter none of the way.
const ARTIFACTS: &[Spec] = &[
    Spec {
        name: ".angular",
        requires: NODE,
    },
    Spec {
        name: ".astro",
        requires: NODE,
    },
    Spec {
        name: ".dart_tool",
        requires: &["pubspec.yaml"],
    },
    Spec {
        name: ".expo",
        requires: NODE,
    },
    Spec {
        name: ".gradle",
        requires: JVM,
    },
    Spec {
        name: ".hypothesis",
        requires: PYTHON,
    },
    Spec {
        name: ".mypy_cache",
        requires: PYTHON,
    },
    Spec {
        name: ".next",
        requires: NODE,
    },
    Spec {
        name: ".nox",
        requires: PYTHON,
    },
    Spec {
        name: ".nuxt",
        requires: NODE,
    },
    Spec {
        name: ".output",
        requires: NODE,
    },
    Spec {
        name: ".parcel-cache",
        requires: NODE,
    },
    Spec {
        name: ".pytest_cache",
        requires: PYTHON,
    },
    Spec {
        name: ".ruff_cache",
        requires: PYTHON,
    },
    Spec {
        name: ".svelte-kit",
        requires: NODE,
    },
    // `.terraform` holds the providers and modules `terraform init` downloaded.
    // The state file it may contain is the *backend* state, not the resources:
    // a local backend keeps `terraform.tfstate` in the working directory, which
    // no rule here names. Losing this directory costs one `terraform init`.
    Spec {
        name: ".terraform",
        requires: &["*.tf"],
    },
    Spec {
        name: ".terragrunt-cache",
        requires: &["terragrunt.hcl"],
    },
    Spec {
        name: ".tox",
        requires: PYTHON,
    },
    Spec {
        name: ".turbo",
        requires: NODE,
    },
    Spec {
        name: ".venv",
        requires: PYTHON,
    },
    Spec {
        name: ".vite",
        requires: NODE,
    },
    Spec {
        name: ".zig-cache",
        requires: &["build.zig"],
    },
    Spec {
        name: "_build",
        requires: &["mix.exs"],
    },
    Spec {
        name: "Pods",
        requires: &["Podfile"],
    },
    Spec {
        name: "bower_components",
        requires: NODE,
    },
    Spec {
        name: "build",
        // Only manifests whose build output is exactly `build/`.
        requires: &["CMakeLists.txt", "package.json", "build.gradle", "pom.xml"],
    },
    Spec {
        name: "deps",
        requires: &["mix.exs"],
    },
    Spec {
        name: "dist",
        requires: &["package.json", "pyproject.toml", "setup.py"],
    },
    Spec {
        name: "elm-stuff",
        requires: &["elm.json"],
    },
    Spec {
        name: "htmlcov",
        requires: PYTHON,
    },
    Spec {
        name: "node_modules",
        requires: NODE,
    },
    Spec {
        name: "obj",
        requires: &["*.csproj", "*.sln"],
    },
    Spec {
        name: "target",
        requires: &["Cargo.toml", "pom.xml"],
    },
    Spec {
        name: "vendor",
        requires: &["go.mod", "composer.json", "Gemfile"],
    },
    Spec {
        name: "venv",
        requires: PYTHON,
    },
    Spec {
        name: "zig-cache",
        requires: &["build.zig"],
    },
    Spec {
        name: "zig-out",
        requires: &["build.zig"],
    },
];

/// Manifests that identify a project root even when nothing is selected.
///
/// `.git` counts: a checkout whose language has no manifest in this table is
/// still a project, and saying "no project here" about it would be wrong.
const MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "CMakeLists.txt",
    "Gemfile",
    "Pipfile",
    "Podfile",
    "build.gradle",
    "build.gradle.kts",
    "build.zig",
    "composer.json",
    "elm.json",
    "go.mod",
    "mix.exs",
    "package.json",
    "pom.xml",
    "pubspec.yaml",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "poetry.lock",
    "settings.gradle",
    "settings.gradle.kts",
    "*.csproj",
    "*.sln",
    "*.tf",
    "terragrunt.hcl",
    ".git",
];

/// Directories that are never walked, whatever they contain.
///
/// `~/.cargo`, `~/.rustup` and `~/go/pkg/mod` are toolchains and module caches,
/// not projects: their `Cargo.toml` files are vendored copies, and the manifests
/// inside them must not turn a package registry into a project tree. `{cache}` is
/// `clean`'s target, and walking it here would double-count and slow the scan.
const NEVER_WALK: &[&str] = &[".cargo", ".rustup", ".cache", "node_modules", "target"];

/// True when `name` satisfies one of the `requires` entries.
///
/// A pattern beginning with `*.` is a suffix match: `*.csproj` is a project file
/// whatever it is called, and the name before the dot is the user's choice.
fn satisfies(name: &str, requires: &[&str]) -> bool {
    requires
        .iter()
        .any(|required| match required.strip_prefix("*.") {
            Some(suffix) => name.len() > suffix.len() + 1 && name.ends_with(suffix),
            None => name == *required,
        })
}

/// The artifact entry for `name`, if the directory name is recognised at all.
fn artifact_spec(name: &str) -> Option<&'static Spec> {
    ARTIFACTS.iter().find(|spec| spec.name == name)
}

fn is_manifest(name: &str) -> bool {
    satisfies(name, MANIFESTS)
}

/// Walks `root` and returns the projects and the build artifacts inside them.
///
/// `depth` is the project-discovery depth from the rule (6 by default, meaning
/// six levels below the home directory), and `keep_days` ages an artifact by its
/// own `mtime`: installing a dependency updates the directory, so a directory
/// whose mtime is old has not been touched by a build since then.
pub fn discover(
    root: &Path,
    depth: usize,
    keep_days: u32,
    now: i64,
    limits: &Limits,
    probe: &dyn FsProbe,
) -> Discovery {
    let mut out = Discovery::default();
    let cutoff = now.saturating_sub(i64::from(keep_days) * 86_400);

    let root_meta = match probe.symlink_metadata(root) {
        Ok(meta) => meta,
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                out.missing_root = true;
            } else {
                out.root_unreadable = true;
            }
            return out;
        }
    };
    if root_meta.is_symlink() {
        out.root_is_symlink = true;
        return out;
    }
    if !root_meta.is_dir() {
        out.not_a_directory = true;
        return out;
    }

    let mut budget = Budget::new(limits);
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    // Depth-first, and the stack is a vector rather than recursion: a symlinked
    // directory that resolves to its own parent would otherwise be a stack
    // overflow rather than a skip.
    while let Some((directory, level)) = stack.pop() {
        match budget.charge() {
            Ok(()) => {}
            Err(stop) => {
                out.stop = stop;
                break;
            }
        }
        if !seen.insert(directory.clone()) {
            continue;
        }
        out.directories += 1;
        out.bytes_visited += probe
            .symlink_metadata(&directory)
            .map(|meta| meta.accounted_bytes())
            .unwrap_or(0);

        let read = match std::fs::read_dir(&directory) {
            Ok(read) => read,
            Err(_) => {
                if directory == root {
                    out.root_unreadable = true;
                    break;
                }
                // An unreadable subdirectory could hold anything, including a
                // project. It is reported once, as a skip, and the walk
                // continues: one unreadable directory must not hide the rest.
                out.skipped.push(Skipped {
                    path: directory.clone(),
                    reason: "unreadable as your user",
                });
                continue;
            }
        };

        let mut children: Vec<Child> = Vec::new();
        for entry in read {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            let meta = match probe.symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            children.push(Child {
                path,
                name,
                is_dir: meta.is_dir(),
                is_symlink: meta.is_symlink(),
                mtime: meta.mtime,
                bytes: meta.accounted_bytes(),
            });
        }
        children.sort_by(|left, right| left.name.cmp(&right.name));

        let manifest = children
            .iter()
            .find(|child| !child.is_dir && !child.is_symlink && is_manifest(&child.name))
            .or_else(|| {
                // `.git` is a directory in a normal checkout and a file in a
                // worktree; both identify a project.
                children
                    .iter()
                    .find(|child| child.name == ".git" && !child.is_symlink)
            });

        if let Some(manifest) = manifest {
            out.projects.push(Project {
                root: directory.clone(),
                manifest: manifest.name.clone(),
            });
        }

        // Artifact-shaped names are judged whether or not this directory is a
        // project, so a `node_modules` with nothing beside it is reported as
        // skipped rather than silently passed over. The reason is the useful
        // part: "no manifest in this directory produces it" tells the user why
        // sweep walked past a directory they expected it to take.
        for child in &children {
            let Some(spec) = artifact_spec(&child.name) else {
                continue;
            };
            // Symlink before directory: `symlink_metadata` never follows, so a
            // link to a directory reports `is_dir == false` and would otherwise
            // disappear from the walk without a word.
            if child.is_symlink {
                out.skipped.push(Skipped {
                    path: child.path.clone(),
                    reason: "a symbolic link is not followed",
                });
                continue;
            }
            if !child.is_dir {
                continue;
            }
            // The manifest gate. `target` beside a `package.json` is not what
            // Cargo produced, and sweeping it would delete a directory the
            // recipe did not create.
            let satisfied = children.iter().any(|other| {
                !other.is_dir && !other.is_symlink && satisfies(&other.name, spec.requires)
            });
            if !satisfied {
                out.skipped.push(Skipped {
                    path: child.path.clone(),
                    reason: "no manifest in this directory produces it",
                });
                continue;
            }
            if child.mtime >= cutoff {
                out.skipped.push(Skipped {
                    path: child.path.clone(),
                    reason: "modified within the retention window",
                });
                continue;
            }
            out.artifacts.push(Artifact {
                path: child.path.clone(),
                name: spec.name,
                bytes: child.bytes,
            });
        }

        if level >= depth {
            continue;
        }
        for child in &children {
            if !child.is_dir || child.is_symlink {
                continue;
            }
            if child.name == ".git" {
                continue;
            }
            if artifact_spec(&child.name).is_some() {
                // Never descend into an artifact: a published package ships its
                // own `package.json`, and the "project" inside `node_modules` is
                // not one the user opened.
                continue;
            }
            if NEVER_WALK.contains(&child.name.as_str()) {
                continue;
            }
            stack.push((child.path.clone(), level + 1));
        }
    }

    out.artifacts
        .sort_by(|left, right| left.path.cmp(&right.path));
    out.projects
        .sort_by(|left, right| left.root.cmp(&right.root));
    out.skipped
        .sort_by(|left, right| left.path.cmp(&right.path));
    out
}

struct Child {
    path: PathBuf,
    name: String,
    is_dir: bool,
    is_symlink: bool,
    mtime: i64,
    bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::RealProbe;
    use std::fs::{File, FileTimes};
    use std::time::{Duration, SystemTime};

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    fn age(path: &Path, days: i64) {
        let when = SystemTime::now() - Duration::from_secs((days.max(0) as u64) * 86_400);
        File::open(path)
            .expect("open")
            .set_times(FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    fn tree(files: &[&str]) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        for relative in files {
            let path = temp.path().join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, "body").expect("write");
        }
        temp
    }

    fn run(root: &Path, depth: usize, keep_days: u32) -> Discovery {
        let probe = RealProbe::new().expect("probe").with_open_scan();
        discover(root, depth, keep_days, now(), &Limits::default(), &probe)
    }

    fn names(discovery: &Discovery, root: &Path) -> Vec<String> {
        discovery
            .artifacts
            .iter()
            .map(|artifact| {
                artifact
                    .path
                    .strip_prefix(root)
                    .expect("below root")
                    .display()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn a_node_modules_beside_a_package_json_is_selected() {
        let temp = tree(&[
            "web/package.json",
            "web/node_modules/left-pad/index.js",
            "web/src/app.js",
        ]);
        age(&temp.path().join("web/node_modules"), 60);

        let found = run(temp.path(), 6, 30);
        assert_eq!(names(&found, temp.path()), ["web/node_modules"]);
        assert_eq!(found.projects.len(), 1);
        assert_eq!(found.projects[0].manifest, "package.json");
    }

    #[test]
    fn a_node_modules_without_its_manifest_is_skipped_with_a_reason() {
        let temp = tree(&["web/node_modules/left-pad/index.js", "web/README.md"]);
        age(&temp.path().join("web/node_modules"), 60);

        let found = run(temp.path(), 6, 30);
        assert!(
            found.artifacts.is_empty(),
            "{:?}",
            names(&found, temp.path())
        );
        assert!(
            found
                .skipped
                .iter()
                .any(|skipped| skipped.path.ends_with("web/node_modules")
                    && skipped.reason.contains("no manifest")),
            "{:?}",
            found.skipped
        );
    }

    #[test]
    fn a_manifest_beside_the_wrong_artifact_selects_nothing() {
        // `target` is Cargo's output. A `package.json` project that happens to
        // have a `target` directory is not a Cargo build, and deleting it would
        // be deleting a directory this table did not understand.
        let temp = tree(&["web/package.json", "web/target/something"]);
        age(&temp.path().join("web/target"), 60);

        let found = run(temp.path(), 6, 30);
        assert!(
            found.artifacts.is_empty(),
            "{:?}",
            names(&found, temp.path())
        );
        assert!(found
            .skipped
            .iter()
            .any(|skipped| skipped.path.ends_with("web/target")));
    }

    #[test]
    fn terraform_providers_need_a_terraform_file_beside_them() {
        let temp = tree(&[
            "infra/main.tf",
            "infra/.terraform/providers/registry.terraform.io/hashicorp/aws",
            "web/package.json",
            "web/.terraform/providers/x",
        ]);
        age(&temp.path().join("infra/.terraform"), 60);
        age(&temp.path().join("web/.terraform"), 60);

        let found = run(temp.path(), 6, 30);
        assert_eq!(names(&found, temp.path()), ["infra/.terraform"]);
        assert!(
            found
                .skipped
                .iter()
                .any(|skipped| skipped.path.ends_with("web/.terraform")),
            "a .terraform in a project with no .tf file is not a target"
        );
    }

    #[test]
    fn a_python_output_directory_needs_a_python_manifest() {
        let temp = tree(&[
            "py/pyproject.toml",
            "py/htmlcov/index.html",
            "js/package.json",
            "js/htmlcov/index.html",
        ]);
        age(&temp.path().join("py/htmlcov"), 60);
        age(&temp.path().join("js/htmlcov"), 60);

        let found = run(temp.path(), 6, 30);
        assert_eq!(names(&found, temp.path()), ["py/htmlcov"]);
    }

    #[test]
    fn a_recent_artifact_is_kept() {
        let temp = tree(&["web/package.json", "web/node_modules/left-pad/index.js"]);
        let found = run(temp.path(), 6, 30);
        assert!(found.artifacts.is_empty());
        assert!(found
            .skipped
            .iter()
            .any(|skipped| skipped.reason.contains("retention")));
    }

    #[test]
    fn a_project_inside_an_artifact_is_not_a_project() {
        // Published packages ship a `package.json`. Descending into
        // `node_modules` would turn every dependency into a project and its
        // nested `node_modules` into a target.
        let temp = tree(&[
            "web/package.json",
            "web/node_modules/dep/package.json",
            "web/node_modules/dep/node_modules/inner/index.js",
        ]);
        age(&temp.path().join("web/node_modules"), 60);
        age(&temp.path().join("web/node_modules/dep/node_modules"), 60);

        let found = run(temp.path(), 6, 30);
        assert_eq!(names(&found, temp.path()), ["web/node_modules"]);
        assert_eq!(found.projects.len(), 1, "only the project the user opened");
    }

    #[test]
    fn a_toolchain_cache_is_never_a_project() {
        let temp = tree(&[
            ".cargo/registry/src/crate/Cargo.toml",
            ".cargo/registry/src/crate/target/debug/x",
            ".rustup/toolchains/stable/Cargo.toml",
        ]);
        age(&temp.path().join(".cargo/registry/src/crate/target"), 60);
        age(&temp.path().join(".rustup"), 60);

        let found = run(temp.path(), 6, 30);
        assert!(
            found.artifacts.is_empty(),
            "{:?}",
            names(&found, temp.path())
        );
        assert!(found.projects.is_empty(), "{:?}", found.projects);
    }

    #[test]
    fn a_symlinked_artifact_is_not_followed() {
        let temp = tree(&["web/package.json"]);
        std::os::unix::fs::symlink("/usr", temp.path().join("web/node_modules")).expect("symlink");

        let found = run(temp.path(), 6, 30);
        assert!(found.artifacts.is_empty());
        assert!(found
            .skipped
            .iter()
            .any(|skipped| skipped.reason.contains("symbolic link")));
    }

    #[test]
    fn nested_projects_are_both_found() {
        let temp = tree(&[
            "repos/web/package.json",
            "repos/web/node_modules/x/index.js",
            "repos/web/packages/ui/package.json",
            "repos/web/packages/ui/node_modules/y/index.js",
        ]);
        age(&temp.path().join("repos/web/node_modules"), 60);
        age(&temp.path().join("repos/web/packages/ui/node_modules"), 60);

        let found = run(temp.path(), 6, 30);
        assert_eq!(
            names(&found, temp.path()),
            [
                "repos/web/node_modules",
                "repos/web/packages/ui/node_modules"
            ]
        );
        assert_eq!(found.projects.len(), 2);
    }

    #[test]
    fn a_python_virtualenv_needs_a_python_manifest() {
        let temp = tree(&[
            "app/pyproject.toml",
            "app/.venv/lib/python3/site-packages/x.py",
            "app/notes/.venv/lib/python3/site-packages/x.py",
        ]);
        age(&temp.path().join("app/.venv"), 60);
        age(&temp.path().join("app/notes/.venv"), 60);

        let found = run(temp.path(), 6, 30);
        assert_eq!(names(&found, temp.path()), ["app/.venv"]);
    }

    #[test]
    fn a_csharp_project_file_is_matched_by_suffix() {
        let temp = tree(&["dotnet/App.csproj", "dotnet/obj/project.assets.json"]);
        age(&temp.path().join("dotnet/obj"), 60);

        let found = run(temp.path(), 6, 30);
        assert_eq!(names(&found, temp.path()), ["dotnet/obj"]);
    }

    #[test]
    fn the_depth_limit_is_counted_from_the_root() {
        let temp = tree(&[
            "a/b/c/d/web/package.json",
            "a/b/c/d/web/node_modules/x/index.js",
        ]);
        age(&temp.path().join("a/b/c/d/web/node_modules"), 60);

        // Depth 4 reaches `a/b/c/d` but not the project one level below it.
        assert!(run(temp.path(), 4, 30).artifacts.is_empty());
        assert_eq!(
            names(&run(temp.path(), 5, 30), temp.path()),
            ["a/b/c/d/web/node_modules"]
        );
    }

    #[test]
    fn a_missing_root_is_reported_rather_than_treated_as_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let found = run(&temp.path().join("nope"), 6, 30);
        assert!(found.missing_root);
        assert!(!found.complete());
        assert!(found.artifacts.is_empty());
    }

    #[test]
    fn two_runs_find_the_same_artifacts() {
        let temp = tree(&[
            "a/package.json",
            "a/node_modules/x/index.js",
            "b/Cargo.toml",
            "b/target/debug/y",
        ]);
        age(&temp.path().join("a/node_modules"), 60);
        age(&temp.path().join("b/target"), 60);

        let first = run(temp.path(), 6, 30);
        let second = run(temp.path(), 6, 30);
        assert_eq!(names(&first, temp.path()), names(&second, temp.path()));
        assert_eq!(names(&first, temp.path()), ["a/node_modules", "b/target"]);
    }
}
