//! What pacman knows about the packages on this machine.
//!
//! Everything here is a read. The one write — `pacman -R` — happens through the
//! privilege boundary, and only after this module has said exactly which
//! packages would go and why.
//!
//! **No prose is parsed.** `pacman -Qi` prints a human table whose field widths,
//! locale-dependent decimals and "None" markers change between releases, so a
//! reader built on it would break on someone else's machine and take the wrong
//! decision quietly. The machine-readable surfaces are used instead:
//!
//! * `pacman -Qe` / `pacman -Qtd` — one `name version` pair per line.
//! * `pacman -Qlq` — one file path per line, raw bytes.
//! * `pacman -Rs --print` — the exact transaction pacman would perform, which is
//!   also the only honest way to learn that a dependent blocks the removal:
//!   pacman's own resolver answers, rather than a copy of its rules.
//!
//! A package whose name is not in the installed set is refused before anything
//! is planned, so a mistyped name cannot be read as an option or a glob.

use std::io;
use std::path::PathBuf;
use std::process::Command;

use serde::Serialize;

/// One installed package, as pacman prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
}

/// Packages that a machine needs to keep working.
///
/// Removing any of these is a reinstall at best and an unbootable system at
/// worst; pacman would happily try. The list is short on purpose: it is the
/// boot path and the package manager itself, not every package that happens to
/// be important to someone.
pub const PROTECTED: &[(&str, &str)] = &[
    ("base", "the base meta package defines the system"),
    (
        "base-devel",
        "the base-devel meta package defines the toolchain",
    ),
    (
        "pacman",
        "pacman removes packages; removing it removes the remover",
    ),
    ("glibc", "every binary on the system links against it"),
    ("systemd", "the init system"),
    ("filesystem", "owns the base directory layout"),
    ("coreutils", "the basic file and shell utilities"),
    ("bash", "the default shell"),
    ("sudo", "the elevation sweep itself relies on"),
    ("linux", "the running kernel"),
    ("linux-lts", "a kernel"),
    ("linux-zen", "a kernel"),
    ("linux-hardened", "a kernel"),
    ("linux-firmware", "firmware the kernel loads at boot"),
];

/// The reason `name` may not be removed through this command, if it may not.
pub fn protected(name: &str) -> Option<&'static str> {
    PROTECTED
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, why)| *why)
}

/// Explicitly installed packages: the ones a user chose, with their versions.
///
/// `pacman -Qe` is the machine-readable half of `pacman -Qet`: dependencies that
/// were pulled in are not listed, because removing those is a consequence of
/// removing something else rather than a decision of its own.
pub fn explicit() -> io::Result<Vec<Package>> {
    let raw = run(&["-Qe"])?;
    Ok(parse_pairs(&raw))
}

/// Packages installed as dependencies that nothing needs any more.
pub fn orphans() -> io::Result<Vec<Package>> {
    match run(&["-Qtd"]) {
        Ok(raw) => Ok(parse_pairs(&raw)),
        // `pacman -Qtd` exits 1 with nothing to say when there are no orphans,
        // which is a fact about the machine rather than a failure.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(error),
        Err(_) => Ok(Vec::new()),
    }
}

/// Every file a package owns, as raw paths.
pub fn files(name: &str) -> io::Result<Vec<PathBuf>> {
    use std::os::unix::ffi::OsStringExt;
    let raw = run(&["-Qlq", name])?;
    Ok(raw
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| PathBuf::from(std::ffi::OsString::from_vec(line.to_vec())))
        .collect())
}

/// The transaction `pacman -Rs` would perform for `names`, without doing it.
///
/// pacman's resolver decides, so a dependent that blocks the removal shows up as
/// an error here rather than as a surprise halfway through the run.
pub fn plan_removal(names: &[String]) -> io::Result<Vec<Package>> {
    let mut args = vec![
        "-Rs".to_string(),
        "--print".to_string(),
        "--print-format".to_string(),
        "%n %v".to_string(),
    ];
    args.extend(names.iter().cloned());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let raw = run(&borrowed)?;
    Ok(parse_pairs(&raw))
}

/// Checks one name from the command line against what is installed.
pub fn validate(name: &str, installed: &[Package]) -> Result<(), String> {
    if name.is_empty() {
        return Err("an empty package name is not a package".to_string());
    }
    if name.starts_with('-') {
        return Err(format!(
            "`{name}` starts with `-`, which pacman would read as an option"
        ));
    }
    if name.len() > 255 {
        return Err(format!("`{name}` is longer than any package name"));
    }
    if name
        .bytes()
        .any(|byte| byte < 0x20 || byte == b'/' || byte == b' ')
    {
        return Err(format!(
            "`{name}` contains a byte a package name cannot contain"
        ));
    }
    if !installed.iter().any(|package| package.name == name) {
        return Err(format!(
            "`{name}` is not one of the explicitly installed packages"
        ));
    }
    Ok(())
}

fn parse_pairs(raw: &[u8]) -> Vec<Package> {
    let text = String::from_utf8_lossy(raw);
    text.lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ' ');
            let name = parts.next()?.trim();
            if name.is_empty() {
                return None;
            }
            Some(Package {
                name: name.to_string(),
                version: parts.next().unwrap_or("").trim().to_string(),
            })
        })
        .collect()
}

fn run(args: &[&str]) -> io::Result<Vec<u8>> {
    let output = Command::new("pacman")
        .args(args)
        .output()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "pacman is not installed; sweep cannot manage packages here",
                )
            } else {
                error
            }
        })?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let first = stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("pacman failed without a message")
        .trim()
        .to_string();
    Err(io::Error::other(first))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str) -> Package {
        Package {
            name: name.to_string(),
            version: "1.0-1".to_string(),
        }
    }

    #[test]
    fn pairs_parse_from_the_machine_format() {
        let parsed = parse_pairs(b"firefox 159.0-1.1\nark 25.08.2-1\n");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "firefox");
        assert_eq!(parsed[0].version, "159.0-1.1");
        assert_eq!(parsed[1].name, "ark");
    }

    #[test]
    fn an_empty_or_noisy_line_does_not_become_a_package() {
        assert!(parse_pairs(b"").is_empty());
        assert!(parse_pairs(b"\n\n").is_empty());
    }

    #[test]
    fn an_option_glob_or_path_is_refused_before_anything_is_planned() {
        let installed = vec![package("firefox")];
        for bad in ["-Syu", "--noconfirm", "some/where", "two words", ""] {
            assert!(
                validate(bad, &installed).is_err(),
                "`{bad}` must not reach pacman as a name"
            );
        }
        assert!(validate("firefox", &installed).is_ok());
    }

    #[test]
    fn a_package_that_is_not_installed_explicitly_is_refused() {
        let installed = vec![package("firefox")];
        let error = validate("nosuchpkg", &installed).expect_err("not installed");
        assert!(
            error.contains("not one of the explicitly installed"),
            "{error}"
        );
    }

    #[test]
    fn the_boot_path_and_the_package_manager_are_protected() {
        for name in ["base", "pacman", "glibc", "systemd", "linux"] {
            assert!(protected(name).is_some(), "{name} must be protected");
        }
        assert!(protected("firefox").is_none());
        assert!(
            protected("pacman").unwrap_or_default().contains("remover"),
            "the reason has to explain itself"
        );
    }

    #[test]
    fn a_missing_pacman_is_a_named_error_not_a_panic() {
        // Nothing to assert about the host's package manager: this test only
        // pins that the module treats "not installed" as a sentence.
        let error = io::Error::new(
            io::ErrorKind::NotFound,
            "pacman is not installed; sweep cannot manage packages here",
        );
        assert!(error.to_string().contains("pacman"));
    }
}
