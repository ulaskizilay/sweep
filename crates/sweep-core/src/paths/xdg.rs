//! XDG base directory resolution.
//!
//! Every value is validated before use. A relative, root, control-byte or
//! traversal-containing value falls back to the specification default and emits
//! a warning instead of being honoured: an exported `XDG_CACHE_HOME=/` would
//! otherwise turn a cache sweep into a filesystem sweep.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::resolve::{has_control_bytes, has_parent_component};

/// Resolved base directories plus any warnings produced while resolving them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xdg {
    pub home: PathBuf,
    pub cache: PathBuf,
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdgError {
    HomeNotSet,
    HomeNotAbsolute(PathBuf),
}

impl std::fmt::Display for XdgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdgError::HomeNotSet => f.write_str("HOME is not set"),
            XdgError::HomeNotAbsolute(p) => {
                write!(f, "HOME must be absolute, got {}", p.display())
            }
        }
    }
}

impl std::error::Error for XdgError {}

impl Xdg {
    /// Resolves from the process environment.
    pub fn from_env() -> Result<Self, XdgError> {
        Self::resolve(|key| std::env::var_os(key))
    }

    /// Resolves from an arbitrary lookup, so tests can pin every variable.
    pub fn resolve<F>(lookup: F) -> Result<Self, XdgError>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        let raw_home = lookup("HOME").ok_or(XdgError::HomeNotSet)?;
        let home = PathBuf::from(&raw_home);
        if !home.is_absolute() || is_usable_base(&home).is_err() {
            return Err(XdgError::HomeNotAbsolute(home));
        }

        let mut warnings = Vec::new();
        let cache = pick(
            lookup("XDG_CACHE_HOME"),
            home.join(".cache"),
            "XDG_CACHE_HOME",
            &mut warnings,
        );
        let config = pick(
            lookup("XDG_CONFIG_HOME"),
            home.join(".config"),
            "XDG_CONFIG_HOME",
            &mut warnings,
        );
        let data = pick(
            lookup("XDG_DATA_HOME"),
            home.join(".local/share"),
            "XDG_DATA_HOME",
            &mut warnings,
        );
        let state = pick(
            lookup("XDG_STATE_HOME"),
            home.join(".local/state"),
            "XDG_STATE_HOME",
            &mut warnings,
        );

        // XDG_RUNTIME_DIR has no specified default; fall back under /run/user.
        let runtime = match lookup("XDG_RUNTIME_DIR") {
            Some(value) => {
                let path = PathBuf::from(value);
                if let Err(reason) = is_usable_base(&path) {
                    warnings.push(format!(
                        "XDG_RUNTIME_DIR ignored ({reason}); using /run/user"
                    ));
                    PathBuf::from(format!("/run/user/{}", crate::sys::euid()))
                } else {
                    path
                }
            }
            None => PathBuf::from(format!("/run/user/{}", crate::sys::euid())),
        };

        Ok(Self {
            home,
            cache,
            config,
            data,
            state,
            runtime,
            warnings,
        })
    }

    /// `~/.local/state/sweep` — where the operation log lives.
    pub fn state_dir(&self) -> PathBuf {
        self.state.join("sweep")
    }

    /// `~/.config/sweep`
    pub fn config_dir(&self) -> PathBuf {
        self.config.join("sweep")
    }

    /// All base directories, for rule-template expansion and diagnostics.
    pub fn bases(&self) -> [(&'static str, &Path); 5] {
        [
            ("home", &self.home),
            ("cache", &self.cache),
            ("config", &self.config),
            ("data", &self.data),
            ("state", &self.state),
        ]
    }
}

fn pick(
    value: Option<OsString>,
    default: PathBuf,
    name: &'static str,
    warnings: &mut Vec<String>,
) -> PathBuf {
    let Some(value) = value else {
        return default;
    };
    if value.is_empty() {
        return default;
    }
    let path = PathBuf::from(value);
    match is_usable_base(&path) {
        Ok(()) => path,
        Err(reason) => {
            warnings.push(format!(
                "{name} ignored ({reason}); using {}",
                default.display()
            ));
            default
        }
    }
}

/// Rejects values that would make a cache sweep unbounded.
fn is_usable_base(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("not absolute");
    }
    if path == Path::new("/") {
        return Err("is the filesystem root");
    }
    if has_control_bytes(path.as_os_str()) {
        return Err("contains a control byte");
    }
    if has_parent_component(path) {
        return Err("contains a parent component");
    }
    if path.as_os_str().as_encoded_bytes().len() > 4096 {
        return Err("longer than PATH_MAX");
    }
    Ok(())
}

/// True when `value` looks like it came from the environment rather than a
/// literal, i.e. it is not empty.
pub fn non_empty(value: Option<&OsStr>) -> Option<&OsStr> {
    value.filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, OsString> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), OsString::from(v)))
            .collect()
    }

    fn resolve(pairs: &[(&str, &str)]) -> Xdg {
        let map = env(pairs);
        Xdg::resolve(|key| map.get(key).cloned()).expect("home present")
    }

    #[test]
    fn defaults_follow_the_specification() {
        let xdg = resolve(&[("HOME", "/home/u")]);
        assert_eq!(xdg.cache, PathBuf::from("/home/u/.cache"));
        assert_eq!(xdg.state, PathBuf::from("/home/u/.local/state"));
        assert_eq!(xdg.state_dir(), PathBuf::from("/home/u/.local/state/sweep"));
        assert!(xdg.warnings.is_empty());
    }

    #[test]
    fn relative_override_falls_back_with_a_warning() {
        let xdg = resolve(&[("HOME", "/home/u"), ("XDG_CACHE_HOME", "relative/cache")]);
        assert_eq!(xdg.cache, PathBuf::from("/home/u/.cache"));
        assert_eq!(xdg.warnings.len(), 1);
        assert!(xdg.warnings[0].contains("not absolute"));
    }

    #[test]
    fn root_override_is_refused() {
        let xdg = resolve(&[("HOME", "/home/u"), ("XDG_CACHE_HOME", "/")]);
        assert_eq!(xdg.cache, PathBuf::from("/home/u/.cache"));
        assert!(xdg.warnings[0].contains("filesystem root"));
    }

    #[test]
    fn traversal_override_is_refused() {
        let xdg = resolve(&[("HOME", "/home/u"), ("XDG_DATA_HOME", "/home/u/../etc")]);
        assert_eq!(xdg.data, PathBuf::from("/home/u/.local/share"));
        assert!(xdg.warnings[0].contains("parent component"));
    }

    #[test]
    fn relative_home_is_an_error() {
        let map = env(&[("HOME", "home/u")]);
        let err = Xdg::resolve(|key| map.get(key).cloned()).unwrap_err();
        assert!(matches!(err, XdgError::HomeNotAbsolute(_)));
    }

    #[test]
    fn missing_home_is_an_error() {
        let err = Xdg::resolve(|_| None).unwrap_err();
        assert_eq!(err, XdgError::HomeNotSet);
    }
}
