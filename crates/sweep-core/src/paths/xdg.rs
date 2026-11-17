//! XDG base directory resolution.
//!
//! Every value is validated before use. A relative, root, control-byte or
//! traversal-containing value falls back to the specification default and emits
//! a warning instead of being honoured: an exported `XDG_CACHE_HOME=/` would
//! otherwise turn a cache sweep into a filesystem sweep.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::resolve::{has_control_bytes, has_parent_component, is_within, normalize};

/// Resolved base directories plus any warnings produced while resolving them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xdg {
    pub home: PathBuf,
    pub cache: PathBuf,
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
    /// The user's downloads directory.
    ///
    /// This is not an XDG *base* directory and it is not in [`Xdg::bases`]: the
    /// name is locale-dependent (`~/Downloads`, `~/İndirilenler`), so it comes
    /// from `XDG_DOWNLOAD_DIR` in `user-dirs.dirs` and falls back to
    /// `$HOME/Downloads`.
    pub download: PathBuf,
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
    /// Resolves from the process environment and the user's `user-dirs.dirs`.
    pub fn from_env() -> Result<Self, XdgError> {
        Self::resolve_with(
            |key| std::env::var_os(key),
            |path| std::fs::read_to_string(path).ok(),
        )
    }

    /// Resolves from an arbitrary lookup, with no filesystem read.
    ///
    /// `download` falls back to `$HOME/Downloads`. A test pins `HOME` to a path
    /// that does not exist, so reading the host's `user-dirs.dirs` here would
    /// let the machine decide the answer; [`Xdg::resolve_with`] is the constructor
    /// that takes a reader, and a test that cares about the file supplies one.
    pub fn resolve<F>(lookup: F) -> Result<Self, XdgError>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        Self::resolve_with(lookup, |_| None)
    }

    /// Resolves from an arbitrary lookup and an arbitrary file reader.
    ///
    /// The reader is what makes `user-dirs.dirs` testable without touching a
    /// real home directory: it receives the path and returns the file body.
    pub fn resolve_with<F, R>(lookup: F, read: R) -> Result<Self, XdgError>
    where
        F: Fn(&str) -> Option<OsString>,
        R: Fn(&Path) -> Option<String>,
    {
        let raw_home = lookup("HOME").ok_or(XdgError::HomeNotSet)?;
        let home = PathBuf::from(&raw_home);
        if !home.is_absolute() || is_usable_base(&home).is_err() {
            return Err(XdgError::HomeNotAbsolute(home));
        }
        // Every base is normalized before it leaves here. The hot path compares
        // them byte-wise (`is_within_named`, `is_within_normalized`), which is
        // only the same answer as a component walk for normalized paths, and
        // `HOME=/home/u/` would otherwise stop protecting `~/.ssh`.
        let home = normalize(&home);

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
                    normalize(&path)
                }
            }
            None => PathBuf::from(format!("/run/user/{}", crate::sys::euid())),
        };

        let download = download_dir(&config, &home, &read, &mut warnings);

        Ok(Self {
            home,
            cache,
            config,
            data,
            state,
            runtime,
            download,
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
    ///
    /// `download` is deliberately absent. This list is what validation refuses
    /// to delete as a whole, and a downloads directory is a user-chosen path, not
    /// an XDG base: refusing to remove `~/Downloads` wholesale is already the
    /// rule-root refusal, and listing it here would make every rule whose root is
    /// `{download}` fail to load as a `bare_root`.
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

/// The downloads directory, from `XDG_DOWNLOAD_DIR` in `user-dirs.dirs`.
///
/// The directory name is locale-dependent - `~/Downloads` in English,
/// `~/İndirilenler` in Turkish - so the setting decides where a browser put a
/// download, not a hardcoded English name. An exported `XDG_DOWNLOAD_DIR` is
/// ignored on purpose: this module takes no deletion root from the environment,
/// and the file is the documented owner of the setting.
///
/// Every failure falls back to `$HOME/Downloads` with a warning rather than
/// refusing the run. A hand-edited file must not stop a user from cleaning their
/// caches, and a value this function cannot trust must not become a deletion
/// root either.
fn download_dir<R>(config: &Path, home: &Path, read: &R, warnings: &mut Vec<String>) -> PathBuf
where
    R: Fn(&Path) -> Option<String>,
{
    let default = home.join("Downloads");
    let Some(content) = read(&config.join("user-dirs.dirs")) else {
        return default;
    };
    let Some(value) = parse_user_dirs(&content, "XDG_DOWNLOAD_DIR", home) else {
        return default;
    };
    // `xdg-user-dirs` writes `$HOME/` when the user turns the directory off, and
    // that value is already dropped during parsing. A literal `$HOME` gets here,
    // and reading it would point the installer sweep at the whole home directory.
    if value == home {
        return default;
    }
    if let Err(reason) = is_usable_base(&value) {
        warnings.push(format!(
            "XDG_DOWNLOAD_DIR ignored ({reason}); using {}",
            default.display()
        ));
        return default;
    }
    // An ancestor of `$HOME` puts the sweep above the user's own files, and the
    // two shapes a typo produces are `/home` and `/`.
    if is_within(&value, home) {
        warnings.push(format!(
            "XDG_DOWNLOAD_DIR ignored ({} is above $HOME); using {}",
            value.display(),
            default.display()
        ));
        return default;
    }
    if let Some(protected) = crate::policy::match_root(&value) {
        warnings.push(format!(
            "XDG_DOWNLOAD_DIR ignored ({} is protected: {}); using {}",
            value.display(),
            protected.why,
            default.display()
        ));
        return default;
    }
    value
}

/// Reads one `XDG_*_DIR` assignment out of a `user-dirs.dirs` body.
///
/// The file is a shell fragment, and it is never executed or `eval`ed: one key
/// is looked for, and only `$HOME` plus the backslash escapes a path can hold
/// are understood. A value carrying anything else - another variable, a command
/// substitution, a relative path - is unusable, and unusable means "fall back to
/// the default", never "guess where the user's files are".
pub fn parse_user_dirs(content: &str, key: &str, home: &Path) -> Option<PathBuf> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, raw)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != key {
            continue;
        }
        return parse_user_dir_value(raw.trim(), home);
    }
    None
}

fn parse_user_dir_value(raw: &str, home: &Path) -> Option<PathBuf> {
    let unquoted = match raw.chars().next() {
        Some(quote @ ('"' | '\'')) if raw.len() >= 2 && raw.ends_with(quote) => {
            &raw[1..raw.len() - 1]
        }
        _ => raw,
    };

    let mut text = String::with_capacity(unquoted.len());
    let mut chars = unquoted.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            text.push(ch);
            continue;
        }
        // The file is read the way a shell would read it, one level of
        // backslash removed, so `my\ downloads` is a directory with a space in
        // its name. It is never executed: a backslash cannot run anything.
        match chars.next() {
            Some(next) => text.push(next),
            None => text.push('\\'),
        }
    }

    // `$HOME` is the only variable the format defines, and it has to be a whole
    // component: `$HOME/Downloads` expands, `$HOMEOLD/x` is not a path we can
    // resolve. A backtick is a command substitution, which is never evaluated
    // here, so a value carrying one is simply refused.
    if text == "$HOME" {
        return Some(home.to_path_buf());
    }
    if let Some(rest) = text.strip_prefix("$HOME/") {
        if rest.contains('$') || rest.contains('`') || rest.is_empty() {
            return None;
        }
        return Some(home.join(rest));
    }
    if text.is_empty() || text.contains('$') || text.contains('`') {
        return None;
    }
    Some(PathBuf::from(text))
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
        Ok(()) => normalize(&path),
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
    fn every_base_is_normalized() {
        // The hot path compares these byte-wise, so a trailing separator or a
        // doubled one has to be gone before anything else sees them. Otherwise
        // `HOME=/home/u/` would stop protecting `~/.ssh`: the byte prefix
        // `/home/u/.ssh` does not start with `/home/u//`.
        let xdg = resolve(&[
            ("HOME", "/home/u/"),
            ("XDG_CACHE_HOME", "/home/u//cache/"),
            ("XDG_RUNTIME_DIR", "/run/user/1000/"),
        ]);
        assert_eq!(xdg.home, PathBuf::from("/home/u"));
        assert_eq!(xdg.cache, PathBuf::from("/home/u/cache"));
        assert_eq!(xdg.runtime, PathBuf::from("/run/user/1000"));
        assert_eq!(xdg.config, PathBuf::from("/home/u/.config"));
        assert_eq!(xdg.state, PathBuf::from("/home/u/.local/state"));
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

    // ------------------------------------------------ downloads directory ---

    /// Resolves with a `user-dirs.dirs` body the test supplies, so no test reads
    /// the host's own file.
    fn resolve_dirs(pairs: &[(&str, &str)], body: Option<&str>) -> Xdg {
        let map = env(pairs);
        Xdg::resolve_with(|key| map.get(key).cloned(), |_| body.map(str::to_string))
            .expect("home present")
    }

    #[test]
    fn download_defaults_to_the_english_name() {
        let xdg = resolve_dirs(&[("HOME", "/home/u")], None);
        assert_eq!(xdg.download, PathBuf::from("/home/u/Downloads"));
        assert!(xdg.warnings.is_empty());
    }

    #[test]
    fn the_user_dirs_setting_names_the_downloads_directory() {
        let body = "# written by xdg-user-dirs-update\n\
                    XDG_DESKTOP_DIR=\"$HOME/Desktop\"\n\
                    XDG_DOWNLOAD_DIR=\"$HOME/İndirilenler\"\n";
        let xdg = resolve_dirs(&[("HOME", "/home/u")], Some(body));
        assert_eq!(xdg.download, PathBuf::from("/home/u/İndirilenler"));
        assert!(xdg.warnings.is_empty(), "{:?}", xdg.warnings);
    }

    #[test]
    fn an_absolute_downloads_directory_on_another_disk_is_honoured() {
        // The directory name is a setting, and a separate disk is a legitimate
        // value: refusing it would push the sweep back to an empty `~/Downloads`.
        let body = "XDG_DOWNLOAD_DIR=\"/mnt/data/Downloads\"\n";
        let xdg = resolve_dirs(&[("HOME", "/home/u")], Some(body));
        assert_eq!(xdg.download, PathBuf::from("/mnt/data/Downloads"));
    }

    #[test]
    fn the_disabled_marker_falls_back_to_the_english_name() {
        // `xdg-user-dirs` writes `$HOME/` when the user turns the directory off.
        // Reading that literally would point the installer sweep at the whole
        // home directory.
        let body = "XDG_DOWNLOAD_DIR=\"$HOME/\"\n";
        let xdg = resolve_dirs(&[("HOME", "/home/u")], Some(body));
        assert_eq!(xdg.download, PathBuf::from("/home/u/Downloads"));
    }

    #[test]
    fn a_protected_downloads_directory_is_refused_with_a_warning() {
        let body = "XDG_DOWNLOAD_DIR=\"/etc\"\n";
        let xdg = resolve_dirs(&[("HOME", "/home/u")], Some(body));
        assert_eq!(xdg.download, PathBuf::from("/home/u/Downloads"));
        assert_eq!(xdg.warnings.len(), 1, "{:?}", xdg.warnings);
        assert!(xdg.warnings[0].contains("protected"), "{:?}", xdg.warnings);
    }

    #[test]
    fn a_downloads_directory_above_home_is_refused() {
        // `/home` is what a typo in the file produces, and it would put the sweep
        // above every user's own files.
        let body = "XDG_DOWNLOAD_DIR=\"/home\"\n";
        let xdg = resolve_dirs(&[("HOME", "/home/u")], Some(body));
        assert_eq!(xdg.download, PathBuf::from("/home/u/Downloads"));
        assert!(
            xdg.warnings[0].contains("above $HOME"),
            "{:?}",
            xdg.warnings
        );
    }

    #[test]
    fn a_sibling_of_home_is_not_above_home() {
        // The test is component-wise, not a byte prefix: `/home/u2` must not be
        // read as `/home/u`.
        let body = "XDG_DOWNLOAD_DIR=\"/home/u2/Downloads\"\n";
        let xdg = resolve_dirs(&[("HOME", "/home/u")], Some(body));
        assert_eq!(xdg.download, PathBuf::from("/home/u2/Downloads"));
        assert!(xdg.warnings.is_empty(), "{:?}", xdg.warnings);
    }

    #[test]
    fn a_relative_downloads_directory_is_refused() {
        let body = "XDG_DOWNLOAD_DIR=\"Downloads\"\n";
        let xdg = resolve_dirs(&[("HOME", "/home/u")], Some(body));
        assert_eq!(xdg.download, PathBuf::from("/home/u/Downloads"));
        assert!(
            xdg.warnings[0].contains("not absolute"),
            "{:?}",
            xdg.warnings
        );
    }

    #[test]
    fn user_dirs_parsing_reads_one_key_and_ignores_the_rest() {
        let body = "\
# XDG_DOWNLOAD_DIR=\"$HOME/commented-out\"
XDG_DESKTOP_DIR=\"$HOME/Desktop\"
  XDG_DOWNLOAD_DIR = \"$HOME/Downloads\"  
XDG_DOWNLOAD_DIR=\"$HOME/second-wins-is-not-a-thing\"
";
        assert_eq!(
            parse_user_dirs(body, "XDG_DOWNLOAD_DIR", Path::new("/home/u")),
            Some(PathBuf::from("/home/u/Downloads"))
        );
    }

    #[test]
    fn user_dirs_parsing_understands_the_escapes_a_path_can_hold() {
        let body = "XDG_DOWNLOAD_DIR=\"$HOME/my\\ downloads\"\n";
        assert_eq!(
            parse_user_dirs(body, "XDG_DOWNLOAD_DIR", Path::new("/home/u")),
            Some(PathBuf::from("/home/u/my downloads"))
        );
        let body = "XDG_DOWNLOAD_DIR='$HOME/quoted'\n";
        assert_eq!(
            parse_user_dirs(body, "XDG_DOWNLOAD_DIR", Path::new("/home/u")),
            Some(PathBuf::from("/home/u/quoted"))
        );
    }

    #[test]
    fn user_dirs_parsing_refuses_a_value_it_cannot_resolve() {
        // Another variable, a command substitution, and `$HOME` glued to a name
        // are all unusable. Guessing would invent a deletion root.
        for body in [
            "XDG_DOWNLOAD_DIR=\"$XDG_DATA_HOME/downloads\"\n",
            "XDG_DOWNLOAD_DIR=\"$(rm -rf /)\"\n",
            "XDG_DOWNLOAD_DIR=\"`rm -rf /`\"\n",
            "XDG_DOWNLOAD_DIR=\"$HOMEOLD/downloads\"\n",
            "XDG_DOWNLOAD_DIR=\"$HOME/\"\n",
            "XDG_DOWNLOAD_DIR=\"\"\n",
        ] {
            let parsed = parse_user_dirs(body, "XDG_DOWNLOAD_DIR", Path::new("/home/u"));
            assert!(
                parsed.is_none(),
                "{body:?} parsed as {parsed:?}; an unusable value must fall back"
            );
        }
    }

    #[test]
    fn user_dirs_parsing_returns_nothing_without_the_key() {
        let body = "XDG_DESKTOP_DIR=\"$HOME/Desktop\"\n";
        assert_eq!(
            parse_user_dirs(body, "XDG_DOWNLOAD_DIR", Path::new("/home/u")),
            None
        );
    }
}
