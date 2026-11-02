//! What a directory looks like to the explorer.
//!
//! A row is one entry of the directory being shown. Its size for a file is the
//! bytes that file occupies; for a directory it is the size of everything below
//! it, which is the number the user actually wants and which has to be measured
//! by walking. That measurement is asynchronous (see [`crate::analyze::measure`])
//! because walking a home directory takes long enough to be visible.
//!
//! Sorting and filtering live here rather than in the drawing code so they can be
//! tested without a terminal.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// What the subtree below a directory was measured to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {
    pub bytes: u64,
    pub items: u64,
    /// The walk hit an entry or time budget, so `bytes` is a lower bound.
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub is_symlink: bool,
    /// Bytes this entry itself occupies. A directory's own block, not its tree.
    pub own_bytes: u64,
    /// Set for a directory once its subtree has been measured.
    pub subtree: Option<Measured>,
    pub mtime: i64,
}

impl Row {
    /// The number shown in the size column, and the number the confirmation
    /// quotes.
    pub fn bytes(&self) -> u64 {
        match self.subtree {
            Some(measured) => measured.bytes,
            None => self.own_bytes,
        }
    }

    pub fn items(&self) -> Option<u64> {
        self.subtree.map(|measured| measured.items)
    }

    pub fn age_days(&self) -> u64 {
        age_days(self.mtime)
    }

    /// True when deleting this row would take a symbolic link out of the tree
    /// rather than what it points at.
    pub fn is_link(&self) -> bool {
        self.is_symlink
    }
}

/// A short age for a column: `today`, `9 days`, `4 mo`.
pub fn age_text(days: u64) -> String {
    match days {
        0 => "today".to_string(),
        1 => "1 day".to_string(),
        d if d < 45 => format!("{d} days"),
        d => format!("{} mo", d / 30),
    }
}

pub fn age_days(mtime: i64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    (now.saturating_sub(mtime) / 86_400) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Size,
    Name,
    Modified,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Sort::Size => Sort::Name,
            Sort::Name => Sort::Modified,
            Sort::Modified => Sort::Size,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Sort::Size => "size",
            Sort::Name => "name",
            Sort::Modified => "modified",
        }
    }
}

/// Reads one directory into rows, without measuring any subtree.
///
/// A missing directory is an error the caller shows; an entry that vanished
/// between `read_dir` and `symlink_metadata` is skipped, because a file that is
/// gone cannot be shown and cannot be chosen.
pub fn build(dir: &Path) -> std::io::Result<Vec<Row>> {
    use std::os::unix::fs::MetadataExt;
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let file_type = meta.file_type();
        rows.push(Row {
            name,
            path,
            is_dir: meta.is_dir(),
            is_symlink: file_type.is_symlink(),
            own_bytes: if meta.is_dir() {
                0
            } else {
                meta.blocks().saturating_mul(512)
            },
            subtree: None,
            mtime: mtime(&meta),
        });
    }
    // A stable starting order, so the rows do not jump while the sizes arrive.
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(rows)
}

fn mtime(meta: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    meta.mtime()
}

/// The indices of `rows` in display order: filter first, then sort.
pub fn order(rows: &[Row], sort: Sort, reverse: bool, filter: &str) -> Vec<usize> {
    let needle = filter.to_lowercase();
    let mut indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| needle.is_empty() || row.name.to_lowercase().contains(&needle))
        .map(|(index, _)| index)
        .collect();

    indices.sort_by(|left, right| {
        let a = &rows[*left];
        let b = &rows[*right];
        match sort {
            Sort::Size => size_order(a, b),
            Sort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            Sort::Modified => b.mtime.cmp(&a.mtime),
        }
        .then_with(|| a.name.cmp(&b.name))
    });
    if reverse {
        indices.reverse();
    }
    indices
}

/// Bigger first, with directories still being measured last.
///
/// A `None` subtree is not zero: it is "not measured yet", and sorting it as
/// zero would bury the largest directory at the bottom of the list until its walk
/// finished, which is exactly when the user is waiting for it to appear.
fn size_order(a: &Row, b: &Row) -> std::cmp::Ordering {
    match (a.bytes_state(), b.bytes_state()) {
        (Some(left), Some(right)) => right.cmp(&left),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

impl Row {
    fn bytes_state(&self) -> Option<u64> {
        if self.is_dir && self.subtree.is_none() {
            None
        } else {
            Some(self.bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, bytes: u64, mtime: i64) -> Row {
        Row {
            name: name.to_string(),
            path: PathBuf::from("/home/u").join(name),
            is_dir: false,
            is_symlink: false,
            own_bytes: bytes,
            subtree: None,
            mtime,
        }
    }

    fn dir(name: &str, measured: Option<u64>) -> Row {
        Row {
            is_dir: true,
            own_bytes: 0,
            subtree: measured.map(|bytes| Measured {
                bytes,
                items: 3,
                partial: false,
            }),
            ..row(name, 0, 0)
        }
    }

    #[test]
    fn size_sort_puts_the_biggest_first_and_unmeasured_directories_last() {
        let rows = vec![
            row("small.bin", 10, 0),
            dir("measuring", None),
            row("big.bin", 1_000, 0),
            dir("cache", Some(500)),
        ];
        let order = order(&rows, Sort::Size, false, "");
        let names: Vec<&str> = order
            .iter()
            .map(|index| rows[*index].name.as_str())
            .collect();
        assert_eq!(names, ["big.bin", "cache", "small.bin", "measuring"]);
    }

    #[test]
    fn name_sort_is_case_insensitive_and_reversible() {
        let rows = vec![row("Beta", 0, 0), row("alpha", 0, 0), row("Gamma", 0, 0)];
        let names = |reverse| -> Vec<String> {
            order(&rows, Sort::Name, reverse, "")
                .iter()
                .map(|index| rows[*index].name.clone())
                .collect()
        };
        assert_eq!(names(false), ["alpha", "Beta", "Gamma"]);
        assert_eq!(names(true), ["Gamma", "Beta", "alpha"]);
    }

    #[test]
    fn modified_sort_is_newest_first() {
        let rows = vec![
            row("old", 0, 1_000),
            row("new", 0, 3_000),
            row("middle", 0, 2_000),
        ];
        let names: Vec<&str> = order(&rows, Sort::Modified, false, "")
            .iter()
            .map(|index| rows[*index].name.as_str())
            .collect();
        assert_eq!(names, ["new", "middle", "old"]);
    }

    #[test]
    fn the_filter_is_a_case_insensitive_substring() {
        let rows = vec![row("photo.JPG", 0, 0), row("notes.txt", 0, 0)];
        let order = order(&rows, Sort::Size, false, "jpg");
        assert_eq!(order.len(), 1);
        assert_eq!(rows[order[0]].name, "photo.JPG");
    }

    #[test]
    fn build_reads_metadata_and_never_follows_a_link() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("file"), b"12345").expect("write");
        std::fs::create_dir(temp.path().join("dir")).expect("mkdir");
        std::os::unix::fs::symlink("/etc/passwd", temp.path().join("link")).expect("link");

        let rows = build(temp.path()).expect("read");
        let by_name = |name: &str| rows.iter().find(|row| row.name == name).expect(name);
        assert!(by_name("dir").is_dir);
        assert!(by_name("link").is_symlink, "a link is shown as a link");
        assert!(!by_name("link").is_dir, "and never as its target");
        assert_eq!(by_name("file").own_bytes, 8 * 512, "block accounting");
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        assert!(build(Path::new("/definitely/not/here")).is_err());
    }
}
