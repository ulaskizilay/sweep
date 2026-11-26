//! The explorer's state, separated from the terminal.
//!
//! Everything a keystroke can do is a method here, and nothing here draws or
//! reads input. That is what makes the behaviour testable: the tests drive keys
//! through [`App::on_key`] and assert on state, without a terminal, a PTY or a
//! screenshot.
//!
//! Two rules are enforced in this layer rather than the drawing layer, because a
//! bug in the drawing code must not be able to break them:
//!
//! * the selection can never leave the root the explorer was opened with, so
//!   `..` at the top does nothing instead of escaping to the parent directory;
//! * a delete is always a two-key sequence — ask, then confirm — and the thing
//!   confirmed is the thing that was asked about, kept in `pending`.

use std::path::PathBuf;

use crossterm::event::KeyCode;

use super::measure::{Sizes, Update};
use super::view::{self, Row, Sort};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Browse,
    Filter,
    /// A delete was asked about and is waiting for `y`.
    Confirm,
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Reload,
    Trash(Row),
}

pub struct App {
    pub root: PathBuf,
    pub cwd: PathBuf,
    rows: Vec<Row>,
    /// Row indices in display order.
    order: Vec<usize>,
    selected: usize,
    /// Whether the user has put the cursor somewhere in this directory.
    ///
    /// Until they do, the cursor stays on the first row: the sizes that arrive
    /// after the directory opens re-sort the list, and pinning the cursor to the
    /// first row keeps it on the entry the user is about to look at instead of
    /// leaving it on whichever name the empty list happened to sort first.
    chosen: bool,
    pub sort: Sort,
    pub reverse: bool,
    pub filter: String,
    draft: String,
    pub mode: Mode,
    pub status: String,
    /// The last refusal or failure, shown until the next action.
    pub error: Option<String>,
    sizes: Option<Sizes>,
    pending: Option<Row>,
}

impl App {
    pub fn open(root: &std::path::Path) -> std::io::Result<Self> {
        let rows = view::build(root)?;
        let order = view::order(&rows, Sort::Size, false, "");
        let mut app = Self {
            root: root.to_path_buf(),
            cwd: root.to_path_buf(),
            rows,
            order,
            selected: 0,
            chosen: false,
            sort: Sort::Size,
            reverse: false,
            filter: String::new(),
            draft: String::new(),
            mode: Mode::Browse,
            status: String::new(),
            error: None,
            sizes: None,
            pending: None,
        };
        app.start_measuring();
        app.refresh_status();
        Ok(app)
    }

    // ------------------------------------------------------------- accessors ---

    pub fn visible(&self) -> &[usize] {
        &self.order
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.order
            .get(self.selected)
            .and_then(|index| self.rows.get(*index))
    }

    pub fn pending(&self) -> Option<&Row> {
        self.pending.as_ref()
    }

    pub fn draft(&self) -> &str {
        &self.draft
    }

    /// How many directory walks have finished, while any are still running.
    pub fn measuring(&self) -> Option<(usize, usize)> {
        let sizes = self.sizes.as_ref()?;
        if sizes.is_finished() {
            return None;
        }
        Some((sizes.done, sizes.total))
    }

    pub fn total_bytes(&self) -> u64 {
        self.rows.iter().map(|row| row.bytes()).sum()
    }

    // ---------------------------------------------------------------- moving ---

    /// One frame's worth of measurement results.
    pub fn tick(&mut self) {
        let Some(path) = self.selected_path() else {
            return;
        };
        let mut applied = 0;
        while applied < 512 {
            let Some(update) = self.sizes.as_mut().and_then(Sizes::poll) else {
                break;
            };
            if let Update::Measured { index, measured } = update {
                if let Some(row) = self.rows.get_mut(index) {
                    row.subtree = Some(measured);
                }
                applied += 1;
            }
        }
        if applied > 0 {
            self.reorder();
            if self.chosen {
                self.reselect(Some(&path));
            } else {
                self.selected = 0;
            }
            self.refresh_status();
        }
    }

    pub fn move_by(&mut self, delta: isize) {
        self.chosen = true;
        if self.order.is_empty() {
            self.selected = 0;
            return;
        }
        let last = self.order.len() - 1;
        let next = self.selected as isize + delta;
        self.selected = next.clamp(0, last as isize) as usize;
    }

    pub fn jump(&mut self, to_end: bool) {
        self.chosen = true;
        if self.order.is_empty() {
            self.selected = 0;
        } else if to_end {
            self.selected = self.order.len() - 1;
        } else {
            self.selected = 0;
        }
    }

    /// Enters the selected directory. Returns whether the view changed.
    pub fn descend(&mut self) -> bool {
        let Some(row) = self.selected_row().cloned() else {
            return false;
        };
        // A symbolic link is checked first: `is_dir` is false for a link to a
        // directory, so the reverse order would call a link a file.
        if row.is_symlink {
            self.status = format!(
                "{} is a symbolic link; sweep does not follow links",
                row.name
            );
            return false;
        }
        if !row.is_dir {
            self.status = format!("{} is a file; nothing to open", row.name);
            return false;
        }
        if let Err(error) = self.open_dir(row.path) {
            self.error = Some(error.to_string());
            return false;
        }
        true
    }

    /// Goes up one level, stopping at the root the explorer was opened with.
    pub fn ascend(&mut self) -> bool {
        if self.cwd == self.root {
            self.status = "this is the top of the explorer".to_string();
            return false;
        }
        let Some(parent) = self.cwd.parent() else {
            return false;
        };
        if !parent.starts_with(&self.root) {
            return false;
        }
        let came_from = self.cwd.clone();
        if let Err(error) = self.open_dir(parent.to_path_buf()) {
            self.error = Some(error.to_string());
            return false;
        }
        // Land on the directory we came out of, not on the first row.
        if let Some(index) = self
            .order
            .iter()
            .position(|row| self.rows[*row].path == came_from)
        {
            self.selected = index;
            self.chosen = true;
        }
        true
    }

    /// Rescans the current directory, keeping the selection where it was.
    pub fn reload(&mut self) {
        let path = self.selected_path();
        let cwd = self.cwd.clone();
        if let Err(error) = self.open_dir(cwd) {
            self.error = Some(error.to_string());
            return;
        }
        if let Some(path) = path {
            self.reselect(Some(&path));
            self.chosen = true;
        }
        self.status = "rescanned".to_string();
    }

    fn open_dir(&mut self, path: PathBuf) -> std::io::Result<()> {
        let rows = view::build(&path)?;
        self.rows = rows;
        self.cwd = path;
        self.selected = 0;
        self.chosen = false;
        self.error = None;
        self.reorder();
        self.start_measuring();
        self.refresh_status();
        Ok(())
    }

    fn start_measuring(&mut self) {
        let directories: Vec<(usize, PathBuf)> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.is_dir && !row.is_symlink)
            .map(|(index, row)| (index, row.path.clone()))
            .collect();
        self.sizes = Sizes::spawn(directories);
    }

    fn reorder(&mut self) {
        self.order = view::order(&self.rows, self.sort, self.reverse, &self.filter);
    }

    fn reselect(&mut self, path: Option<&std::path::Path>) {
        if let Some(path) = path {
            if let Some(index) = self
                .order
                .iter()
                .position(|row| self.rows[*row].path == path)
            {
                self.selected = index;
                return;
            }
        }
        self.selected = self.selected.min(self.order.len().saturating_sub(1));
    }

    fn selected_path(&self) -> Option<PathBuf> {
        self.selected_row().map(|row| row.path.clone())
    }

    // -------------------------------------------------------- sort and filter ---

    pub fn cycle_sort(&mut self) {
        let path = self.selected_path();
        self.sort = self.sort.next();
        self.reorder();
        self.reselect(path.as_deref());
        self.chosen = true;
        self.status = format!(
            "sorted by {}{}",
            self.sort.label(),
            if self.reverse { ", reversed" } else { "" }
        );
    }

    pub fn toggle_reverse(&mut self) {
        self.reverse = !self.reverse;
        let path = self.selected_path();
        self.reorder();
        self.reselect(path.as_deref());
        self.chosen = true;
        self.status = format!(
            "sorted by {}{}",
            self.sort.label(),
            if self.reverse { ", reversed" } else { "" }
        );
    }

    pub fn begin_filter(&mut self) {
        self.draft = self.filter.clone();
        self.mode = Mode::Filter;
    }

    pub fn filter_push(&mut self, character: char) {
        self.draft.push(character);
        self.apply_filter_draft();
    }

    pub fn filter_backspace(&mut self) {
        self.draft.pop();
        self.apply_filter_draft();
    }

    fn apply_filter_draft(&mut self) {
        let path = self.selected_path();
        self.filter = self.draft.clone();
        self.reorder();
        self.reselect(path.as_deref());
    }

    pub fn filter_commit(&mut self) {
        self.filter = self.draft.clone();
        self.mode = Mode::Browse;
        self.reorder();
        self.reselect(None);
        self.refresh_status();
    }

    pub fn filter_cancel(&mut self) {
        self.draft.clear();
        self.filter.clear();
        self.mode = Mode::Browse;
        self.reorder();
        self.reselect(None);
        self.refresh_status();
    }

    pub fn clear_filter(&mut self) {
        if self.filter.is_empty() {
            return;
        }
        self.filter.clear();
        self.draft.clear();
        self.reorder();
        self.reselect(None);
        self.refresh_status();
    }

    // --------------------------------------------------- ask, then confirm ---

    pub fn ask_delete(&mut self) {
        if self.selected_row().is_some() {
            self.pending = self.selected_row().cloned();
            self.mode = Mode::Confirm;
            self.error = None;
        }
    }

    pub fn cancel_delete(&mut self) {
        self.pending = None;
        self.mode = Mode::Browse;
    }

    /// Called by the caller after a successful move, so the row disappears from a
    /// list that would otherwise show an entry that is no longer there.
    pub fn after_trash(&mut self, path: &std::path::Path, destination: &std::path::Path) {
        let index = self.selected;
        let before = self.rows.len();
        self.rows.retain(|row| row.path != path);
        if self.rows.len() != before {
            self.reorder();
            self.selected = index.min(self.order.len().saturating_sub(1));
        }
        self.pending = None;
        self.mode = Mode::Browse;
        self.error = None;
        self.status = format!("moved to {}", destination.display());
    }

    pub fn report_error(&mut self, message: String) {
        self.pending = None;
        self.mode = Mode::Browse;
        self.error = Some(message);
    }

    fn refresh_status(&mut self) {
        self.status = match self.measuring() {
            Some((done, total)) => format!("measuring {done} of {total} directories"),
            None => String::new(),
        };
    }

    // ------------------------------------------------------------- keyboard ---

    pub fn on_key(&mut self, code: KeyCode) -> Action {
        match self.mode {
            Mode::Confirm => self.on_confirm(code),
            Mode::Filter => self.on_filter(code),
            Mode::Help => {
                self.mode = Mode::Browse;
                Action::None
            }
            Mode::Browse => self.on_browse(code),
        }
    }

    fn on_confirm(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let row = self.pending.take();
                self.mode = Mode::Browse;
                match row {
                    Some(row) => Action::Trash(row),
                    None => Action::None,
                }
            }
            _ => {
                self.cancel_delete();
                self.status = "kept".to_string();
                Action::None
            }
        }
    }

    fn on_filter(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Char(character) => {
                self.filter_push(character);
                Action::None
            }
            KeyCode::Backspace => {
                self.filter_backspace();
                Action::None
            }
            KeyCode::Enter => {
                self.filter_commit();
                Action::None
            }
            KeyCode::Esc => {
                self.filter_cancel();
                Action::None
            }
            KeyCode::Down => {
                self.move_by(1);
                Action::None
            }
            KeyCode::Up => {
                self.move_by(-1);
                Action::None
            }
            _ => Action::None,
        }
    }

    fn on_browse(&mut self, code: KeyCode) -> Action {
        self.error = None;
        match code {
            KeyCode::Char('q') => Action::Quit,
            KeyCode::Esc => {
                if self.filter.is_empty() {
                    Action::Quit
                } else {
                    self.clear_filter();
                    Action::None
                }
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_by(1);
                Action::None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_by(-1);
                Action::None
            }
            KeyCode::PageDown => {
                self.move_by(10);
                Action::None
            }
            KeyCode::PageUp => {
                self.move_by(-10);
                Action::None
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.jump(false);
                Action::None
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.jump(true);
                Action::None
            }
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                self.descend();
                Action::None
            }
            KeyCode::Backspace | KeyCode::Char('h') | KeyCode::Left => {
                self.ascend();
                Action::None
            }
            KeyCode::Char('s') => {
                self.cycle_sort();
                Action::None
            }
            KeyCode::Char('S') => {
                self.toggle_reverse();
                Action::None
            }
            KeyCode::Char('r') => Action::Reload,
            KeyCode::Char('/') => {
                self.begin_filter();
                Action::None
            }
            KeyCode::Char('d') | KeyCode::Char('x') => {
                self.ask_delete();
                Action::None
            }
            KeyCode::Char('?') => {
                self.mode = Mode::Help;
                Action::None
            }
            _ => Action::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, FileTimes};
    use std::time::{Duration, SystemTime};

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join("big")).expect("mkdir");
        std::fs::write(temp.path().join("big/data.bin"), vec![b'x'; 8192]).expect("write");
        std::fs::create_dir_all(temp.path().join("small")).expect("mkdir");
        std::fs::write(temp.path().join("small/one.txt"), b"one").expect("write");
        std::fs::write(temp.path().join("top.txt"), b"top").expect("write");
        let when = SystemTime::now() - Duration::from_secs(10 * 86_400);
        for relative in ["big/data.bin", "small/one.txt"] {
            File::options()
                .read(true)
                .open(temp.path().join(relative))
                .expect("open")
                .set_times(FileTimes::new().set_modified(when))
                .expect("set mtime");
        }
        temp
    }

    fn names(app: &App) -> Vec<String> {
        app.visible()
            .iter()
            .map(|index| app.rows()[*index].name.clone())
            .collect()
    }

    #[test]
    fn the_explorer_opens_on_the_root_and_shows_every_entry() {
        let temp = fixture();
        let app = App::open(temp.path()).expect("open");
        assert_eq!(app.cwd, temp.path());
        let mut names = names(&app);
        names.sort();
        assert_eq!(names, ["big", "small", "top.txt"]);
        assert_eq!(app.selected(), 0, "something is selected from the start");
    }

    #[test]
    fn a_keystroke_moves_the_selection_without_leaving_the_list() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        app.on_key(KeyCode::Char('k'));
        assert_eq!(app.selected(), 0, "up at the top stays at the top");
        app.on_key(KeyCode::Char('j'));
        assert_eq!(app.selected(), 1);
        app.on_key(KeyCode::End);
        assert_eq!(app.selected(), app.visible().len() - 1);
        app.on_key(KeyCode::Char('j'));
        assert_eq!(app.selected(), app.visible().len() - 1, "and at the bottom");
    }

    #[test]
    fn ascending_at_the_root_does_nothing() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        assert!(!app.ascend());
        assert_eq!(app.cwd, temp.path());
        assert!(app.status.contains("top of the explorer"));
    }

    #[test]
    fn entering_a_directory_and_returning_lands_on_it() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        let index = app
            .visible()
            .iter()
            .position(|row| app.rows()[*row].name == "big")
            .expect("big");
        app.selected = index;
        assert!(app.on_key(KeyCode::Enter) == Action::None);
        assert_eq!(app.cwd, temp.path().join("big"));
        assert_eq!(names(&app), ["data.bin"]);

        app.on_key(KeyCode::Backspace);
        assert_eq!(app.cwd, temp.path());
        assert_eq!(app.selected_row().expect("row").name, "big");
    }

    #[test]
    fn a_file_does_not_open_and_a_symlinked_directory_is_not_followed() {
        let temp = fixture();
        std::os::unix::fs::symlink(temp.path().join("big"), temp.path().join("link"))
            .expect("link");
        let mut app = App::open(temp.path()).expect("open");
        let select = |app: &mut App, name: &str| {
            app.selected = app
                .visible()
                .iter()
                .position(|row| app.rows()[*row].name == name)
                .expect(name);
        };
        select(&mut app, "top.txt");
        app.on_key(KeyCode::Enter);
        assert_eq!(app.cwd, temp.path(), "a file is not a directory");
        select(&mut app, "link");
        app.on_key(KeyCode::Enter);
        assert_eq!(app.cwd, temp.path(), "a link is not followed");
        assert!(app.status.contains("symbolic link"), "{}", app.status);
    }

    #[test]
    fn sort_cycles_and_reverse_flips_the_order() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        assert_eq!(app.sort, Sort::Size);
        app.on_key(KeyCode::Char('s'));
        assert_eq!(app.sort, Sort::Name);
        assert_eq!(names(&app), ["big", "small", "top.txt"]);
        app.on_key(KeyCode::Char('S'));
        assert!(app.reverse);
        assert_eq!(names(&app), ["top.txt", "small", "big"]);
    }

    #[test]
    fn the_filter_narrows_the_list_and_escape_clears_it() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        app.on_key(KeyCode::Char('/'));
        assert_eq!(app.mode, Mode::Filter);
        for character in "to".chars() {
            app.on_key(KeyCode::Char(character));
        }
        assert_eq!(names(&app), ["top.txt"]);
        app.on_key(KeyCode::Enter);
        assert_eq!(app.mode, Mode::Browse);
        assert_eq!(names(&app), ["top.txt"]);

        app.on_key(KeyCode::Esc);
        assert!(app.filter.is_empty(), "escape clears the filter first");
        assert!(!names(&app).is_empty());
        app.on_key(KeyCode::Esc);
        assert_eq!(
            app.on_key(KeyCode::Esc),
            Action::Quit,
            "and quits once nothing is left to clear"
        );
    }

    #[test]
    fn deleting_takes_two_keys_and_the_second_one_confirms_the_first() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        app.on_key(KeyCode::Char('d'));
        assert_eq!(app.mode, Mode::Confirm);
        let pending = app.pending().expect("asked about a row").clone();
        assert_eq!(pending.name, app.selected_row().expect("row").name);

        // A keystroke that is not `y` keeps the entry.
        assert_eq!(app.on_key(KeyCode::Char('n')), Action::None);
        assert_eq!(app.mode, Mode::Browse);
        assert!(app.pending().is_none());
        assert!(temp.path().join("big").exists());
    }

    #[test]
    fn confirming_returns_the_row_that_was_asked_about() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        app.on_key(KeyCode::Char('d'));
        let asked = app.pending().expect("asked").clone();
        let action = app.on_key(KeyCode::Char('y'));
        assert!(matches!(action, Action::Trash(row) if row.path == asked.path));
        assert_eq!(app.mode, Mode::Browse);
        assert!(app.pending().is_none());
    }

    #[test]
    fn a_row_that_was_trashed_disappears_from_the_list() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        let path = temp.path().join("top.txt");
        app.after_trash(
            &path,
            std::path::Path::new("/home/u/.local/share/Trash/files/top.txt"),
        );
        assert!(
            names(&app).iter().all(|name| name != "top.txt"),
            "{:?}",
            names(&app)
        );
        assert!(app.status.contains("moved to"));
    }

    #[test]
    fn measurements_arrive_and_replace_the_pending_size() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        for _ in 0..600 {
            app.tick();
            let measured = app
                .rows()
                .iter()
                .find(|row| row.name == "big")
                .and_then(|row| row.subtree);
            if let Some(measured) = measured {
                assert!(measured.items >= 1, "{measured:?}");
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the sizes never arrived");
    }

    #[test]
    fn the_sizes_settling_leave_the_cursor_on_the_first_row_until_it_is_moved() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join("aaa")).expect("mkdir");
        std::fs::write(temp.path().join("aaa/one.txt"), b"one").expect("write");
        std::fs::create_dir_all(temp.path().join("zzz")).expect("mkdir");
        std::fs::write(temp.path().join("zzz/big.bin"), vec![b'x'; 65536]).expect("write");

        let mut app = App::open(temp.path()).expect("open");
        assert_eq!(
            app.selected_row().expect("row").name,
            "aaa",
            "an unmeasured list has no sizes to sort by, so it falls back to the name"
        );

        for _ in 0..600 {
            app.tick();
            if app.measuring().is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(names(&app)[0], "zzz", "the measured sizes re-sort the list");
        assert_eq!(
            app.selected(),
            0,
            "the cursor never left the first row: {:?}",
            names(&app)
        );
        assert_eq!(app.selected_row().expect("row").name, "zzz");
    }

    #[test]
    fn a_moved_cursor_stays_on_its_row_while_sizes_arrive() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        let chosen = app.selected_row().expect("row").path.clone();
        app.on_key(KeyCode::Char('j'));
        let moved_to = app.selected_row().expect("row").path.clone();
        assert_ne!(chosen, moved_to, "the fixture has a second row");

        for _ in 0..600 {
            app.tick();
            if app.measuring().is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(
            app.selected_row().expect("row").path,
            moved_to,
            "the row the user chose is the row that stays highlighted"
        );
    }
}
