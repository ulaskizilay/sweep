//! The explorer, driven the way a terminal drives it.
//!
//! Every other test of `analyze` calls into the app or reads `--largest`
//! output; none of them opens a terminal, so the ratatui draw loop, crossterm's
//! raw mode and the key path that actually moves a file were unproven end to
//! end. This file allocates a real pseudo-terminal, runs the real binary in it,
//! and types the keys a person would.
//!
//! The assertions are about what a person saw and what the filesystem holds
//! afterwards, not about escape sequences: the screen must name the directory
//! and the footer, the confirmation must ask before anything moves, and the
//! payload must end up in the trash with a record that names where it came from.
//!
//! Reading the screen needs the small terminal in [`Screen`] rather than a
//! substring search over the byte stream, because a full-screen program redraws
//! by patching cells: a frame that changes one letter writes only that letter and
//! leaves the rest of the word where it already was on the terminal.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ROWS: usize = 40;
const COLS: usize = 120;

/// A child process attached to a pseudo-terminal, plus the screen it drew.
struct Session {
    child: Child,
    master: File,
    screen: Screen,
}

impl Session {
    /// Starts `sweep` with `args` in a terminal of [`ROWS`] by [`COLS`].
    fn start(args: &[&OsStr], home: &Home) -> Session {
        let (master_fd, slave_fd) = open_pty();

        let binary = env!("CARGO_BIN_EXE_sweep");
        let mut command = Command::new(binary);
        command.args(args);
        command.env("TERM", "xterm-256color");
        for (key, value) in home.envs() {
            command.env(key, value);
        }
        // The child owns the slave side; each standard stream needs its own
        // descriptor, because one descriptor handed to all three would be closed
        // three times when the child is reaped.
        command.stdin(Stdio::from(dup(slave_fd)));
        command.stdout(Stdio::from(dup(slave_fd)));
        command.stderr(Stdio::from(dup(slave_fd)));
        // A new session is what a program started by a terminal emulator sees;
        // without it the child could open the test runner's own terminal.
        // SAFETY: `setsid` is async-signal-safe and is the only call in the child
        // before `exec`.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn sweep");

        // The parent keeps only the master side; leaving the slave open would
        // keep the child from ever seeing end-of-file.
        // SAFETY: `slave_fd` came from `openpty` and is closed exactly once.
        unsafe { libc::close(slave_fd) };
        // SAFETY: `master_fd` is owned from here on and closed by `File`.
        let master = unsafe { File::from_raw_fd(master_fd) };
        // Non-blocking reads let the helpers below drain whatever arrived and
        // return, instead of blocking forever on a quiet screen.
        // SAFETY: the descriptor is live and `F_GETFL` has no preconditions.
        unsafe {
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        Session {
            child,
            master,
            screen: Screen::new(ROWS, COLS),
        }
    }

    /// Reads until `needle` is on screen, or the deadline passes.
    ///
    /// Ready-to-type is a screen event, not a sleep: the test waits for the text
    /// it is about to react to, so a slow machine takes longer instead of
    /// failing.
    fn wait_for(&mut self, needle: &str, seconds: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            self.drain();
            if self.screen.text().contains(needle) {
                return true;
            }
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.drain();
        self.screen.text().contains(needle)
    }

    fn drain(&mut self) {
        let mut buffer = [0u8; 8192];
        loop {
            match self.master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => self.screen.feed(&String::from_utf8_lossy(&buffer[..count])),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn screen(&self) -> String {
        self.screen.text()
    }

    fn type_keys(&mut self, keys: &str) {
        self.master
            .write_all(keys.as_bytes())
            .expect("write a keystroke");
        self.master.flush().expect("flush");
    }

    /// Waits for the child to exit and returns its status.
    fn finish(mut self, seconds: u64) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.drain();
            match self.child.try_wait() {
                Ok(Some(status)) => return status.code().unwrap_or(-1),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    panic!(
                        "sweep did not exit within {seconds}s; the screen held:\n{}",
                        self.screen()
                    );
                }
                Err(error) => panic!("wait failed: {error}"),
            }
        }
    }
}

/// Just enough of a terminal to know what a person would be looking at.
///
/// Escape sequences are applied rather than stripped: cursor moves position the
/// next character, and the parts of the screen a frame does not touch keep what
/// an earlier frame put there. Colours, modes and titles are ignored, because no
/// assertion reads them.
struct Screen {
    rows: usize,
    cols: usize,
    cells: Vec<char>,
    row: usize,
    col: usize,
}

impl Screen {
    fn new(rows: usize, cols: usize) -> Screen {
        Screen {
            rows,
            cols,
            cells: vec![' '; rows * cols],
            row: 0,
            col: 0,
        }
    }

    fn feed(&mut self, text: &str) {
        let mut chars = text.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '\u{1b}' => self.escape(&mut chars),
                '\r' => self.col = 0,
                '\n' => {
                    self.row = (self.row + 1).min(self.rows - 1);
                    self.col = 0;
                }
                '\u{8}' => self.col = self.col.saturating_sub(1),
                '\t' => self.col = ((self.col / 8 + 1) * 8).min(self.cols - 1),
                other if !other.is_control() => self.put(other),
                _ => {}
            }
        }
    }

    fn put(&mut self, character: char) {
        if self.row < self.rows && self.col < self.cols {
            self.cells[self.row * self.cols + self.col] = character;
        }
        self.col += 1;
        if self.col >= self.cols {
            self.col = self.cols - 1;
        }
    }

    fn escape(&mut self, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
        match chars.next() {
            Some('[') => self.csi(chars),
            // OSC (window title) runs to BEL or ST; ignore its content.
            Some(']') => {
                for next in chars.by_ref() {
                    if next == '\u{7}' {
                        break;
                    }
                }
            }
            // Two-character escapes such as ESC ( B, and anything else unknown.
            Some(_) => {}
            None => {}
        }
    }

    fn csi(&mut self, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
        let mut numbers: Vec<usize> = Vec::new();
        let mut current = String::new();
        let final_byte = loop {
            match chars.next() {
                Some(next) if next.is_ascii_digit() => current.push(next),
                Some(';') => {
                    numbers.push(current.parse().unwrap_or(0));
                    current.clear();
                }
                Some(next) if ('\u{40}'..='\u{7e}').contains(&next) => {
                    numbers.push(current.parse().unwrap_or(0));
                    break next;
                }
                // Private-parameter introducers such as `?` belong to the
                // sequence, not to its arguments.
                Some(_) => {}
                None => return,
            }
        };
        let first = numbers.first().copied().unwrap_or(0);
        let second = numbers.get(1).copied().unwrap_or(0);
        match final_byte {
            // Cursor position: row;column, both one-based and zero meaning "1".
            'H' | 'f' => {
                self.row = first.saturating_sub(1).min(self.rows - 1);
                self.col = second.saturating_sub(1).min(self.cols - 1);
            }
            // Column, one-based.
            'G' => self.col = first.saturating_sub(1).min(self.cols - 1),
            // Row, one-based.
            'd' => self.row = first.saturating_sub(1).min(self.rows - 1),
            'A' => self.row = self.row.saturating_sub(first.max(1)),
            'B' => self.row = (self.row + first.max(1)).min(self.rows - 1),
            'C' => self.col = (self.col + first.max(1)).min(self.cols - 1),
            'D' => self.col = self.col.saturating_sub(first.max(1)),
            // Erase in display: 0 from the cursor, 2 everything, 3 scrollback.
            'J' => match first {
                0 => {
                    let from = self.row * self.cols + self.col;
                    for cell in &mut self.cells[from..] {
                        *cell = ' ';
                    }
                }
                2 | 3 => self.cells.iter_mut().for_each(|cell| *cell = ' '),
                _ => {}
            },
            // Erase in line: 0 to the end, 1 from the start, 2 the whole line.
            'K' => {
                let start = self.row * self.cols;
                match first {
                    0 => {
                        for cell in &mut self.cells[start + self.col..start + self.cols] {
                            *cell = ' ';
                        }
                    }
                    1 => {
                        for cell in &mut self.cells[start..start + self.col + 1] {
                            *cell = ' ';
                        }
                    }
                    2 => {
                        for cell in &mut self.cells[start..start + self.cols] {
                            *cell = ' ';
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn text(&self) -> String {
        let mut out = String::with_capacity(self.rows * (self.cols + 1));
        for row in 0..self.rows {
            let line: String = self.cells[row * self.cols..(row + 1) * self.cols]
                .iter()
                .collect();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }
}

fn open_pty() -> (libc::c_int, libc::c_int) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: both integers are valid out-parameters, and the name, termios and
    // winsize arguments are documented as optional.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());

    // A zero-sized terminal makes ratatui compute an empty area, so the window
    // is set before the child starts reading its size.
    let winsize = libc::winsize {
        ws_row: ROWS as u16,
        ws_col: COLS as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `slave` is the live descriptor `openpty` just made, and the
    // winsize pointer is valid for the duration of the call.
    let rc = unsafe { libc::ioctl(slave, libc::TIOCSWINSZ, &winsize) };
    assert_eq!(rc, 0, "TIOCSWINSZ failed");
    (master, slave)
}

fn dup(fd: libc::c_int) -> File {
    // SAFETY: `dup` returns a new descriptor for a live one, and the result is
    // owned by the returned `File`.
    let copy = unsafe { libc::dup(fd) };
    assert_ne!(copy, -1, "dup failed: {}", std::io::Error::last_os_error());
    // SAFETY: `copy` is a fresh descriptor we own.
    unsafe { File::from_raw_fd(copy) }
}

/// A home with no configuration, so the explorer under test never reads the
/// machine's own state, trash or logs.
struct Home {
    temp: tempfile::TempDir,
}

impl Home {
    fn new() -> Home {
        let temp = tempfile::tempdir().expect("tempdir");
        for name in ["data", "state", "config"] {
            std::fs::create_dir_all(temp.path().join(name)).expect("mkdir");
        }
        Home { temp }
    }

    fn root(&self) -> &Path {
        self.temp.path()
    }

    fn envs(&self) -> [(&'static str, PathBuf); 4] {
        [
            ("HOME", self.root().to_path_buf()),
            ("XDG_DATA_HOME", self.root().join("data")),
            ("XDG_STATE_HOME", self.root().join("state")),
            ("XDG_CONFIG_HOME", self.root().join("config")),
        ]
    }
}

/// A directory holding one file, which the explorer lists as its only row.
fn tree(home: &Home, name: &str, bytes: usize) -> PathBuf {
    let tree = home.root().join("tree");
    std::fs::create_dir_all(&tree).expect("mkdir");
    std::fs::write(tree.join(name), vec![b'x'; bytes]).expect("write");
    tree
}

#[test]
fn the_explorer_draws_a_screen_and_quits_on_q() {
    let home = Home::new();
    let tree = tree(&home, "notes.txt", 16);

    let mut session = Session::start(&[OsStr::new("analyze"), tree.as_os_str()], &home);
    assert!(
        session.wait_for("q quit", 20),
        "the footer never appeared; the screen held:\n{}",
        session.screen()
    );
    let screen = session.screen();
    assert!(
        screen.contains("tree"),
        "the title names the directory being explored: {screen}"
    );
    assert!(
        screen.contains("notes.txt"),
        "the entry is listed: {screen}"
    );

    session.type_keys("q");
    assert_eq!(session.finish(20), 0, "a clean quit exits 0");
}

#[test]
fn confirming_a_move_puts_the_entry_in_the_trash_with_its_record() {
    let home = Home::new();
    let tree = tree(&home, "payload.bin", 4096);
    let payload = tree.join("payload.bin");

    let mut session = Session::start(&[OsStr::new("analyze"), tree.as_os_str()], &home);
    assert!(
        session.wait_for("q quit", 20),
        "the list never appeared; the screen held:\n{}",
        session.screen()
    );

    // `d` asks, `y` answers. Nothing may move before the question is on screen.
    session.type_keys("d");
    assert!(
        session.wait_for("Move to the trash?", 20),
        "the confirmation never appeared; the screen held:\n{}",
        session.screen()
    );
    assert!(
        payload.exists(),
        "asking the question must not move anything yet"
    );

    session.type_keys("y");
    assert!(
        session.wait_for("moved to", 20),
        "the move was never confirmed; the screen held:\n{}",
        session.screen()
    );
    session.type_keys("q");
    assert_eq!(session.finish(20), 0, "the explorer exits 0 after a move");

    assert!(!payload.exists(), "the entry left the directory it was in");
    let trashed = home.root().join("data/Trash/files/payload.bin");
    assert_eq!(
        std::fs::read(&trashed).expect("the payload is in the trash"),
        vec![b'x'; 4096],
        "the same bytes, moved rather than deleted"
    );
    let record = std::fs::read_to_string(home.root().join("data/Trash/info/payload.bin.trashinfo"))
        .expect("the restore record exists");
    assert!(
        record.contains(&format!("Path={}", payload.display())),
        "the record names where the entry came from: {record}"
    );

    // The move is a logged action, like every other change sweep makes.
    let log = std::fs::read_to_string(home.root().join("state/sweep/operations.jsonl"))
        .expect("the operation log exists");
    let row = log
        .lines()
        .find(|line| line.contains("TRASHED"))
        .expect("a TRASHED row");
    assert!(
        row.contains("analyze") && row.contains("payload.bin"),
        "the row names the command and the path: {row}"
    );
}

#[test]
fn keeping_the_entry_leaves_it_alone() {
    let home = Home::new();
    let tree = tree(&home, "keep.txt", 16);
    let payload = tree.join("keep.txt");

    let mut session = Session::start(&[OsStr::new("analyze"), tree.as_os_str()], &home);
    assert!(
        session.wait_for("q quit", 20),
        "the list never appeared; the screen held:\n{}",
        session.screen()
    );

    session.type_keys("d");
    assert!(
        session.wait_for("Move to the trash?", 20),
        "the confirmation never appeared"
    );
    // Any key other than `y` keeps it, and the screen says so.
    session.type_keys("n");
    assert!(
        session.wait_for("kept", 20),
        "the explorer never acknowledged the refusal; the screen held:\n{}",
        session.screen()
    );
    session.type_keys("q");
    assert_eq!(session.finish(20), 0);

    assert!(payload.exists(), "a declined question moves nothing");
    assert!(
        !home.root().join("data/Trash/files/keep.txt").exists(),
        "and writes nothing into the trash"
    );
}

#[test]
fn a_bare_analyze_in_a_terminal_opens_the_explorer_over_the_home_it_was_given() {
    let home = Home::new();
    std::fs::write(home.root().join("marker.txt"), b"found me").expect("write");

    let mut session = Session::start(&[OsStr::new("analyze")], &home);
    assert!(
        session.wait_for("q quit", 20),
        "no terminal explorer; the screen held:\n{}",
        session.screen()
    );
    assert!(
        session.screen().contains("marker.txt"),
        "it explored the home it was given: {}",
        session.screen()
    );
    session.type_keys("q");
    assert_eq!(session.finish(20), 0);
}

#[test]
fn a_directory_holding_one_entry_is_one_item_in_the_confirmation() {
    let home = Home::new();
    let tree = home.root().join("tree");
    std::fs::create_dir_all(tree.join("only")).expect("mkdir");
    std::fs::write(tree.join("only/one.txt"), b"x").expect("write");

    let mut session = Session::start(&[OsStr::new("analyze"), tree.as_os_str()], &home);
    assert!(
        session.wait_for("q quit", 20),
        "the list never appeared; the screen held:\n{}",
        session.screen()
    );
    // The directory's size and item count arrive together from the measuring
    // thread, and the footer prints the count the dialog is about to repeat.
    // Waiting for it is waiting for the number, not guessing a duration.
    assert!(
        session.wait_for("1 item measured", 20),
        "the directory was never measured; the screen held:\n{}",
        session.screen()
    );
    // The header counts the entries on screen, which is also one.
    assert!(
        session.screen().contains("1 entry,"),
        "one entry is one entry in the header: {}",
        session.screen()
    );
    assert!(
        !session.screen().contains("1 entries"),
        "one entry is not 1 entries: {}",
        session.screen()
    );

    session.type_keys("d");
    assert!(
        session.wait_for("Move to the trash?", 20),
        "the confirmation never appeared; the screen held:\n{}",
        session.screen()
    );
    let screen = session.screen();
    assert!(
        screen.contains("1 item —"),
        "one entry is one item: {screen}"
    );
    assert!(
        !screen.contains("1 items"),
        "one entry is not one items: {screen}"
    );

    session.type_keys("n");
    assert!(session.wait_for("kept", 20), "no refusal was recorded");
    session.type_keys("q");
    assert_eq!(session.finish(20), 0);
}
