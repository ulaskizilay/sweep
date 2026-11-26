//! The terminal the explorer draws itself on.
//!
//! This module owns the terminal and the event loop, and nothing else: every
//! decision lives in [`super::app`]. The split is what makes the rendering
//! testable — a `TestBackend` measures a frame the same way a real terminal
//! shows it — and it keeps the destructive path in one readable place.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::Frame;
use sweep_core::oplog::{rfc3339, Action as LogAction, Oplog, Record};
use sweep_core::paths::Xdg;

use super::app::{Action, App, Mode};
use super::view::{self, Row};
use crate::format::{human_bytes, plural, plural_forms};
use crate::trash::Trash;
use crate::EXIT_UNSUPPORTED_ENVIRONMENT;

pub fn run(root: &Path, xdg: &Xdg, verbose: u8) -> ExitCode {
    let mut app = match App::open(root) {
        Ok(app) => app,
        Err(error) => {
            eprintln!("sweep analyze: cannot read {}: {error}", root.display());
            return ExitCode::from(EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };
    // A trash that cannot be created does not stop the explorer: reading a disk
    // is the main job, and deleting is one key. The refusal is reported when the
    // key is pressed, with the reason the trash could not be opened.
    let trash = Trash::open(xdg);
    if let Err(error) = &trash {
        app.report_error(format!("the trash is not available: {error}"));
    }

    let mut terminal = ratatui::init();
    let outcome = event_loop(&mut terminal, &mut app, xdg, &trash, verbose);
    // `init` installed a panic hook that restores the terminal; this is the
    // ordinary path out of it.
    ratatui::restore();
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sweep analyze: {error}");
            ExitCode::FAILURE
        }
    }
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    xdg: &Xdg,
    trash: &Result<Trash, std::io::Error>,
    verbose: u8,
) -> std::io::Result<()> {
    let session = format!("analyze-{}", now_unix());
    let mut oplog: Option<Oplog> = None;

    loop {
        app.tick();
        terminal.draw(|frame| draw(frame, app))?;

        if !event::poll(Duration::from_millis(80))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(());
        }
        match app.on_key(key.code) {
            Action::None => {}
            Action::Quit => return Ok(()),
            Action::Reload => app.reload(),
            Action::Trash(row) => {
                let Some(row) = row_for(app, &row) else {
                    app.report_error("that entry is no longer in this directory".to_string());
                    continue;
                };
                let trash = match trash {
                    Ok(trash) => trash,
                    Err(error) => {
                        app.report_error(format!("the trash is not available: {error}"));
                        continue;
                    }
                };
                match trash.send(&row.path, xdg) {
                    Ok(moved) => {
                        // One row per move, in the same log every sweep writes, so
                        // a restore is not the only record of what happened. The
                        // log is opened on the first move, because opening it
                        // creates a state directory and reading a disk is not a
                        // reason to write anything.
                        let log_error = if let Some(log) = oplog.as_mut() {
                            log.append(record(&session, &row, &moved));
                            None
                        } else {
                            match Oplog::open(&xdg.state_dir(), session.clone()) {
                                Ok(mut log) => {
                                    log.append(record(&session, &row, &moved));
                                    oplog = Some(log);
                                    None
                                }
                                Err(error) => Some(error.to_string()),
                            }
                        };
                        app.after_trash(&row.path, &moved.to);
                        if let Some(error) = log_error {
                            app.status.push_str(&format!(" (not logged: {error})"));
                        }
                    }
                    Err(refusal) => app.report_error(refusal.to_string()),
                }
            }
        }
        if verbose > 2 {
            tracing::debug!(frame = true, "drew a frame");
        }
    }
}

fn record<'a>(session: &'a str, row: &Row, moved: &crate::trash::Moved) -> Record<'a> {
    Record {
        ts: rfc3339(now_unix()),
        cmd: "analyze",
        session,
        action: LogAction::Trashed,
        rule: "analyze.manual",
        path: moved.from.display().to_string(),
        path_hex: encode_hex(&moved.from),
        bytes: row.bytes(),
        reason: None,
        detail: Some(format!("moved to {}", moved.to.display())),
    }
}

/// The row as it is on disk now, so a list that changed under the cursor does
/// not move something the user never saw.
fn row_for(app: &App, asked: &Row) -> Option<Row> {
    app.rows()
        .iter()
        .find(|row| row.path == asked.path)
        .cloned()
}

fn encode_hex(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if std::str::from_utf8(bytes).is_ok() {
        return None;
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Some(out)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

// ------------------------------------------------------------------ frames ---

pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .split(frame.area());

    draw_header(frame, rows[0], app);
    draw_rows(frame, rows[1], app);
    draw_footer(frame, rows[2], app);

    match app.mode {
        Mode::Confirm => draw_confirm(frame, app),
        Mode::Help => draw_help(frame),
        Mode::Browse | Mode::Filter => {}
    }
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let sort = format!(
        "sort: {}{}",
        app.sort.label(),
        if app.reverse { " ↓" } else { " ↑" }
    );
    let count = app.visible().len();
    let filter = if app.filter.is_empty() {
        String::new()
    } else {
        format!("  filter: {}", app.filter)
    };
    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", app.cwd.display()),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  {}, {}  {sort}{filter}",
            plural_forms(count as u64, "entry", "entries"),
            human_bytes(app.total_bytes())
        )),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_rows(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let height = area.height as usize;
    // Keep the selection on screen without a scroll-offset field: the window is
    // derived from the selection, which is all a list of this size needs.
    let start = app.selected().saturating_sub(height.saturating_sub(1));
    let mut lines: Vec<Line<'_>> = Vec::with_capacity(height);
    for (offset, index) in app.visible().iter().enumerate().skip(start).take(height) {
        let row = &app.rows()[*index];
        let selected = offset == app.selected();
        let style = if selected {
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let size = size_cell(row);
        let name = if row.is_dir {
            format!("{}/", row.name)
        } else {
            row.name.clone()
        };
        lines.push(
            Line::from(vec![
                Span::styled(format!(" {size:>10}  "), style),
                Span::styled(
                    format!("{:>9}  ", view::age_text(row.age_days())),
                    style.fg(if selected { Color::White } else { Color::Gray }),
                ),
                Span::styled(name, style),
            ])
            .style(style),
        );
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn size_cell(row: &Row) -> String {
    if row.is_link() {
        return "link".to_string();
    }
    match row.subtree {
        Some(measured) if measured.partial => format!("≥{}", human_bytes(measured.bytes)),
        Some(measured) => human_bytes(measured.bytes),
        None if row.is_dir => "…".to_string(),
        None => human_bytes(row.own_bytes),
    }
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let status = if let Some(error) = &app.error {
        Line::from(Span::styled(
            format!(" {error}"),
            Style::default().fg(Color::Red),
        ))
    } else if app.mode == Mode::Filter {
        Line::from(format!(" filter: {}_", app.draft()))
    } else if !app.status.is_empty() {
        Line::from(format!(" {}", app.status))
    } else {
        let items: u64 = app.rows().iter().filter_map(Row::items).sum();
        Line::from(format!(" {} measured", plural(items as usize, "item")))
    };
    let keys = Line::from(Span::styled(
        " ↑↓ move  ⏎ open  ⌫ up  s sort  S reverse  / filter  d trash  r rescan  ? help  q quit",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(Paragraph::new(vec![status, keys]), area);
}

fn draw_confirm(frame: &mut Frame<'_>, app: &App) {
    let Some(row) = app.pending() else {
        return;
    };
    let area = centred(frame.area(), 70, 9);
    frame.render_widget(Clear, area);
    let size = if row.is_link() {
        "a symbolic link; its target is not touched".to_string()
    } else if row.is_dir {
        format!(
            "{}, {}",
            human_bytes(row.bytes()),
            plural(row.items().unwrap_or(0) as usize, "item")
        )
    } else {
        human_bytes(row.bytes())
    };
    let body = vec![
        Line::from(Span::styled(
            "Move to the trash?",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(row.path.display().to_string()),
        Line::from(format!(
            "{size} — last modified {}",
            view::age_text(row.age_days())
        )),
        Line::from(""),
        Line::from(Span::styled(
            "y  move it      any other key  keep it",
            Style::default().fg(Color::Yellow),
        )),
    ];
    frame.render_widget(
        Paragraph::new(body)
            .block(Block::bordered().title(" confirm "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_help(frame: &mut Frame<'_>) {
    let area = centred(frame.area(), 60, 18);
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from(Span::styled(
            "sweep analyze — keys",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("↑ ↓  j k      move the selection"),
        Line::from("⏎ l →         open a directory"),
        Line::from("⌫ h ←         go up, never above the start"),
        Line::from("g G           first / last row"),
        Line::from("s             sort by size, name, modified"),
        Line::from("S             reverse the order"),
        Line::from("/             filter by name"),
        Line::from("d             move the selection to the trash"),
        Line::from("r             rescan this directory"),
        Line::from("?             this help"),
        Line::from("q esc         quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Nothing is deleted. A trashed entry can be restored from your desktop.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(" help "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn centred(area: Rect, percent_x: u16, height: u16) -> Rect {
    let width = area.width * percent_x / 100;
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join("cache")).expect("mkdir");
        std::fs::write(temp.path().join("cache/blob"), vec![b'x'; 4096]).expect("write");
        std::fs::write(temp.path().join("notes.txt"), b"notes").expect("write");
        std::fs::create_dir_all(temp.path().join("empty")).expect("mkdir");
        temp
    }

    fn screen(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal.draw(|frame| draw(frame, app)).expect("draw");
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn the_header_names_the_directory_and_the_sort() {
        let temp = fixture();
        let app = App::open(temp.path()).expect("open");
        let text = screen(&app, 100, 20);
        assert!(text.contains(&temp.path().display().to_string()), "{text}");
        assert!(text.contains("sort: size"), "{text}");
        assert!(text.contains("notes.txt"), "{text}");
        assert!(text.contains("cache/"), "directories are marked: {text}");
    }

    #[test]
    fn an_unmeasured_directory_is_not_drawn_as_zero() {
        let temp = fixture();
        let app = App::open(temp.path()).expect("open");
        let text = screen(&app, 100, 20);
        assert!(
            text.contains('…') || text.contains('≥'),
            "a directory whose walk has not finished has no number yet: {text}"
        );
    }

    #[test]
    fn the_confirmation_names_the_entry_and_the_keys() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        app.on_key(KeyCode::Char('d'));
        let text = screen(&app, 100, 24);
        assert!(text.contains("Move to the trash?"), "{text}");
        assert!(text.contains("y  move it"), "{text}");
        assert!(
            text.contains(&app.pending().expect("pending").path.display().to_string()),
            "{text}"
        );
    }

    #[test]
    fn the_footer_lists_the_keys_and_the_filter_closes_over_the_list() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        app.on_key(KeyCode::Char('/'));
        for character in "not".chars() {
            app.on_key(KeyCode::Char(character));
        }
        let text = screen(&app, 100, 20);
        assert!(text.contains("filter: not"), "{text}");
        assert!(text.contains("notes.txt"), "{text}");
        assert!(
            !text.contains("cache/"),
            "the filter hides the rest: {text}"
        );
    }

    #[test]
    fn help_is_one_screen_and_says_nothing_is_deleted() {
        let temp = fixture();
        let mut app = App::open(temp.path()).expect("open");
        app.on_key(KeyCode::Char('?'));
        let text = screen(&app, 100, 24);
        assert!(text.contains("sweep analyze — keys"), "{text}");
        assert!(text.contains("Nothing is deleted"), "{text}");
    }
}
