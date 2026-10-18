//! Drawing: the header and the Board, as plain text lines on a ratatui frame.
//! The selection is a `▸` marker, not only a colour, so a text snapshot shows it.

use super::app::{open_text, quiet_text};
use super::App;
use crate::model::{Header, Link};
use newtui::Component;
use ratatui::backend::TestBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};

const MEMBER: usize = 10;
const ROLE: usize = 9;
const SESSION: usize = 10;
const SAYS: usize = 14;
const OPEN: usize = 22;

/// The two header lines every view shows.
#[must_use]
pub fn header_lines(h: &Header) -> [String; 2] {
    let status = match &h.link {
        Link::Live => "live".to_owned(),
        Link::Stale { since } => format!("stale since #{since}"),
        Link::Failed(why) => why.clone(),
    };
    let mark = if matches!(h.link, Link::Failed(_)) {
        "✗"
    } else {
        "✓"
    };
    [
        format!(
            "amesh-tui · flock {} · id {} · {} members",
            h.flock, h.short_id, h.members
        ),
        format!("log {mark} {} · epoch {} · {status}", h.verified, h.epoch),
    ]
}

fn cell(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        format!("{s:<width$}")
    } else {
        let cut: String = s.chars().take(width.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// The Board table lines (header row, then one per member) for `app`.
#[must_use]
pub fn board_lines(app: &App) -> Vec<String> {
    let mut out = vec![format!(
        "  {} {} {} {} {} QUIET",
        cell("MEMBER", MEMBER),
        cell("ROLE", ROLE),
        cell("SESSION", SESSION),
        cell("SELF", SAYS),
        cell("OPEN", OPEN),
    )];
    for (i, m) in app.model().members.iter().enumerate() {
        let marker = if app.selected() == Some(i) {
            "▸"
        } else {
            " "
        };
        out.push(format!(
            "{marker} {} {} {} {} {} {}",
            cell(&m.name, MEMBER),
            cell(&m.role, ROLE),
            cell(&m.session, SESSION),
            cell(&m.says, SAYS),
            cell(&open_text(m.open), OPEN),
            quiet_text(m.quiet_for),
        ));
    }
    out
}

/// Draw the whole screen.
pub fn draw(f: &mut Frame<'_>, app: &App) {
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(area);
    let head = header_lines(&app.model().header);
    f.render_widget(
        Paragraph::new(
            head.iter()
                .map(|l| Line::from(l.as_str()))
                .collect::<Vec<_>>(),
        ),
        rows[0],
    );
    let selected = app.selected();
    let lines: Vec<Line<'_>> = board_lines(app)
        .into_iter()
        .enumerate()
        .map(|(i, l)| {
            // line 0 is the column header; member i is line i + 1
            if i > 0 && selected == Some(i - 1) {
                Line::styled(l, Style::default().add_modifier(Modifier::REVERSED))
            } else {
                Line::from(l)
            }
        })
        .collect();
    f.render_widget(Paragraph::new(lines), rows[1]);
    f.render_widget(
        Paragraph::new(app.view().footer),
        Rect {
            height: 1,
            ..rows[2]
        },
    );
}

/// The screen as text, `width` x `height`: what `--once` prints and what the
/// snapshot tests compare. Trailing blanks are trimmed from each line.
///
/// # Panics
/// Never in practice: a test backend cannot fail to draw.
#[must_use]
pub fn to_text(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    terminal.draw(|f| draw(f, app)).expect("draw");
    let buffer = terminal.backend().buffer();
    let mut text = String::new();
    for y in 0..height {
        let line: String = (0..width)
            .map(|x| buffer[(x, y)].symbol().to_owned())
            .collect();
        text.push_str(line.trim_end());
        text.push('\n');
    }
    text
}
