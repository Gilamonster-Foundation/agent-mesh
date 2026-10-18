//! Drawing: the header, the tab bar and the views, as plain text lines on a ratatui frame.
//! The selection is a `▸` marker, not only a colour, so a text snapshot shows it.

use super::app::{open_text, quiet_text};
use super::{App, Tab};
use crate::model::{Header, Link};
use newtui::Component;
use ratatui::backend::TestBackend;
use ratatui::layout::{Constraint, Layout};
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
        Link::Unsaved(why) => format!("⚠ {why}; showing the last saved state"),
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

/// The Board table: the column header, then the members from `offset` that
/// fit in `visible` rows.
#[must_use]
pub fn board_lines(app: &App, offset: usize, visible: usize) -> Vec<String> {
    let mut out = vec![format!(
        "  {} {} {} {} {} QUIET",
        cell("MEMBER", MEMBER),
        cell("ROLE", ROLE),
        cell("SESSION", SESSION),
        cell("SELF", SAYS),
        cell("OPEN", OPEN),
    )];
    for (i, m) in app
        .model()
        .members
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible)
    {
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

/// The tab bar: the showing tab in brackets.
#[must_use]
pub fn tab_line(app: &App) -> String {
    Tab::ALL
        .iter()
        .map(|(t, name)| {
            if *t == app.tab() {
                format!("[{name}]")
            } else {
                format!(" {name} ")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The Stream list: a column header, then events from `offset` that fit.
#[must_use]
pub fn stream_lines(app: &App, offset: usize, visible: usize) -> Vec<String> {
    let mut out = vec![format!(
        "  {:>5} {} {} {} SUMMARY",
        "#",
        cell("KIND", 13),
        cell("MEMBER", 8),
        cell("LANE", 8),
    )];
    let selected = app.stream_selected();
    for i in app.stream_rows().into_iter().skip(offset).take(visible) {
        let e = &app.model().events[i];
        let marker = if selected == Some(i) { "▸" } else { " " };
        out.push(format!(
            "{marker} {:>5} {} {} {} {}{}",
            e.index,
            cell(&e.kind, 13),
            cell(&e.member, 8),
            cell(e.lane.as_deref().unwrap_or("-"), 8),
            e.summary,
            if e.conflict { " [conflict]" } else { "" },
        ));
    }
    out
}

/// The raw view of one event: everything the verified log holds about it.
#[must_use]
pub fn raw_lines(app: &App) -> Vec<String> {
    let Some(e) = app.raw() else {
        return vec![];
    };
    let events = &app.model().events;
    let mut out = vec![
        format!("event #{}  {}", e.index, e.id),
        e.verified.clone(),
        format!("kind {} · signed by {}", e.kind, e.signer),
        format!("lane {} · at {}", e.lane.as_deref().unwrap_or("-"), e.at),
        "parents:".to_owned(),
    ];
    if e.parents.is_empty() {
        out.push("  (none)".to_owned());
    }
    for (i, p) in e.parents.iter().enumerate() {
        let what = p.row.map_or_else(
            || "not in this log".to_owned(),
            |r| format!("#{} {}", events[r].index, events[r].kind),
        );
        out.push(format!("  {} {:<6} → {what}  {}", i + 1, p.role, p.id));
    }
    for f in &e.files {
        out.push(format!("file {f}"));
    }
    out.push("body:".to_owned());
    out.extend(e.body.iter().map(|l| format!("  {l}")));
    out
}

fn stream_footer(app: &App, visible: usize, total: usize, offset: usize) -> [String; 2] {
    let f = app.filters();
    let shown = app.stream_rows().len();
    let of = |v: &Option<String>| v.clone().unwrap_or_else(|| "all".into());
    let range = if shown > visible {
        format!(" · rows {}-{} ", offset + 1, (offset + visible).min(shown))
    } else {
        " · ".to_owned()
    };
    [
        format!(
            "kind {} · lane {} · member {} · follow {}{}{shown} of {total} events",
            of(&f.kind),
            of(&f.lane),
            of(&f.member),
            if app.following() { "on" } else { "off" },
            range,
        ),
        app.view().footer,
    ]
}

/// Draw the whole screen: the header, the tab bar and the footer stay put;
/// the rows scroll to keep the selection in view.
pub fn draw(f: &mut Frame<'_>, app: &App) {
    let area = f.area();
    let stream = app.tab() == Tab::Stream;
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(if stream { 2 } else { 1 }),
    ])
    .split(area);
    let mut head: Vec<String> = header_lines(&app.model().header).to_vec();
    head.push(tab_line(app));
    f.render_widget(
        Paragraph::new(
            head.iter()
                .map(|l| Line::from(l.as_str()))
                .collect::<Vec<_>>(),
        ),
        rows[0],
    );
    // one line of the body area is the column header
    let visible = usize::from(rows[1].height).saturating_sub(1);
    let footer: Vec<String>;
    let body: Vec<Line<'_>>;
    match app.tab() {
        Tab::Board => {
            let offset = app.viewport(visible);
            let total = app.model().members.len();
            let selected = app.selected();
            body = board_lines(app, offset, visible)
                .into_iter()
                .enumerate()
                .map(|(i, l)| {
                    // line 0 is the column header; member offset + i - 1 follows
                    if i > 0 && selected == Some(offset + i - 1) {
                        Line::styled(l, Style::default().add_modifier(Modifier::REVERSED))
                    } else {
                        Line::from(l)
                    }
                })
                .collect();
            let mut text = app.view().footer;
            if total > visible {
                let last = (offset + visible).min(total);
                text = format!("rows {}-{last} of {total} · {text}", offset + 1);
            }
            footer = vec![text];
        }
        Tab::Stream if app.raw().is_some() => {
            let height = usize::from(rows[1].height);
            let mut lines = raw_lines(app);
            if lines.len() > height {
                lines.truncate(height.saturating_sub(1));
                lines.push("  … (clipped to the screen)".to_owned());
            }
            body = lines.into_iter().map(Line::from).collect();
            footer = vec![String::new(), app.view().footer];
        }
        Tab::Stream => {
            let offset = app.stream_viewport(visible);
            let selected = app.stream_selected();
            let rows_shown = app.stream_rows();
            body = stream_lines(app, offset, visible)
                .into_iter()
                .enumerate()
                .map(|(i, l)| {
                    // line 0 is the column header; event offset + i - 1 follows
                    let row = i
                        .checked_sub(1)
                        .and_then(|n| rows_shown.get(offset + n).copied());
                    if row.is_some() && row == selected {
                        Line::styled(l, Style::default().add_modifier(Modifier::REVERSED))
                    } else {
                        Line::from(l)
                    }
                })
                .collect();
            footer = stream_footer(app, visible, app.model().events.len(), offset).to_vec();
        }
    }
    f.render_widget(Paragraph::new(body), rows[1]);
    f.render_widget(
        Paragraph::new(
            footer
                .iter()
                .map(|l| Line::from(l.as_str()))
                .collect::<Vec<_>>(),
        ),
        rows[2],
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
