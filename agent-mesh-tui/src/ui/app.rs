//! The application component: the Board view over the latest model.
//!
//! A component only describes: keys move the selection, nothing a key does can
//! change what the model says (the model is replaced only by the feed).

use crate::model::{Model, Open};
use newtui::{Component, Flow, Key, Row, View};

/// Lines a PageUp / PageDown moves.
const PAGE: usize = 10;

/// The Board over a model.
pub struct App {
    model: Model,
    selected: usize,
}

impl App {
    /// A view over `model`, first member selected.
    #[must_use]
    pub fn new(model: Model) -> Self {
        Self { model, selected: 0 }
    }

    /// Replace the model with a newer fold of the log. The selection stays on
    /// its row number, clamped to the roster.
    pub fn set_model(&mut self, model: Model) {
        self.model = model;
        self.selected = self
            .selected
            .min(self.model.members.len().saturating_sub(1));
    }

    /// The model this view shows.
    #[must_use]
    pub fn model(&self) -> &Model {
        &self.model
    }

    /// The selected row, if the roster is not empty.
    #[must_use]
    pub fn selected(&self) -> Option<usize> {
        (!self.model.members.is_empty()).then_some(self.selected)
    }
}

/// `1 job, 2 lanes`, or `-` when nothing is open.
pub(crate) fn open_text(o: Open) -> String {
    let plural = |n: usize, one: &str| format!("{n} {one}{}", if n == 1 { "" } else { "s" });
    let parts: Vec<String> = [(o.jobs, "job"), (o.lanes, "lane"), (o.asks, "ask")]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, w)| plural(n, w))
        .collect();
    if parts.is_empty() {
        "-".to_owned()
    } else {
        parts.join(", ")
    }
}

/// `3 events`, or `never` for a member that has written nothing.
pub(crate) fn quiet_text(quiet_for: Option<u64>) -> String {
    match quiet_for {
        None => "never".to_owned(),
        Some(1) => "1 event".to_owned(),
        Some(n) => format!("{n} events"),
    }
}

impl Component for App {
    fn handle(&mut self, key: Key) -> Flow {
        let last = self.model.members.len().saturating_sub(1);
        match key {
            Key::Up => self.selected = self.selected.saturating_sub(1),
            Key::Down => self.selected = (self.selected + 1).min(last),
            Key::Home => self.selected = 0,
            Key::End => self.selected = last,
            Key::PageUp => self.selected = self.selected.saturating_sub(PAGE),
            Key::PageDown => self.selected = (self.selected + PAGE).min(last),
            Key::Esc | Key::Char('q') | Key::Ctrl('c') => return Flow::Close(false),
            _ => {}
        }
        Flow::Stay
    }

    fn view(&self) -> View {
        let mut view = View::titled("Board").footer(
            "↑↓ select · q quit · refused events (!) are not on the stream: not shown in v1",
        );
        for (i, m) in self.model.members.iter().enumerate() {
            let row = Row::new(
                m.name.clone(),
                format!("{} · {} · {}", m.role, m.session, m.says),
            )
            .note(format!(
                "open: {} · quiet: {}",
                open_text(m.open),
                quiet_text(m.quiet_for)
            ));
            view = view.row(if self.selected() == Some(i) {
                row.selected()
            } else {
                row
            });
        }
        view
    }
}
