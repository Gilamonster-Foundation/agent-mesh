//! The application component: tabs over the latest model.
//!
//! A component only describes: keys move selections, filters and tabs, and
//! nothing a key does can change what the model says (the model is replaced
//! only by the feed).

use super::board::{window, BoardState, PAGE};
use super::lane::LaneState;
use super::stream::{cycle, Filters, StreamState};
use crate::drift::Drift;
use crate::events::EventRow;
use crate::model::{Model, Open};
use agent_mesh_flock::FileRef;
use newtui::{Component, Flow, Key, Row, View};

/// The views, left to right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Who is on the roster and what is open against them.
    Board,
    /// Every admitted event, with a raw view of each.
    Stream,
    /// Each lane's attempts, reviews and the files its events cite.
    Lane,
}

impl Tab {
    /// Tab names in order, for the tab bar.
    pub const ALL: [(Self, &'static str); 3] = [
        (Self::Board, "Board"),
        (Self::Stream, "Stream"),
        (Self::Lane, "Lane"),
    ];

    fn next(self) -> Self {
        match self {
            Self::Board => Self::Stream,
            Self::Stream => Self::Lane,
            Self::Lane => Self::Board,
        }
    }

    fn prev(self) -> Self {
        match self {
            Self::Board => Self::Lane,
            Self::Stream => Self::Board,
            Self::Lane => Self::Stream,
        }
    }
}

/// The tabs over a model.
pub struct App {
    model: Model,
    tab: Tab,
    board: BoardState,
    stream: StreamState,
    lane: LaneState,
    drift: Drift,
}

impl App {
    /// Board first; the Stream follows the end of the log.
    #[must_use]
    pub fn new(model: Model) -> Self {
        let mut app = Self {
            model,
            tab: Tab::Board,
            board: BoardState::default(),
            stream: StreamState::new(),
            lane: LaneState::default(),
            drift: Drift::new(),
        };
        app.stream.settle(&app.model);
        app
    }

    /// Replace the model with a newer fold of the log. Selections stay on
    /// their row, clamped; a following Stream moves to the newest event.
    pub fn set_model(&mut self, model: Model) {
        self.model = model;
        self.board.selected = self
            .board
            .selected
            .min(self.model.members.len().saturating_sub(1));
        self.stream.settle(&self.model);
        self.lane.selected = self
            .lane
            .selected
            .min(self.model.lanes.len().saturating_sub(1));
    }

    /// Replace what is known about the cited files (computed off the UI
    /// thread by [`crate::drift`]; a key never changes it).
    pub fn set_drift(&mut self, drift: Drift) {
        self.drift = drift;
    }

    /// What is known about the cited files.
    #[must_use]
    pub fn drift(&self) -> &Drift {
        &self.drift
    }

    /// Every distinct file any lane cites, first cited first.
    #[must_use]
    pub fn cited_files(&self) -> Vec<FileRef> {
        let mut out: Vec<FileRef> = vec![];
        for l in &self.model.lanes {
            for f in &l.files {
                if !out.contains(f) {
                    out.push(f.clone());
                }
            }
        }
        out
    }

    /// Whether the reader asked to check the files again (and forget the ask).
    pub fn take_recheck(&mut self) -> bool {
        std::mem::take(&mut self.lane.recheck)
    }

    /// The selected lane, if there are any.
    #[must_use]
    pub fn lane_selected(&self) -> Option<usize> {
        (!self.model.lanes.is_empty()).then_some(self.lane.selected)
    }

    /// The first Lane row to draw when `visible` rows fit.
    #[must_use]
    pub fn lane_viewport(&self, visible: usize) -> usize {
        window(
            &self.lane.offset,
            self.lane.selected,
            self.model.lanes.len(),
            visible,
        )
    }

    fn lane_key(&mut self, key: Key) {
        let last = self.model.lanes.len().saturating_sub(1);
        let l = &mut self.lane;
        match key {
            Key::Up => l.selected = l.selected.saturating_sub(1),
            Key::Down => l.selected = (l.selected + 1).min(last),
            Key::Home => l.selected = 0,
            Key::End => l.selected = last,
            Key::PageUp => l.selected = l.selected.saturating_sub(PAGE),
            Key::PageDown => l.selected = (l.selected + PAGE).min(last),
            Key::Char('r') => l.recheck = true,
            _ => {}
        }
    }

    /// The model this view shows.
    #[must_use]
    pub fn model(&self) -> &Model {
        &self.model
    }

    /// The tab showing.
    #[must_use]
    pub fn tab(&self) -> Tab {
        self.tab
    }

    /// The first Board row to draw when `visible` rows fit (see
    /// [`window`](super::board::window)).
    #[must_use]
    pub fn viewport(&self, visible: usize) -> usize {
        window(
            &self.board.offset,
            self.board.selected,
            self.model.members.len(),
            visible,
        )
    }

    /// The selected Board row, if the roster is not empty.
    #[must_use]
    pub fn selected(&self) -> Option<usize> {
        (!self.model.members.is_empty()).then_some(self.board.selected)
    }

    // --- the Stream ---

    /// The events the Stream shows (positions into the model's events).
    #[must_use]
    pub fn stream_rows(&self) -> Vec<usize> {
        self.stream.rows(&self.model)
    }

    /// The selected event's position, if the Stream shows any.
    #[must_use]
    pub fn stream_selected(&self) -> Option<usize> {
        self.stream_rows()
            .contains(&self.stream.sel)
            .then_some(self.stream.sel)
    }

    /// The first Stream row to draw when `visible` rows fit.
    #[must_use]
    pub fn stream_viewport(&self, visible: usize) -> usize {
        let rows = self.stream_rows();
        let at = rows.iter().position(|r| *r == self.stream.sel).unwrap_or(0);
        window(&self.stream.offset, at, rows.len(), visible)
    }

    /// The filters in force.
    #[must_use]
    pub fn filters(&self) -> &Filters {
        &self.stream.filters
    }

    /// Whether the Stream follows the newest event.
    #[must_use]
    pub fn following(&self) -> bool {
        self.stream.follow
    }

    /// The event the raw panel shows, when it is open.
    #[must_use]
    pub fn raw(&self) -> Option<&EventRow> {
        self.stream
            .panel
            .then(|| self.model.events.get(self.stream.sel))
            .flatten()
    }

    fn board_key(&mut self, key: Key) {
        let last = self.model.members.len().saturating_sub(1);
        let b = &mut self.board;
        match key {
            Key::Up => b.selected = b.selected.saturating_sub(1),
            Key::Down => b.selected = (b.selected + 1).min(last),
            Key::Home => b.selected = 0,
            Key::End => b.selected = last,
            Key::PageUp => b.selected = b.selected.saturating_sub(PAGE),
            Key::PageDown => b.selected = (b.selected + PAGE).min(last),
            _ => {}
        }
    }

    /// Move the Stream selection `by` rows through what is shown (clamped).
    fn stream_move(&mut self, by: isize) {
        let rows = self.stream_rows();
        if rows.is_empty() {
            return;
        }
        let at = rows.iter().position(|r| *r == self.stream.sel).unwrap_or(0);
        let to = at.saturating_add_signed(by).min(rows.len() - 1);
        self.stream.sel = rows[to];
    }

    fn stream_key(&mut self, key: Key) {
        if self.stream.panel {
            return self.panel_key(key);
        }
        let end = self.stream_rows().last().copied().unwrap_or(0);
        match key {
            Key::Up => {
                self.stream.follow = false;
                self.stream_move(-1);
            }
            Key::Down => self.stream_move(1),
            Key::PageUp => {
                self.stream.follow = false;
                self.stream_move(-(PAGE as isize));
            }
            Key::PageDown => self.stream_move(PAGE as isize),
            Key::Home => {
                self.stream.follow = false;
                self.stream_move(isize::MIN / 2);
            }
            Key::End => {
                self.stream.follow = true;
                self.stream.sel = end;
            }
            Key::Char('f') => {
                self.stream.follow = !self.stream.follow;
                self.stream.settle(&self.model);
            }
            Key::Enter => {
                if self.stream_selected().is_some() {
                    self.stream.panel = true;
                    self.stream.history.clear();
                }
            }
            Key::Char('k') => {
                let kinds = self.model.events.iter().map(|e| e.kind.clone()).collect();
                self.stream.filters.kind = cycle(&self.stream.filters.kind, kinds);
                self.stream.settle(&self.model);
            }
            Key::Char('l') => {
                let lanes = self
                    .model
                    .events
                    .iter()
                    .filter_map(|e| e.lane.clone())
                    .collect();
                self.stream.filters.lane = cycle(&self.stream.filters.lane, lanes);
                self.stream.settle(&self.model);
            }
            Key::Char('m') => {
                let who = self.model.events.iter().map(|e| e.member.clone()).collect();
                self.stream.filters.member = cycle(&self.stream.filters.member, who);
                self.stream.settle(&self.model);
            }
            Key::Char('c') => {
                self.stream.filters = Filters::default();
                self.stream.settle(&self.model);
            }
            _ => {}
        }
    }

    fn panel_key(&mut self, key: Key) {
        match key {
            Key::Esc => self.stream.panel = false,
            Key::Up => {
                self.stream.follow = false;
                self.stream.history.clear();
                self.stream_move(-1);
            }
            Key::Down => {
                self.stream.history.clear();
                self.stream_move(1);
            }
            Key::Backspace => {
                if let Some(back) = self.stream.history.pop() {
                    self.stream.sel = back;
                }
            }
            Key::Char(c @ '1'..='9') => {
                let n = usize::from(c as u8 - b'1');
                let Some(to) = self
                    .model
                    .events
                    .get(self.stream.sel)
                    .and_then(|e| e.parents.get(n))
                    .and_then(|p| p.row)
                else {
                    return;
                };
                self.stream.follow = false;
                self.stream.push_history();
                self.stream.sel = to;
                // a parent the filters hide is still wanted: show everything
                if !self.stream_rows().contains(&to) {
                    self.stream.filters = Filters::default();
                }
            }
            _ => {}
        }
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

/// Footer for the Board.
pub(crate) const BOARD_FOOTER: &str =
    "↑↓ select · Tab next view · q quit · refused events (!) are not on the stream: not shown in v1";

/// Footer for the Lane view.
pub(crate) const LANE_FOOTER: &str =
    "↑↓ select · r check the files again · Tab next view · q quit · files are read, never written";

impl Component for App {
    fn handle(&mut self, key: Key) -> Flow {
        match key {
            Key::Char('q') | Key::Ctrl('c') => return Flow::Close(false),
            Key::Esc if !(self.tab == Tab::Stream && self.stream.panel) => {
                return Flow::Close(false)
            }
            Key::Tab => self.tab = self.tab.next(),
            Key::BackTab => self.tab = self.tab.prev(),
            Key::Char('1') if !(self.tab == Tab::Stream && self.stream.panel) => {
                self.tab = Tab::Board;
            }
            Key::Char('2') if !(self.tab == Tab::Stream && self.stream.panel) => {
                self.tab = Tab::Stream;
            }
            Key::Char('3') if !(self.tab == Tab::Stream && self.stream.panel) => {
                self.tab = Tab::Lane;
            }
            k => match self.tab {
                Tab::Board => self.board_key(k),
                Tab::Stream => self.stream_key(k),
                Tab::Lane => self.lane_key(k),
            },
        }
        Flow::Stay
    }

    fn view(&self) -> View {
        match self.tab {
            Tab::Board => self.board_view(),
            Tab::Stream => self.stream_view(),
            Tab::Lane => self.lane_view(),
        }
    }
}

impl App {
    fn board_view(&self) -> View {
        let mut view = View::titled("Board").footer(BOARD_FOOTER);
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

    fn lane_view(&self) -> View {
        let mut view = View::titled("Lane").footer(LANE_FOOTER);
        for (i, l) in self.model.lanes.iter().enumerate() {
            let row = Row::new(l.lane.clone(), l.latest.label.clone());
            view = view.row(if self.lane_selected() == Some(i) {
                row.selected()
            } else {
                row
            });
        }
        view
    }

    fn stream_view(&self) -> View {
        let mut view = View::titled("Stream").footer(if self.stream.panel {
            "1-9 jump to a parent · Backspace back · ↑↓ neighbours · Esc close"
        } else {
            "↑↓ select · Enter raw · f follow · k/l/m filter kind/lane/member · c clear"
        });
        if let Some(e) = self.raw() {
            // the cursor is on the event being read
            view = view.row(
                Row::new(format!("#{}", e.index), e.id.clone())
                    .note(e.verified.clone())
                    .selected(),
            );
            for (i, p) in e.parents.iter().enumerate() {
                view = view.row(Row::new(format!("{}", i + 1), p.id.clone()).note(p.role.clone()));
            }
            return view;
        }
        let selected = self.stream_selected();
        for i in self.stream_rows() {
            let e = &self.model.events[i];
            let row = Row::new(format!("#{}", e.index), format!("{} {}", e.kind, e.member))
                .note(e.summary.clone());
            view = view.row(if selected == Some(i) {
                row.selected()
            } else {
                row
            });
        }
        view
    }
}
