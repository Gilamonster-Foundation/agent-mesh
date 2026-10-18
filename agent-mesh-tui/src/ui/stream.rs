//! The Stream tab: every admitted event, filters, follow mode and the raw
//! event panel. State only; the model is never touched.

use crate::events::EventRow;
use crate::model::Model;
use std::cell::Cell;

/// How many panel jumps `Backspace` can undo.
const HISTORY: usize = 8;

/// Which events the list shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filters {
    /// Only this kind.
    pub kind: Option<String>,
    /// Only this lane.
    pub lane: Option<String>,
    /// Only this signer.
    pub member: Option<String>,
}

impl Filters {
    fn admits(&self, e: &EventRow) -> bool {
        self.kind.as_ref().is_none_or(|k| *k == e.kind)
            && self
                .lane
                .as_ref()
                .is_none_or(|l| e.lane.as_ref() == Some(l))
            && self.member.as_ref().is_none_or(|m| *m == e.member)
    }

    /// Whether any filter is set.
    #[must_use]
    pub fn any(&self) -> bool {
        self.kind.is_some() || self.lane.is_some() || self.member.is_some()
    }
}

pub(crate) struct StreamState {
    pub filters: Filters,
    /// The selected event: its position in the model's event list.
    pub sel: usize,
    pub follow: bool,
    pub panel: bool,
    /// Where `Backspace` goes back to, most recent last.
    pub history: Vec<usize>,
    pub offset: Cell<usize>,
}

impl StreamState {
    pub fn new() -> Self {
        Self {
            filters: Filters::default(),
            sel: 0,
            follow: true,
            panel: false,
            history: vec![],
            offset: Cell::new(0),
        }
    }

    /// Positions (into the model's events) the filters let through.
    pub fn rows(&self, m: &Model) -> Vec<usize> {
        m.events
            .iter()
            .enumerate()
            .filter(|(_, e)| self.filters.admits(e))
            .map(|(i, _)| i)
            .collect()
    }

    /// Put the selection on a row that is shown: the one it is on, else the
    /// next one after it, else the last.
    pub fn settle(&mut self, m: &Model) {
        let rows = self.rows(m);
        self.sel = if self.follow {
            rows.last().copied().unwrap_or(0)
        } else {
            rows.iter()
                .copied()
                .find(|r| *r >= self.sel)
                .or_else(|| rows.last().copied())
                .unwrap_or(0)
        };
    }

    pub fn push_history(&mut self) {
        if self.history.len() == HISTORY {
            self.history.remove(0);
        }
        self.history.push(self.sel);
    }
}

/// The next value after `current` among the sorted distinct `values`, `None`
/// after the last: one key cycles through what the log has and back to "all".
pub(crate) fn cycle(current: &Option<String>, mut values: Vec<String>) -> Option<String> {
    values.sort();
    values.dedup();
    match current {
        None => values.into_iter().next(),
        Some(c) => {
            let i = values.iter().position(|v| v == c);
            i.and_then(|i| values.get(i + 1).cloned())
        }
    }
}
