//! Every admitted event, as the Stream view and the raw-event panel show it.
//! Folded from the verified board: nothing here is fetched, parsed from the
//! wire or checked again; an event is only ever in the board because the
//! follower verified it.

use agent_mesh_flock::{Board, Body, Entry, Kind, Role};
use std::collections::BTreeMap;

/// One thing an event points at: its `prev`, or a named reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    /// `prev`, or the reference's role (`of`, `brief`, `job`, ...).
    pub role: String,
    /// Its content id.
    pub id: String,
    /// Its position in the event list, if the log has it (it always should:
    /// parents are admitted first).
    pub row: Option<usize>,
}

/// One admitted event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    /// Admission index (the first event is 1).
    pub index: u64,
    /// Content id.
    pub id: String,
    /// Kind, kebab-case (`job-end`).
    pub kind: String,
    /// The roster member whose session signed it, or `server`.
    pub member: String,
    /// The lane it belongs to, from itself or the event it answers.
    pub lane: Option<String>,
    /// One line about it.
    pub summary: String,
    /// Admitted as a conflict (a second closer).
    pub conflict: bool,
    /// Signer: the member and the session fingerprint.
    pub signer: String,
    /// The author's claim of when (order is the admission index, not this).
    pub at: u64,
    /// Its `prev` then its references.
    pub parents: Vec<Parent>,
    /// Cited files: `root/path` and the id they were cited with.
    pub files: Vec<String>,
    /// The body, pretty-printed.
    pub body: Vec<String>,
    /// What was checked before it was shown.
    pub verified: String,
}

pub(crate) fn kind_name(k: Kind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn summary(body: &Body) -> String {
    match body {
        Body::Brief { to, lane } => format!("to {to} lane {lane}"),
        Body::Review { to, lane, head } => format!("to {to} lane {lane} head {head}"),
        Body::Result { outcome } => format!("{outcome:?}").to_lowercase(),
        Body::Verdict { head, approved } => {
            format!("{} {head}", if *approved { "approved" } else { "rejected" })
        }
        Body::Job { lane, label } => format!("lane {lane} {label}"),
        Body::JobEnd { code, signal } => match (code, signal) {
            (Some(c), None) => format!("exit {c}"),
            (None, Some(s)) => format!("signal {s}"),
            _ => "unreadable exit".to_owned(),
        },
        Body::Ask { text, .. } | Body::Status { text } | Body::Answer { text } => text.clone(),
        Body::Pane { pane, tab } => format!("pane {pane} tab {tab}"),
        Body::Epoch { epoch } => format!("epoch {epoch}"),
        Body::Invite { member, .. } => format!("for {member}"),
        Body::SessionStart { member, .. } => format!("{member} started"),
        Body::SessionEnd { reason, .. } => format!("{reason:?}").to_lowercase(),
        _ => String::new(),
    }
}

fn own_lane(body: &Body) -> Option<String> {
    match body {
        Body::Brief { lane, .. } | Body::Review { lane, .. } | Body::Job { lane, .. } => {
            Some(lane.clone())
        }
        Body::Ask { lane, .. } => lane.clone(),
        _ => None,
    }
}

fn row_of(e: &Entry, roles: &BTreeMap<&str, Role>, rows: &[EventRow]) -> EventRow {
    let member = e.member.clone().unwrap_or_else(|| "server".to_owned());
    let parent = |role: &str, id: String| {
        let row = rows.iter().position(|r| r.id == id);
        Parent {
            role: role.to_owned(),
            id,
            row,
        }
    };
    let mut parents = vec![];
    if let Some(p) = e.event.prev {
        parents.push(parent("prev", p.to_string()));
    }
    for (role, id) in &e.event.refs {
        parents.push(parent(role, id.to_string()));
    }
    // the lane it names, else the lane of what it answers
    let lane = own_lane(&e.event.body).or_else(|| {
        parents
            .iter()
            .filter_map(|p| p.row)
            .find_map(|i| rows[i].lane.clone())
    });
    let role = roles.get(member.as_str()).map_or(String::new(), |r| {
        format!(", {}", format!("{r:?}").to_lowercase())
    });
    let body = serde_json::to_string_pretty(&e.event.body)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    EventRow {
        index: e.index,
        id: e.id.to_string(),
        kind: kind_name(e.event.kind),
        signer: format!("{member}{role}; session {}", e.event.author),
        member,
        lane,
        summary: summary(&e.event.body),
        conflict: e.conflict.is_some(),
        at: e.event.at,
        parents,
        files: e
            .event
            .files
            .iter()
            .map(|f| format!("{}/{} ({})", f.root, f.path, f.id))
            .collect(),
        body,
        verified: match &e.conflict {
            None => format!(
                "✓ signature, session certificate and admission checked; admitted at #{}",
                e.index
            ),
            Some(c) => format!(
                "✓ checked; admitted at #{} as a conflict ({c:?}): it closes nothing",
                e.index
            ),
        },
    }
}

/// Every event of `board` in admission order. With `prev`, reuse the rows it
/// already holds when they are a prefix of this log (the log only grows), and
/// fold only the new ones.
#[must_use]
pub fn fold_events(board: &Board, prev: Option<&[EventRow]>) -> Vec<EventRow> {
    let roles: BTreeMap<&str, Role> = board
        .members()
        .iter()
        .map(|m| (m.name.as_str(), m.role))
        .collect();
    let entries: Vec<&Entry> = board.entries().collect();
    let mut rows: Vec<EventRow> = match prev {
        Some(p)
            if p.len() <= entries.len()
                && p.last()
                    .is_none_or(|l| entries[p.len() - 1].id.to_string() == l.id) =>
        {
            p.to_vec()
        }
        _ => vec![],
    };
    for e in entries.iter().skip(rows.len()) {
        let row = row_of(e, &roles, &rows);
        rows.push(row);
    }
    rows
}
