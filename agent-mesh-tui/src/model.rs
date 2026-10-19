//! The model: a pure fold of the verified log into what the views show. No
//! I/O, no clock, no terminal; the same log always folds to the same model.

use crate::events::{fold_events, EventRow};
use agent_mesh_flock::{AttemptState, AttemptView, Board, Body, FileRef, Kind};
use agent_mesh_flock_server::{Follower, Sessions, Snapshot, Status};
use content_addressable::ContentId;
use std::sync::Arc;

/// What the fold reads: a verified prefix of one flock.
pub struct Source<'a> {
    /// The flock's name (from its genesis).
    pub name: &'a str,
    /// The flock id (the genesis id).
    pub id: ContentId,
    /// The board folded from the log.
    pub board: &'a Board,
    /// The session table derived from the log.
    pub sessions: &'a Sessions,
    /// How many events are verified.
    pub admitted: u64,
    /// The epoch at the end of the prefix.
    pub epoch: u64,
}

impl<'a> Source<'a> {
    /// From a follower (the live feed).
    #[must_use]
    pub fn of_follower(name: &'a str, id: ContentId, f: &'a Follower) -> Self {
        Self {
            name,
            id,
            board: f.board(),
            sessions: f.sessions(),
            admitted: f.admitted(),
            epoch: f.epoch(),
        }
    }

    /// From a read-only snapshot of the log on disk.
    #[must_use]
    pub fn of_snapshot(name: &'a str, id: ContentId, s: &'a Snapshot) -> Self {
        Self {
            name,
            id,
            board: s.board(),
            sessions: s.sessions(),
            admitted: s.admitted(),
            epoch: s.epoch(),
        }
    }
}

/// Whether the view is following the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// Caught up and following.
    Live,
    /// The stream is down; the view is the log as of `since` events.
    Stale {
        /// The last verified index.
        since: u64,
    },
    /// Verification or rollback failed: nothing after this can be trusted.
    Failed(String),
    /// A verified frame could not be saved. The view stays at the last saved
    /// prefix (what is shown has been witnessed) and says why.
    Unsaved(String),
}

/// What every view shows at the top.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The flock's name.
    pub flock: String,
    /// The first characters of the flock id.
    pub short_id: String,
    /// Roster size.
    pub members: usize,
    /// Events verified.
    pub verified: u64,
    /// The epoch.
    pub epoch: u64,
    /// Following or not.
    pub link: Link,
}

/// Open work a member holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Open {
    /// Jobs it started that have not ended.
    pub jobs: usize,
    /// Lanes briefed to it whose latest attempt is submitted or working.
    pub lanes: usize,
    /// Asks it raised that nobody has answered.
    pub asks: usize,
}

/// One roster member as the Board shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    /// Roster name.
    pub name: String,
    /// Role, lower case.
    pub role: String,
    /// Session state from the log.
    pub session: String,
    /// The member's own latest `status` text (what it says about itself).
    pub says: String,
    /// Open work.
    pub open: Open,
    /// Events since the member last wrote anything; `None` if it never has.
    pub quiet_for: Option<u64>,
}

/// One attempt (a brief) of a lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The brief's admission index.
    pub index: u64,
    /// `completed, job open` and the like, verbatim from the fold.
    pub label: String,
    /// Admission indexes of the conflict events aimed at it.
    pub conflicts: Vec<u64>,
}

/// A review or verdict of a lane and whether a later result has overtaken it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewed {
    /// Its admission index.
    pub index: u64,
    /// `review` or `verdict`.
    pub kind: String,
    /// The head it is about (the author's claim: the flock cannot see git).
    pub head: String,
    /// The first result of the lane admitted after it, if any: the head it
    /// names may be stale since then.
    pub newer_result: Option<u64>,
}

/// One lane as the Lane view shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneRow {
    /// Lane name.
    pub lane: String,
    /// The latest attempt.
    pub latest: Attempt,
    /// Earlier attempts, oldest first.
    pub older: Vec<Attempt>,
    /// Its reviews and verdicts, in admission order.
    pub reviews: Vec<Reviewed>,
    /// Every distinct file its events cite (root, path, id), first cited first.
    pub files: Vec<FileRef>,
}

/// Everything the views need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    /// The header.
    pub header: Header,
    /// The roster, in roster order.
    pub members: Vec<MemberRow>,
    /// Every admitted event, in admission order (shared between models: the
    /// log only grows, so a newer model reuses the older one's rows).
    pub events: Arc<Vec<EventRow>>,
    /// Every lane with a brief, by name.
    pub lanes: Vec<LaneRow>,
}

const SHORT_ID: usize = 12;

/// Fold a verified log into the model.
#[must_use]
pub fn fold(src: &Source<'_>, link: Link) -> Model {
    fold_onto(None, src, link)
}

/// [`fold`], reusing the event rows of `prev` (an earlier fold of the same
/// log) instead of building them again.
#[must_use]
pub fn fold_onto(prev: Option<&Model>, src: &Source<'_>, link: Link) -> Model {
    let id = src.id.to_string();
    let header = Header {
        flock: src.name.to_owned(),
        short_id: id.chars().take(SHORT_ID).collect(),
        members: src.board.members().len(),
        verified: src.admitted,
        epoch: src.epoch,
        link,
    };
    let members = src
        .board
        .members()
        .iter()
        .map(|m| MemberRow {
            name: m.name.clone(),
            role: format!("{:?}", m.role).to_lowercase(),
            session: session_state(src.sessions, &m.name),
            says: latest_status(src.board, &m.name),
            open: open_work(src.board, &m.name),
            quiet_for: quiet_for(src.board, &m.name, src.admitted),
        })
        .collect();
    let events = Arc::new(fold_events(src.board, prev.map(|p| p.events.as_slice())));
    let lanes = lane_rows(src.board, &events);
    Model {
        header,
        members,
        events,
        lanes,
    }
}

fn attempt(a: &AttemptView, board: &Board) -> Attempt {
    let at = |id| board.get(id).map_or(0, |e| e.index);
    Attempt {
        index: at(&a.brief),
        label: a.label(),
        conflicts: a.conflicts.iter().map(at).collect(),
    }
}

fn lane_rows(board: &Board, events: &[EventRow]) -> Vec<LaneRow> {
    board
        .lanes()
        .into_iter()
        .map(|l| {
            let mine: Vec<(&agent_mesh_flock::Entry, &EventRow)> = board
                .entries()
                .zip(events)
                .filter(|(_, r)| r.lane.as_deref() == Some(l.lane.as_str()))
                .collect();
            let mut files: Vec<FileRef> = vec![];
            for (e, _) in &mine {
                for f in &e.event.files {
                    if !files.contains(f) {
                        files.push(f.clone());
                    }
                }
            }
            let results: Vec<u64> = mine
                .iter()
                .filter(|(e, _)| e.event.kind == Kind::Result && e.conflict.is_none())
                .map(|(e, _)| e.index)
                .collect();
            let reviews = mine
                .iter()
                .filter_map(|(e, r)| {
                    let (kind, head) = match &e.event.body {
                        Body::Review { head, .. } => ("review", head),
                        Body::Verdict { head, .. } => ("verdict", head),
                        _ => return None,
                    };
                    Some(Reviewed {
                        index: e.index,
                        kind: kind.to_owned(),
                        head: head.clone(),
                        newer_result: results.iter().copied().find(|i| *i > r.index),
                    })
                })
                .collect();
            LaneRow {
                latest: attempt(&l.latest, board),
                older: l.older.iter().map(|a| attempt(a, board)).collect(),
                lane: l.lane,
                reviews,
                files,
            }
        })
        .collect()
}

/// A member can hold one active session and pending replacements.
fn session_state(sessions: &Sessions, member: &str) -> String {
    let (mut active, mut pending) = (0, 0);
    for s in sessions
        .live()
        .filter_map(|(s, _, _)| sessions.get(s))
        .filter(|s| s.member == member)
    {
        match s.status {
            Status::Active => active += 1,
            Status::Pending => pending += 1,
            Status::Ended => {}
        }
    }
    match (active, pending) {
        (0, 0) => "none".to_owned(),
        (0, _) => "pending".to_owned(),
        (_, 0) => "active".to_owned(),
        (_, n) => format!("active +{n}"),
    }
}

fn latest_status(board: &Board, member: &str) -> String {
    board
        .entries()
        .filter(|e| e.event.kind == Kind::Status && e.member.as_deref() == Some(member))
        .last()
        .and_then(|e| match &e.event.body {
            Body::Status { text } => Some(text.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "-".to_owned())
}

fn open_work(board: &Board, member: &str) -> Open {
    let mine = |e: &agent_mesh_flock::Entry| e.member.as_deref() == Some(member);
    let jobs = board
        .entries()
        .filter(|e| mine(e) && e.event.kind == Kind::Job && e.conflict.is_none())
        .filter(|e| board.closer_of(&e.id).is_none())
        .count();
    let asks = board
        .entries()
        .filter(|e| mine(e) && e.event.kind == Kind::Ask && e.conflict.is_none())
        .filter(|e| board.closer_of(&e.id).is_none())
        .count();
    let lanes = board
        .lanes()
        .into_iter()
        .filter(|l| {
            matches!(
                l.latest.state,
                AttemptState::Submitted | AttemptState::Working | AttemptState::InputRequired
            ) && board
                .get(&l.latest.brief)
                .is_some_and(|e| matches!(&e.event.body, Body::Brief { to, .. } if to == member))
        })
        .count();
    Open { jobs, lanes, asks }
}

fn quiet_for(board: &Board, member: &str, admitted: u64) -> Option<u64> {
    board
        .entries()
        .filter(|e| e.member.as_deref() == Some(member))
        .map(|e| e.index)
        .max()
        .map(|last| admitted.saturating_sub(last))
}
