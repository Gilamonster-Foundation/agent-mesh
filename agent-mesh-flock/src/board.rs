//! The derived state: a deterministic fold of the admitted log.
//!
//! Every reader applies the same events in admission order through the same
//! [`admit`], so every reader computes the same board.

use crate::admission::{admit, ConflictKind, Refusal, Verdict};
use crate::event::{Body, Event, Genesis, Kind, Member, Outcome};
use crate::signer::Signer;
use content_addressable::{ContentAddressable, ContentError, ContentId, MerkleNode};
use std::collections::BTreeMap;

/// One admitted-log item as a reader sees it: the node and who signed it.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// The event node.
    pub node: MerkleNode<Event>,
    /// The signer, resolved by the caller.
    pub signer: Signer,
}

/// An admitted event in the board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its content id.
    pub id: ContentId,
    /// Admission index (genesis is not counted; the first event is 1).
    pub index: u64,
    /// The event.
    pub event: Event,
    /// The roster member of the signing session, if any.
    pub member: Option<String>,
    /// Set when it was admitted as a conflict.
    pub conflict: Option<ConflictKind>,
}

/// A brief's state, the first row that applies (A2A names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptState {
    /// Admitted, nothing more.
    Submitted,
    /// Acked.
    Working,
    /// An open ask names it.
    InputRequired,
    /// A result with outcome completed.
    Completed,
    /// A result with outcome failed.
    Failed,
}

/// One attempt (brief) and what surrounds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptView {
    /// The brief.
    pub brief: ContentId,
    /// Its state.
    pub state: AttemptState,
    /// A job in the same lane is still open.
    pub job_open: bool,
    /// Conflict events aimed at it, in admission order.
    pub conflicts: Vec<ContentId>,
}

impl AttemptView {
    /// The label a board shows: `completed, job open`.
    #[must_use]
    pub fn label(&self) -> String {
        let state = match self.state {
            AttemptState::Submitted => "submitted",
            AttemptState::Working => "working",
            AttemptState::InputRequired => "input-required",
            AttemptState::Completed => "completed",
            AttemptState::Failed => "failed",
        };
        if self.job_open {
            format!("{state}, job open")
        } else {
            state.to_owned()
        }
    }
}

/// A lane: the latest attempt, and the older ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneView {
    /// Lane name.
    pub lane: String,
    /// The latest attempt.
    pub latest: AttemptView,
    /// Earlier attempts, oldest first.
    pub older: Vec<AttemptView>,
}

/// A log entry the fold refused: the log is not an admitted log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldError {
    /// Position in the input.
    pub position: usize,
    /// Why.
    pub refusal: Refusal,
}

/// The board.
#[derive(Debug, Clone)]
pub struct Board {
    flock: ContentId,
    roster_id: ContentId,
    members: Vec<Member>,
    entries: BTreeMap<ContentId, Entry>,
    order: Vec<ContentId>,
    heads: BTreeMap<String, ContentId>,
    closers: BTreeMap<ContentId, ContentId>,
}

impl Board {
    /// Start from genesis; the genesis roster is the current roster.
    ///
    /// # Errors
    /// Encoding failure computing the genesis id.
    pub fn new(genesis: &MerkleNode<Genesis>) -> Result<Self, ContentError> {
        let flock = genesis.content_id()?;
        Ok(Self {
            flock,
            roster_id: flock,
            members: genesis.payload.roster.clone(),
            entries: BTreeMap::new(),
            order: Vec::new(),
            heads: BTreeMap::new(),
            closers: BTreeMap::new(),
        })
    }

    /// Fold an admitted log.
    ///
    /// # Errors
    /// The first entry that is refused (a log contains only admitted events).
    pub fn fold(genesis: &MerkleNode<Genesis>, log: &[LogEntry]) -> Result<Self, FoldError> {
        let mut board = Self::new(genesis).map_err(|_| FoldError {
            position: 0,
            refusal: Refusal::Unencodable,
        })?;
        for (position, entry) in log.iter().enumerate() {
            if let Verdict::Refuse(refusal) = board.apply(entry) {
                return Err(FoldError { position, refusal });
            }
        }
        Ok(board)
    }

    /// Admit one entry and, unless refused or a duplicate, record it.
    pub fn apply(&mut self, entry: &LogEntry) -> Verdict {
        let verdict = admit(self, &entry.node, &entry.signer);
        let conflict = match &verdict {
            Verdict::Admit => None,
            Verdict::Conflict(kind) => Some(kind.clone()),
            Verdict::Duplicate(_) | Verdict::Refuse(_) => return verdict,
        };
        let Ok(id) = entry.node.content_id() else {
            return Verdict::Refuse(Refusal::Unencodable);
        };
        let event = entry.node.payload.clone();
        let member = match &entry.signer.class {
            crate::SignerClass::Session { member, .. } => Some(member.clone()),
            _ => None,
        };
        let index = self.order.len() as u64 + 1;
        if conflict != Some(ConflictKind::ForkAttempt) {
            self.heads.insert(event.author.clone(), id);
        }
        if conflict.is_none() {
            if let Some(target) = closed_by(&event) {
                self.closers.insert(target, id);
            }
        }
        if let (Kind::Roster, Body::Roster { members }) = (event.kind, &event.body) {
            if conflict.is_none() {
                self.members.clone_from(members);
                self.roster_id = id;
            }
        }
        self.order.push(id);
        self.entries.insert(
            id,
            Entry {
                id,
                index,
                event,
                member,
                conflict,
            },
        );
        verdict
    }

    /// The flock id (genesis id).
    #[must_use]
    pub fn flock(&self) -> ContentId {
        self.flock
    }

    /// The current roster event id (genesis until replaced).
    #[must_use]
    pub fn roster_id(&self) -> ContentId {
        self.roster_id
    }

    /// The current roster.
    #[must_use]
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// An admitted event.
    #[must_use]
    pub fn get(&self, id: &ContentId) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// Admitted events in admission order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.order.iter().filter_map(|id| self.entries.get(id))
    }

    /// The author's current chain head (hex fingerprint).
    #[must_use]
    pub fn head_of(&self, author: &str) -> Option<ContentId> {
        self.heads.get(author).copied()
    }

    /// The event that closed `target`, if any.
    #[must_use]
    pub fn closer_of(&self, target: &ContentId) -> Option<ContentId> {
        self.closers.get(target).copied()
    }

    /// The attempt view of a brief.
    #[must_use]
    pub fn attempt(&self, brief: &ContentId) -> Option<AttemptView> {
        let entry = self.get(brief)?;
        let Body::Brief { lane, .. } = &entry.event.body else {
            return None;
        };
        let outcome = self
            .closer_of(brief)
            .and_then(|r| match self.get(&r)?.event.body {
                Body::Result { outcome } => Some(outcome),
                _ => None,
            });
        let refs_brief = |e: &Entry, role: &str| e.event.refs.get(role) == Some(brief);
        let input_required = self.entries().any(|e| {
            e.event.kind == Kind::Ask
                && refs_brief(e, "about")
                && e.conflict.is_none()
                && self.closer_of(&e.id).is_none()
        });
        let acked = self
            .entries()
            .any(|e| e.event.kind == Kind::Ack && refs_brief(e, "of"));
        let state = match outcome {
            Some(Outcome::Completed) => AttemptState::Completed,
            Some(Outcome::Failed) => AttemptState::Failed,
            None if input_required => AttemptState::InputRequired,
            None if acked => AttemptState::Working,
            None => AttemptState::Submitted,
        };
        let job_open = self.entries().any(|e| {
            matches!(&e.event.body, Body::Job { lane: l, .. } if l == lane)
                && self.closer_of(&e.id).is_none()
        });
        let conflicts = self
            .entries()
            .filter(|e| e.conflict.is_some() && e.event.refs.values().any(|r| r == brief))
            .map(|e| e.id)
            .collect();
        Some(AttemptView {
            brief: *brief,
            state,
            job_open,
            conflicts,
        })
    }

    /// Lanes by name, each with its latest attempt first-class and the older
    /// ones kept visible.
    #[must_use]
    pub fn lanes(&self) -> Vec<LaneView> {
        let mut by_lane: BTreeMap<&str, Vec<AttemptView>> = BTreeMap::new();
        for e in self.entries() {
            if let Body::Brief { lane, .. } = &e.event.body {
                if let Some(view) = self.attempt(&e.id) {
                    by_lane.entry(lane).or_default().push(view);
                }
            }
        }
        by_lane
            .into_iter()
            .filter_map(|(lane, mut attempts)| {
                let latest = attempts.pop()?;
                Some(LaneView {
                    lane: lane.to_owned(),
                    latest,
                    older: attempts,
                })
            })
            .collect()
    }
}

/// The event this one closes, by kind (second closers are conflicts and
/// never reach here).
fn closed_by(event: &Event) -> Option<ContentId> {
    let role = match event.kind {
        Kind::Result => "brief",
        Kind::Verdict => "review",
        Kind::JobEnd => "job",
        Kind::Answer => "ask",
        _ => return None,
    };
    event.refs.get(role).copied()
}
