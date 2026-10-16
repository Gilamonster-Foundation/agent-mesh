//! Genesis and event schema. Both are `MerkleNode` payloads; the node's id is
//! the event's identity, and the signature is detached (`Assertion`).

use agent_mesh_protocol::CertChain;
use content_addressable::{ContentId, MerkleNode, RawContentId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What an event is. Serialized as its kebab-case name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Replaces the roster.
    Roster,
    /// A task for a member.
    Brief,
    /// A review request for a member.
    Review,
    /// Receipt of a brief or review.
    Ack,
    /// The outcome of a brief.
    Result,
    /// The outcome of a review.
    Verdict,
    /// A long-running job began.
    Job,
    /// A job ended.
    JobEnd,
    /// A question for the operator.
    Ask,
    /// The operator's signed answer.
    Answer,
    /// A member's copy of an answer; closes nothing.
    RelayedAnswer,
    /// Adapter status.
    Status,
    /// Adapter nudge record.
    Nudged,
    /// Server: epoch bump.
    Epoch,
    /// Server: certificate renewal.
    Renewal,
    /// Server: session started.
    SessionStart,
    /// Server: session ended.
    SessionEnd,
    /// Server: role hand-off.
    Handoff,
    /// Server: enrollment invite.
    Invite,
}

/// A member's role in the roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Dispatches briefs and reviews.
    Shepherd,
    /// Receives reviews.
    Reviewer,
    /// Receives briefs.
    Helper,
    /// The herdr adapter: status and nudges only, never an `ack`.
    Adapter,
    /// A human operator.
    Operator,
}

/// One roster entry. Identity only; model and harness are labels elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Unique name within the flock.
    pub name: String,
    /// Its role.
    pub role: Role,
}

/// How a brief ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// The work was done.
    Completed,
    /// It was not.
    Failed,
}

/// A cited file: a root the roster declares, a path under it, and the bytes'
/// id. A reference, never a parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// Declared root name.
    pub root: String,
    /// Path under the root.
    pub path: String,
    /// Content id of the bytes as cited.
    pub id: RawContentId,
}

/// Kind-specific content. Its variant must match the event's [`Kind`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Body {
    /// New roster.
    Roster {
        /// All members.
        members: Vec<Member>,
    },
    /// A brief for `to` in `lane`.
    Brief {
        /// Addressee member name.
        to: String,
        /// Lane name.
        lane: String,
    },
    /// A review request for `to` of `head`.
    Review {
        /// Addressee member name.
        to: String,
        /// Lane name.
        lane: String,
        /// The head under review.
        head: String,
    },
    /// Receipt.
    Ack,
    /// Result of a brief.
    Result {
        /// How it ended.
        outcome: Outcome,
    },
    /// Verdict on a review of `head`.
    Verdict {
        /// Must equal the review's head.
        head: String,
        /// Approved or not.
        approved: bool,
    },
    /// A job in `lane`.
    Job {
        /// Lane name.
        lane: String,
        /// Short label.
        label: String,
    },
    /// A job ended.
    JobEnd {
        /// Exit code.
        code: i64,
    },
    /// A question; `lane` is set when it concerns a lane.
    Ask {
        /// Lane, if any; must match `about`'s lane.
        lane: Option<String>,
        /// The question.
        text: String,
    },
    /// The operator's answer.
    Answer {
        /// The answer.
        text: String,
    },
    /// A copy of an answer.
    RelayedAnswer {
        /// The answer as relayed.
        text: String,
    },
    /// Adapter status.
    Status {
        /// Status text.
        text: String,
    },
    /// Adapter nudge.
    Nudged {
        /// Target the nudge went to.
        target: String,
    },
    /// Server bookkeeping events (epoch, renewal, session-*, handoff, invite).
    Server {
        /// What happened.
        note: String,
    },
}

impl Body {
    /// Whether this body is a legal payload for `kind`.
    #[must_use]
    pub fn fits(&self, kind: Kind) -> bool {
        use Kind as K;
        matches!(
            (self, kind),
            (Self::Roster { .. }, K::Roster)
                | (Self::Brief { .. }, K::Brief)
                | (Self::Review { .. }, K::Review)
                | (Self::Ack, K::Ack)
                | (Self::Result { .. }, K::Result)
                | (Self::Verdict { .. }, K::Verdict)
                | (Self::Job { .. }, K::Job)
                | (Self::JobEnd { .. }, K::JobEnd)
                | (Self::Ask { .. }, K::Ask)
                | (Self::Answer { .. }, K::Answer)
                | (Self::RelayedAnswer { .. }, K::RelayedAnswer)
                | (Self::Status { .. }, K::Status)
                | (Self::Nudged { .. }, K::Nudged)
                | (
                    Self::Server { .. },
                    K::Epoch
                        | K::Renewal
                        | K::SessionStart
                        | K::SessionEnd
                        | K::Handoff
                        | K::Invite
                )
        )
    }
}

/// Genesis payload: the flock's root. `flock_id` is its node id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    /// Always `"genesis"`; keeps the payload distinct from an [`Event`].
    pub kind: String,
    /// Flock name.
    pub name: String,
    /// The server's certificate chain.
    pub server_cert: CertChain,
    /// The first roster.
    pub roster: Vec<Member>,
    /// Makes two flocks of the same name and roster distinct.
    pub salt: String,
}

impl Genesis {
    /// The genesis node (no parents).
    #[must_use]
    pub fn node(self) -> MerkleNode<Self> {
        MerkleNode::genesis(self)
    }
}

/// A non-genesis event payload. `author` is inside the hashed bytes, so two
/// signers of an identical body get different ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The flock (genesis id) this event belongs to.
    pub flock: ContentId,
    /// What it is.
    pub kind: Kind,
    /// Author fingerprint, hex.
    pub author: String,
    /// The author's previous event; absent for operator answers and a
    /// session's first event.
    pub prev: Option<ContentId>,
    /// Named references to other events.
    pub refs: BTreeMap<String, ContentId>,
    /// Cited files (never parents).
    pub files: Vec<FileRef>,
    /// The author's claim of when; order is admission index, not this.
    pub at: u64,
    /// Kind-specific content.
    pub body: Body,
}

impl Event {
    /// The node: parents are `prev` plus every `refs` value.
    #[must_use]
    pub fn node(self) -> MerkleNode<Self> {
        let parents: Vec<ContentId> = self
            .prev
            .iter()
            .chain(self.refs.values())
            .copied()
            .collect();
        MerkleNode::new(self, parents)
    }

    /// Parents this event's node must have: `prev` plus every `refs` value.
    #[must_use]
    pub fn expected_parents(&self) -> std::collections::BTreeSet<ContentId> {
        self.prev
            .iter()
            .chain(self.refs.values())
            .copied()
            .collect()
    }
}
