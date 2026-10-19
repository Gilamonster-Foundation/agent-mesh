//! The admission table as a pure function: (derived state, event, signer) ->
//! admit / admit-as-conflict / refuse.
//!
//! Checks run in the spec's order: duplicate, signer class, writer chain,
//! references, then who may sign what.

use crate::board::Board;
use crate::event::{Body, Event, Kind, Member, Role};
use crate::signer::{Signer, SignerClass};
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use std::collections::{BTreeMap, BTreeSet};

/// Why an event is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The id could not be computed.
    Unencodable,
    /// The event names another flock.
    WrongFlock,
    /// `author` is not the signer's fingerprint.
    AuthorMismatch,
    /// The node's parents are not `prev` plus the `refs`.
    BadParents,
    /// The body does not belong to the kind.
    BodyKindMismatch,
    /// A pending (replacement) session signs nothing.
    PendingSession,
    /// The session's member is not on the roster.
    UnknownMember,
    /// This signer class or role may not sign this kind.
    NotAllowed,
    /// `prev` is neither the author's head nor a legal first link.
    BadPrev,
    /// A second child of the author's head: a writer fork. Refused; the
    /// server records the attempt, this crate admits nothing.
    WriterFork,
    /// A required reference is absent.
    MissingRef(&'static str),
    /// A reference role this kind does not take.
    UnexpectedRef(String),
    /// A referenced event is not in this flock's log.
    UnknownRef(&'static str),
    /// A referenced event is of the wrong kind.
    WrongRefKind(&'static str),
    /// A referenced event is in another lane.
    CrossLane,
    /// The signer is not the addressee (or job author) of the target.
    NotAddressee,
    /// The herdr adapter never acks, even a brief addressed to it.
    AdapterCannotAck,
    /// A verdict's head differs from its review's.
    HeadMismatch,
    /// `replaces` is not the current roster.
    StaleRoster,
    /// The frame this would commit is too large to deliver to a watcher.
    TooLarge,
    /// Only a server-signed roster changes operator devices.
    DevicesLocked,
    /// `devices` on a member that is not an operator.
    DevicesOnNonOperator,
    /// Two roster members share a name.
    DuplicateMember,
    /// A claim (pane, tab) that is empty, too long or not printable.
    BadClaim,
    /// A `job-end` that does not say exactly one of an exit code and a signal.
    BadExit,
}

/// An event admitted but flagged: it never replaces the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictKind {
    /// A second closer of the same target.
    SecondCloser {
        /// The closer already admitted.
        first: ContentId,
    },
}

/// The admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Admit.
    Admit,
    /// Admit, logged as a conflict.
    Conflict(ConflictKind),
    /// Already admitted at this index.
    Duplicate(u64),
    /// Refuse.
    Refuse(Refusal),
}

/// Decide whether `node`, signed by `signer`, is admitted to `board`.
#[must_use]
pub fn admit(board: &Board, node: &MerkleNode<Event>, signer: &Signer) -> Verdict {
    match decide(board, node, signer) {
        Ok(verdict) => verdict,
        Err(refusal) => Verdict::Refuse(refusal),
    }
}

fn decide(board: &Board, node: &MerkleNode<Event>, signer: &Signer) -> Result<Verdict, Refusal> {
    let id = node.content_id().map_err(|_| Refusal::Unencodable)?;
    if let Some(done) = board.get(&id) {
        return Ok(Verdict::Duplicate(done.index));
    }
    let ev = &node.payload;
    if ev.flock != board.flock() {
        return Err(Refusal::WrongFlock);
    }
    if ev.author != signer.fingerprint.hex() {
        return Err(Refusal::AuthorMismatch);
    }
    if node.parents != ev.expected_parents() {
        return Err(Refusal::BadParents);
    }
    if !ev.body.fits(ev.kind) {
        return Err(Refusal::BodyKindMismatch);
    }
    let member = signer_member(board, ev.kind, signer)?;
    if let Body::Roster { members } = &ev.body {
        check_devices(board, members, signer)?;
    }
    writer_chain(board, ev, signer)?;
    let target = check_refs(board, ev)?;
    let closes = apply_table(board, ev, member, target)?;
    Ok(match closes.and_then(|t| board.closer_of(&t)) {
        Some(first) => Verdict::Conflict(ConflictKind::SecondCloser { first }),
        None => Verdict::Admit,
    })
}

/// A roster is well formed when member names are unique (bindings are by
/// name) and devices belong to operator members only. Every reader of a
/// roster (init, the genesis loader, roster admission) uses this one rule.
#[must_use]
pub fn roster_well_formed(members: &[Member]) -> bool {
    let mut names = std::collections::BTreeSet::new();
    members.iter().all(|m| {
        names.insert(m.name.as_str()) && (m.role == Role::Operator || m.devices.is_empty())
    })
}

/// Device bindings by member name, each list sorted: roster order and device
/// order are not part of the binding.
fn bindings(ms: &[Member]) -> BTreeMap<&str, Vec<[u8; 32]>> {
    ms.iter()
        .filter(|m| !m.devices.is_empty())
        .map(|m| {
            let mut d: Vec<_> = m.devices.iter().map(|f| f.0).collect();
            d.sort_unstable();
            (m.name.as_str(), d)
        })
        .collect()
}

/// Operator `devices`: only on operator members, and changed only by the
/// server (a shepherd's roster must carry the bindings the roster has now).
fn check_devices(board: &Board, new: &[Member], signer: &Signer) -> Result<(), Refusal> {
    let mut names = BTreeSet::new();
    if !new.iter().all(|m| names.insert(m.name.as_str())) {
        return Err(Refusal::DuplicateMember);
    }
    if !roster_well_formed(new) {
        return Err(Refusal::DevicesOnNonOperator);
    }
    if signer.class != SignerClass::Server && bindings(new) != bindings(board.members()) {
        return Err(Refusal::DevicesLocked);
    }
    Ok(())
}

/// The signing member (name, role) for session signers, after the class gate.
fn signer_member<'a>(
    board: &'a Board,
    kind: Kind,
    signer: &'a Signer,
) -> Result<Option<(&'a str, Role)>, Refusal> {
    use Kind as K;
    match &signer.class {
        SignerClass::Server => match kind {
            K::Roster
            | K::Epoch
            | K::Renewal
            | K::SessionStart
            | K::SessionEnd
            | K::Handoff
            | K::Invite => Ok(None),
            _ => Err(Refusal::NotAllowed),
        },
        SignerClass::Operator => match kind {
            K::Answer => Ok(None),
            _ => Err(Refusal::NotAllowed),
        },
        SignerClass::Session { member, pending } => {
            if *pending {
                return Err(Refusal::PendingSession);
            }
            let role = board
                .members()
                .iter()
                .find(|m| &m.name == member)
                .map(|m| m.role)
                .ok_or(Refusal::UnknownMember)?;
            let allowed = match kind {
                K::Roster | K::Brief | K::Review => role == Role::Shepherd,
                K::Status | K::Nudged | K::NudgeMisfire => role == Role::Adapter,
                K::Ack
                | K::Result
                | K::Verdict
                | K::Job
                | K::JobEnd
                | K::Ask
                | K::Pane
                | K::RelayedAnswer => true,
                K::Answer
                | K::Epoch
                | K::Renewal
                | K::SessionStart
                | K::SessionEnd
                | K::Handoff
                | K::Invite => false,
            };
            if kind == K::Ack && role == Role::Adapter {
                return Err(Refusal::AdapterCannotAck);
            }
            if allowed {
                Ok(Some((member.as_str(), role)))
            } else {
                Err(Refusal::NotAllowed)
            }
        }
    }
}

/// `prev` must be the session author's head; a second child is a writer
/// fork and is refused before any reference or table check. A session's
/// first event may chain from a server `handoff`.
fn writer_chain(board: &Board, ev: &Event, signer: &Signer) -> Result<(), Refusal> {
    match signer.class {
        SignerClass::Server => return Ok(()),
        SignerClass::Operator => {
            return if ev.prev.is_none() {
                Ok(())
            } else {
                Err(Refusal::BadPrev)
            }
        }
        SignerClass::Session { .. } => {}
    }
    let head = board.head_of(&ev.author);
    if ev.prev == head {
        return Ok(());
    }
    match (head, ev.prev) {
        (None, Some(p)) => match board.get(&p) {
            Some(e) if e.event.kind == Kind::Handoff => Ok(()),
            _ => Err(Refusal::BadPrev),
        },
        (Some(_), None) => Err(Refusal::WriterFork),
        (Some(_), Some(p)) => match board.get(&p) {
            Some(e) if e.event.author == ev.author => Err(Refusal::WriterFork),
            _ => Err(Refusal::BadPrev),
        },
        (None, None) => Ok(()),
    }
}

/// The referenced events a kind takes: (role, allowed target kinds, required).
fn ref_spec(kind: Kind) -> &'static [(&'static str, &'static [Kind], bool)] {
    use Kind as K;
    match kind {
        K::Roster => &[("replaces", &[K::Roster], true)],
        K::Ack => &[("of", &[K::Brief, K::Review], true)],
        K::Result => &[("brief", &[K::Brief], true)],
        K::Verdict => &[("review", &[K::Review], true)],
        K::JobEnd => &[("job", &[K::Job], true)],
        K::Ask => &[("about", &[K::Brief], false)],
        K::Answer | K::RelayedAnswer => &[("ask", &[K::Ask], true)],
        // what a nudge was about; optional, so a nudge needs no event to cite
        K::Nudged | K::NudgeMisfire => &[("of", &[K::Brief, K::Review], false)],
        _ => &[],
    }
}

fn is_server_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Epoch
            | Kind::Renewal
            | Kind::SessionStart
            | Kind::SessionEnd
            | Kind::Handoff
            | Kind::Invite
    )
}

fn declared_lane(body: &Body) -> Option<&str> {
    match body {
        Body::Brief { lane, .. } | Body::Review { lane, .. } | Body::Job { lane, .. } => Some(lane),
        Body::Ask { lane, .. } => lane.as_deref(),
        _ => None,
    }
}

/// Every reference exists in this flock, is of the right kind and stays in
/// the event's lane. Returns the event the kind acts on, if any.
fn check_refs(board: &Board, ev: &Event) -> Result<Option<ContentId>, Refusal> {
    if is_server_kind(ev.kind) {
        // Server bookkeeping may cite earlier events freely, but they must exist.
        for cid in ev.refs.values() {
            if board.get(cid).is_none() {
                return Err(Refusal::UnknownRef("server"));
            }
        }
        return Ok(None);
    }
    let spec = ref_spec(ev.kind);
    if let Some(role) = ev
        .refs
        .keys()
        .find(|r| !spec.iter().any(|(s, _, _)| s == r))
    {
        return Err(Refusal::UnexpectedRef(role.clone()));
    }
    let mut acts_on = None;
    for (role, kinds, required) in spec {
        let Some(cid) = ev.refs.get(*role) else {
            if *required {
                return Err(Refusal::MissingRef(role));
            }
            continue;
        };
        if ev.kind == Kind::Roster {
            // `replaces` is the current roster: the genesis or a roster event.
            if *cid != board.roster_id() {
                return Err(Refusal::StaleRoster);
            }
            continue;
        }
        let entry = board.get(cid).ok_or(Refusal::UnknownRef(role))?;
        if !kinds.contains(&entry.event.kind) {
            return Err(Refusal::WrongRefKind(role));
        }
        if let (Some(mine), Some(theirs)) =
            (declared_lane(&ev.body), declared_lane(&entry.event.body))
        {
            if mine != theirs {
                return Err(Refusal::CrossLane);
            }
        }
        acts_on = Some(*cid);
    }
    Ok(acts_on)
}

/// Who may sign what, against the referenced event. Returns the target the
/// event closes, if it closes one.
fn apply_table(
    board: &Board,
    ev: &Event,
    member: Option<(&str, Role)>,
    target: Option<ContentId>,
) -> Result<Option<ContentId>, Refusal> {
    let target_entry = target.and_then(|t| board.get(&t));
    let addressee = |entry: &crate::board::Entry| match &entry.event.body {
        Body::Brief { to, .. } | Body::Review { to, .. } => Some(to.clone()),
        _ => None,
    };
    match (&ev.body, ev.kind) {
        (_, Kind::Ack) => {
            let (name, _) = member.ok_or(Refusal::NotAllowed)?;
            let entry = target_entry.ok_or(Refusal::MissingRef("of"))?;
            if addressee(entry).as_deref() != Some(name) {
                return Err(Refusal::NotAddressee);
            }
            Ok(None)
        }
        (_, Kind::Result) => {
            let (name, _) = member.ok_or(Refusal::NotAllowed)?;
            let entry = target_entry.ok_or(Refusal::MissingRef("brief"))?;
            if addressee(entry).as_deref() != Some(name) {
                return Err(Refusal::NotAddressee);
            }
            Ok(target)
        }
        (Body::Verdict { head, .. }, Kind::Verdict) => {
            let (name, _) = member.ok_or(Refusal::NotAllowed)?;
            let entry = target_entry.ok_or(Refusal::MissingRef("review"))?;
            if addressee(entry).as_deref() != Some(name) {
                return Err(Refusal::NotAddressee);
            }
            match &entry.event.body {
                Body::Review { head: h, .. } if h == head => Ok(target),
                _ => Err(Refusal::HeadMismatch),
            }
        }
        (body, Kind::JobEnd) => {
            if !matches!(body, Body::JobEnd { code, signal } if code.is_some() != signal.is_some())
            {
                return Err(Refusal::BadExit);
            }
            let (name, _) = member.ok_or(Refusal::NotAllowed)?;
            let entry = target_entry.ok_or(Refusal::MissingRef("job"))?;
            if entry.member.as_deref() != Some(name) {
                return Err(Refusal::NotAddressee);
            }
            Ok(target)
        }
        (Body::Pane { pane, tab }, Kind::Pane) => {
            if [pane, tab].iter().all(|v| claim_ok(v)) {
                Ok(None)
            } else {
                Err(Refusal::BadClaim)
            }
        }
        (_, Kind::Answer) => Ok(target),
        (Body::Nudged { target: to }, Kind::Nudged) => nudge_ok(board, to, target_entry, &[]),
        (
            Body::NudgeMisfire {
                target: to,
                expected,
                found,
            },
            Kind::NudgeMisfire,
        ) => nudge_ok(board, to, target_entry, &[expected, found]),
        _ => Ok(None),
    }
}

/// A nudge (or a misfire) is about a roster member, and, if it cites a brief
/// or review, about that one's addressee: the adapter cannot say it nudged
/// someone about work addressed to someone else. It closes nothing.
fn nudge_ok(
    board: &Board,
    target: &str,
    about: Option<&crate::board::Entry>,
    texts: &[&String],
) -> Result<Option<ContentId>, Refusal> {
    if !board.members().iter().any(|m| m.name == target) {
        return Err(Refusal::UnknownMember);
    }
    if let Some(entry) = about {
        let to = match &entry.event.body {
            Body::Brief { to, .. } | Body::Review { to, .. } => to,
            _ => return Err(Refusal::WrongRefKind("of")),
        };
        if to != target {
            return Err(Refusal::NotAddressee);
        }
    }
    if !texts.iter().all(|t| claim_ok(t)) {
        return Err(Refusal::BadClaim);
    }
    Ok(None)
}

/// A claimed id is short and printable: it ends up on an operator's screen.
fn claim_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control)
}
