//! What the server knows, all derived from the log: the board, the admission
//! chain's head and the session table. Cloned for a multi-event transaction
//! so a failure half way leaves the live state untouched.

use crate::chain::{verify_record, Chain};
use crate::frame::{seal, AdmissionRecord, Sealed};
use crate::sessions::Sessions;
use crate::ServerError;
use agent_mesh_flock::{
    admit, Board, Body, ConflictKind, Event, Kind, LogEntry, Member, Signer, Verdict,
};
use agent_mesh_protocol::{AgentKey, Assertion};
use content_addressable::{ContentAddressable, ContentId, MerkleNode};

#[derive(Clone)]
pub struct State {
    pub board: Board,
    pub chain: Chain,
    pub sessions: Sessions,
}

/// A server-authored event to be built, signed and admitted.
pub struct Spec {
    pub kind: Kind,
    pub refs: Vec<(&'static str, ContentId)>,
    pub body: Body,
}

/// An event that passed every check, sealed and ready to append.
pub struct Prepared {
    pub sealed: Sealed,
    pub signer: Signer,
    pub conflict: Option<ConflictKind>,
    pub id: ContentId,
    pub record_id: ContentId,
}

fn enc(e: content_addressable::ContentError) -> ServerError {
    ServerError::Encoding(e.to_string())
}

/// A `session-end` or `handoff` and its `epoch` bump are one transaction:
/// each in a frame is followed at once by the `epoch` event.
///
/// # Errors
/// Which position breaks the rule.
pub fn check_frame_shape(sealed: &[Sealed]) -> Result<(), String> {
    for (i, s) in sealed.iter().enumerate() {
        if matches!(s.event.payload.kind, Kind::SessionEnd | Kind::Handoff)
            && sealed.get(i + 1).map(|n| n.event.payload.kind) != Some(Kind::Epoch)
        {
            return Err(
                "session-end or handoff is not followed by its epoch bump in the same frame".into(),
            );
        }
    }
    Ok(())
}

/// Whether `after` lacks a name that `before` has: the one roster change
/// that strands live sessions, so it must carry an epoch bump.
#[must_use]
pub fn drops_member(before: &[Member], after: &[Member]) -> bool {
    before
        .iter()
        .any(|b| !after.iter().any(|a| a.name == b.name))
}

impl State {
    /// Replay one frame: each `roster` that drops a member must be followed
    /// at once by the `epoch` bump, in the same frame.
    pub fn replay_frame(&mut self, sealed: &[Sealed]) -> Result<(), ServerError> {
        for (i, s) in sealed.iter().enumerate() {
            let before = self.board.members().to_vec();
            self.replay(s)?;
            if s.event.payload.kind == Kind::Roster
                && drops_member(&before, self.board.members())
                && sealed.get(i + 1).map(|n| n.event.payload.kind) != Some(Kind::Epoch)
            {
                return Err(ServerError::Session(
                    "a roster that drops a member is not followed by its epoch bump in the same frame"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// The sessions that are live (not ended) and whose member is on the
    /// current roster.
    #[must_use]
    pub fn eligible(&self) -> crate::Eligible {
        let members = self.board.members();
        std::sync::Arc::new(
            self.sessions
                .live()
                .filter_map(|(s, _, _)| self.sessions.get(s).map(|i| (s, i)))
                .filter(|(_, i)| members.iter().any(|m| m.name == i.member))
                .map(|(s, _)| s.to_owned())
                .collect(),
        )
    }

    /// Signer, then the model's table, then the session rules: the order the
    /// log is verified in live and on replay.
    fn vet(
        &self,
        node: &MerkleNode<Event>,
        id: &ContentId,
        sig: &Assertion,
        epoch: u64,
    ) -> Result<(Signer, Option<ConflictKind>), ServerError> {
        let server = &self.chain.server_pub;
        let signer = self
            .sessions
            .resolve(sig, id, server, epoch)
            .map_err(ServerError::Signer)?;
        let conflict = match admit(&self.board, node, &signer) {
            Verdict::Admit => None,
            Verdict::Conflict(c) => Some(c),
            Verdict::Duplicate(_) => return Err(ServerError::Session("already admitted".into())),
            Verdict::Refuse(r) => return Err(ServerError::Refused(r)),
        };
        self.sessions
            .check(&self.board, &node.payload, epoch, &self.chain)
            .map_err(ServerError::Session)?;
        self.sessions
            .first_link(&self.board, &node.payload)
            .map_err(ServerError::Session)?;
        Ok((signer, conflict))
    }

    /// Check and seal `node` as the next admission, changing nothing.
    pub fn prepare(
        &self,
        key: &AgentKey,
        node: &MerkleNode<Event>,
        sig: Assertion,
    ) -> Result<Prepared, ServerError> {
        let id = node.content_id().map_err(enc)?;
        let epoch = self.chain.epoch_for(node.payload.kind);
        let (signer, conflict) = self.vet(node, &id, &sig, epoch)?;
        let sealed = seal(
            key,
            self.chain.prev,
            self.chain.next_index,
            epoch,
            node.clone(),
            sig,
        )?;
        let record_id = sealed.record.content_id().map_err(enc)?;
        Ok(Prepared {
            sealed,
            signer,
            conflict,
            id,
            record_id,
        })
    }

    /// Take a prepared admission (after it is durable) into the state.
    pub fn commit(&mut self, p: &Prepared) -> Result<(), ServerError> {
        let rec = &p.sealed.record.payload;
        self.apply(&p.sealed.event, p.signer.clone(), p.id, p.record_id, rec)
    }

    /// Verify one retained entry against the state so far, then take it in.
    pub fn replay(&mut self, sealed: &Sealed) -> Result<(), ServerError> {
        let (id, record_id) = verify_record(&self.chain, sealed)?;
        let rec = &sealed.record.payload;
        let (signer, _) = self.vet(&sealed.event, &id, &sealed.event_sig, rec.epoch)?;
        self.apply(&sealed.event, signer, id, record_id, rec)
    }

    fn apply(
        &mut self,
        node: &MerkleNode<Event>,
        signer: Signer,
        id: ContentId,
        record_id: ContentId,
        rec: &AdmissionRecord,
    ) -> Result<(), ServerError> {
        self.sessions
            .observe(id, &node.payload, rec.epoch)
            .map_err(ServerError::Session)?;
        self.board.apply(&LogEntry {
            node: node.clone(),
            signer,
        });
        self.chain.advance(record_id, rec);
        Ok(())
    }

    /// A server event chained after the server's previous one.
    pub fn server_event(
        &self,
        key: &AgentKey,
        spec: Spec,
    ) -> Result<(MerkleNode<Event>, Assertion), ServerError> {
        let author = key.fingerprint().hex();
        let node = Event {
            flock: self.board.flock(),
            kind: spec.kind,
            prev: self.board.head_of(&author),
            author,
            refs: spec
                .refs
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
            files: vec![],
            at: self.chain.next_index,
            body: spec.body,
        }
        .node();
        let sig = Assertion::sign(key, &node.content_id().map_err(enc)?);
        Ok((node, sig))
    }
}
