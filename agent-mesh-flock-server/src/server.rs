//! The server: one process, one log, one admission transaction at a time.

use crate::entry::Held;
use crate::frame::{Frame, Sealed};
use crate::init::{load_genesis, KEY_FILE, LOG_FILE, REFUSALS_FILE};
use crate::journal::Journal;
use crate::log::Log;
use crate::refusal::{Reason, RefusalEntry, RefusalRecord};
use crate::sessions::Sessions;
use crate::state::{drops_member, enc, rebuild_with, Spec, State};
use crate::{load_server_key, CrashPlan, ServerError};
use agent_mesh_flock::{Board, ConflictKind, Event, Genesis, Kind, Refusal, SignerClass};
use agent_mesh_protocol::{AgentKey, Assertion};
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

/// What an admission returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The event's admission index.
    pub index: u64,
    /// It was already admitted; nothing was written.
    pub duplicate: bool,
    /// Admitted as a conflict.
    pub conflict: Option<ConflictKind>,
}

/// An open flock server.
pub struct Server {
    pub(crate) key: AgentKey,
    genesis: MerkleNode<Genesis>,
    pub(crate) st: State,
    log: Log,
    refusal_log: Log,
    refusals: Vec<RefusalEntry>,
    refusal_prev: ContentId,
    /// Challenges the server issued and has not yet consumed. Volatile by
    /// design: a restart forgets them and the holder asks again.
    pub(crate) challenges: BTreeMap<[u8; 32], Held>,
    poisoned: bool,
    journal: Arc<Journal>,
}

impl Server {
    /// Open the flock in `dir`: re-verify genesis, load the key, lock the
    /// log, rebuild the board and the session table from the retained frames
    /// and only then cut a torn tail.
    ///
    /// # Errors
    /// [`ServerError::Locked`]; [`ServerError::Corrupt`] for damaged
    /// committed history or a chain that is not the server's.
    pub fn open(dir: &Path) -> Result<Self, ServerError> {
        let genesis = load_genesis(dir)?;
        let server_pub = genesis.node.payload.server_cert.agent_pubkey;
        let key = load_server_key(&dir.join(KEY_FILE))?;
        if key.cert() != &genesis.node.payload.server_cert {
            return Err(ServerError::BadFiles(
                "the key file is not the genesis server key".into(),
            ));
        }
        // Parse both files without touching them; verify everything retained;
        // only then cut a torn tail.
        let (mut log, frames) = Log::open::<Frame>(&dir.join(LOG_FILE))?;
        let (mut refusal_log, entries) = Log::open::<RefusalEntry>(&dir.join(REFUSALS_FILE))?;
        let mut sealed_frames: Vec<Vec<Sealed>> =
            frames.iter().map(|(_, f)| f.sealed.clone()).collect();
        sealed_frames.reverse();
        let mut published = Vec::new();
        let st = rebuild_with(&genesis.node, frames, |st| {
            if let Some(f) = sealed_frames.pop() {
                published.push((f, st.eligible()));
            }
        })?;
        let mut refusal_prev = st.board.flock();
        let mut last = 0;
        for (offset, entry) in &entries {
            refusal_prev = entry
                .verify(
                    &refusal_prev,
                    &server_pub,
                    st.chain.epoch,
                    last,
                    st.chain.next_index - 1,
                )
                .map_err(|e| ServerError::Corrupt {
                    offset: *offset,
                    why: e.to_string(),
                })?;
            last = entry.record.payload.admitted;
        }
        log.commit_recovery()?;
        refusal_log.commit_recovery()?;
        Ok(Self {
            key,
            genesis: genesis.node,
            st,
            log,
            refusal_log,
            refusals: entries.into_iter().map(|(_, e)| e).collect(),
            refusal_prev,
            challenges: BTreeMap::new(),
            poisoned: false,
            journal: Journal::new(published),
        })
    }

    /// The flock's genesis node: public, and what the flock id is the hash of.
    #[must_use]
    pub fn genesis(&self) -> &MerkleNode<Genesis> {
        &self.genesis
    }

    /// The published log, readable without this server's lock.
    #[must_use]
    pub fn journal(&self) -> Arc<Journal> {
        self.journal.clone()
    }

    /// Whether `proof` is an active session of a current member signing
    /// `challenge`: what opens a stream. Returns the session's fingerprint.
    ///
    /// # Errors
    /// A signature that does not resolve to a live, certified session; a
    /// pending or ended session; a member the roster no longer lists.
    pub fn authorize_stream(
        &self,
        proof: &Assertion,
        challenge: &ContentId,
    ) -> Result<String, ServerError> {
        let signer = self
            .st
            .sessions
            .resolve(
                proof,
                challenge,
                &self.st.chain.server_pub,
                self.st.chain.epoch,
            )
            .map_err(ServerError::Signer)?;
        match signer.class {
            SignerClass::Session {
                member,
                pending: false,
            } if self.st.board.members().iter().any(|m| m.name == member) => {
                Ok(signer.fingerprint.hex())
            }
            _ => Err(ServerError::Session(
                "a stream needs an active session of a current member".into(),
            )),
        }
    }

    /// Test-only: how many fsyncs the log has done.
    #[doc(hidden)]
    #[must_use]
    pub fn log_syncs(&self) -> u64 {
        self.log.syncs()
    }

    /// The admission index of `session`'s `session-start`, if it has one.
    #[must_use]
    pub fn session_start_index(&self, session: &str) -> Option<u64> {
        let start = self.st.sessions.get(session)?.start;
        self.st.board.get(&start).map(|e| e.index)
    }

    /// The flock id.
    #[must_use]
    pub fn flock(&self) -> ContentId {
        self.st.board.flock()
    }

    /// The derived board.
    #[must_use]
    pub fn board(&self) -> &Board {
        &self.st.board
    }

    /// The server's agent public key.
    #[must_use]
    pub fn server_pub(&self) -> [u8; 32] {
        self.st.chain.server_pub
    }

    /// The refusal audit chain, oldest first.
    #[must_use]
    pub fn refusals(&self) -> &[RefusalEntry] {
        &self.refusals
    }

    /// The latest admission record's id (the genesis id before any): what
    /// the next record must extend.
    #[must_use]
    pub fn head_record(&self) -> ContentId {
        self.st.chain.prev
    }

    /// How many events are admitted.
    #[must_use]
    pub fn admitted(&self) -> u64 {
        self.st.chain.next_index - 1
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.st.chain.epoch
    }

    /// Test-only: arm a crash for the next append.
    #[doc(hidden)]
    pub fn plan_crash(&mut self, plan: Option<CrashPlan>) {
        self.log.plan(plan);
    }

    /// The session table, derived from the log.
    #[must_use]
    pub fn sessions(&self) -> &Sessions {
        &self.st.sessions
    }

    /// One admission transaction: duplicate lookup, signer, the model's
    /// checks (writer chain, references, table), the session rules, then
    /// one frame and one fsync.
    ///
    /// # Errors
    /// [`ServerError::Signer`], [`ServerError::Refused`] (also journaled in
    /// the refusals file), [`ServerError::Session`], I/O. After an I/O
    /// failure the server stops.
    pub fn admit(
        &mut self,
        node: MerkleNode<Event>,
        sig: Assertion,
    ) -> Result<Receipt, ServerError> {
        if self.poisoned {
            return Err(ServerError::Poisoned);
        }
        let cid = node.content_id().map_err(enc)?;
        if let Some(done) = self.st.board.get(&cid) {
            return Ok(Receipt {
                index: done.index,
                duplicate: true,
                conflict: None,
            });
        }
        if matches!(node.payload.kind, Kind::SessionEnd | Kind::Handoff) {
            return Err(ServerError::Session(
                "session-end and handoff are admitted only with their epoch bump".into(),
            ));
        }
        let prepared = match self.st.prepare(&self.key, &node, sig) {
            Ok(p) => p,
            Err(ServerError::Refused(r)) => {
                self.record_refusal(&cid, &node, &r)?;
                return Err(ServerError::Refused(r));
            }
            Err(e) => return Err(e),
        };
        if !crate::wire::frame_fits(std::slice::from_ref(&prepared.sealed))? {
            let why = Refusal::TooLarge;
            self.record_refusal(&cid, &node, &why)?;
            return Err(ServerError::Refused(why));
        }
        if node.payload.kind == Kind::Roster {
            // A roster that drops a member is sealed with its epoch bump.
            let mut next = self.st.clone();
            next.commit(&prepared)?;
            if drops_member(self.st.board.members(), next.board.members()) {
                let epoch = next.chain.epoch + 1;
                let (en, es) = next.server_event(
                    &self.key,
                    Spec {
                        kind: Kind::Epoch,
                        refs: vec![],
                        body: agent_mesh_flock::Body::Epoch { epoch },
                    },
                )?;
                let bump = next.prepare(&self.key, &en, es)?;
                next.commit(&bump)?;
                let sealed = vec![prepared.sealed.clone(), bump.sealed];
                if !crate::wire::frame_fits(&sealed)? {
                    let why = Refusal::TooLarge;
                    self.record_refusal(&cid, &node, &why)?;
                    return Err(ServerError::Refused(why));
                }
                self.append(sealed.clone())?;
                self.st = next;
                self.journal.publish(sealed, self.st.eligible());
                return Ok(Receipt {
                    index: prepared.sealed.record.payload.index,
                    duplicate: false,
                    conflict: prepared.conflict,
                });
            }
        }
        self.append(vec![prepared.sealed.clone()])?;
        self.st.commit(&prepared)?;
        self.journal
            .publish(vec![prepared.sealed.clone()], self.st.eligible());
        Ok(Receipt {
            index: prepared.sealed.record.payload.index,
            duplicate: false,
            conflict: prepared.conflict,
        })
    }

    /// Server-authored events as one transaction: each is checked against the
    /// state the previous one left, then all go out in one frame with one
    /// fsync. A failure leaves the live state as it was.
    pub(crate) fn transact(&mut self, specs: Vec<Spec>) -> Result<Vec<ContentId>, ServerError> {
        if self.poisoned {
            return Err(ServerError::Poisoned);
        }
        let mut next = self.st.clone();
        let (mut sealed, mut ids) = (Vec::new(), Vec::new());
        for spec in specs {
            let (node, sig) = next.server_event(&self.key, spec)?;
            let p = next.prepare(&self.key, &node, sig)?;
            next.commit(&p)?;
            ids.push(p.id);
            sealed.push(p.sealed);
        }
        if !crate::wire::frame_fits(&sealed)? {
            return Err(ServerError::Session(
                "the frame would be too large to deliver to a watcher".into(),
            ));
        }
        self.append(sealed.clone())?;
        self.st = next;
        self.journal.publish(sealed, self.st.eligible());
        Ok(ids)
    }

    fn append(&mut self, sealed: Vec<Sealed>) -> Result<(), ServerError> {
        self.log.append(&Frame { sealed }).inspect_err(|_| {
            self.poisoned = true;
        })
    }

    /// Refused events stay out of the board and the admission index; each is
    /// signed into the refusal chain with one frame and one fsync.
    fn record_refusal(
        &mut self,
        cid: &ContentId,
        node: &MerkleNode<Event>,
        why: &Refusal,
    ) -> Result<(), ServerError> {
        let entry = RefusalEntry::sign(
            &self.key,
            self.refusal_prev,
            RefusalRecord {
                event: *cid,
                author: node.payload.author.clone(),
                reason: Reason::from(why),
                admitted: self.admitted(),
            },
        )?;
        if let Err(e) = self.refusal_log.append(&entry) {
            self.poisoned = true;
            return Err(e);
        }
        self.refusal_prev = entry.record.content_id().map_err(enc)?;
        self.refusals.push(entry);
        Ok(())
    }
}
