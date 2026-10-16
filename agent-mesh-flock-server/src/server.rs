//! The server: one process, one log, one admission transaction at a time.

use crate::chain::{verify_entry, Chain};
use crate::frame::{seal, Frame};
use crate::init::{load_genesis, KEY_FILE, LOG_FILE, REFUSALS_FILE};
use crate::log::Log;
use crate::{load_server_key, CrashPlan, ServerError, SignerResolver};
use agent_mesh_flock::{admit, Board, ConflictKind, Event, LogEntry, Refusal, Signer, Verdict};
use agent_mesh_protocol::{AgentKey, Assertion};
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use std::io::Write;
use std::path::{Path, PathBuf};

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
    dir: PathBuf,
    key: AgentKey,
    board: Board,
    chain: Chain,
    log: Log,
    resolver: Box<dyn SignerResolver>,
    poisoned: bool,
}

fn enc(e: content_addressable::ContentError) -> ServerError {
    ServerError::Encoding(e.to_string())
}

impl Server {
    /// Open the flock in `dir`: re-verify genesis, load the key, lock the
    /// log, cut a torn tail and rebuild the board from the retained frames.
    ///
    /// # Errors
    /// [`ServerError::Locked`]; [`ServerError::Corrupt`] for damaged
    /// committed history or a chain that is not the server's.
    pub fn open(dir: &Path, resolver: Box<dyn SignerResolver>) -> Result<Self, ServerError> {
        let genesis = load_genesis(dir)?;
        let server_pub = genesis.node.payload.server_cert.agent_pubkey;
        let key = load_server_key(&dir.join(KEY_FILE))?;
        if key.cert() != &genesis.node.payload.server_cert {
            return Err(ServerError::BadFiles(
                "the key file is not the genesis server key".into(),
            ));
        }
        let (log, frames) = Log::open(&dir.join(LOG_FILE))?;
        let mut board = Board::new(&genesis.node).map_err(enc)?;
        let mut chain = Chain::new(board.flock(), server_pub);
        for (offset, frame) in frames {
            let corrupt = |why: String| ServerError::Corrupt { offset, why };
            if frame.sealed.is_empty() {
                return Err(corrupt("empty frame".into()));
            }
            for sealed in &frame.sealed {
                let signer = verify_entry(&chain, &board, sealed, &*resolver)
                    .map_err(|e| corrupt(e.to_string()))?;
                let entry = LogEntry {
                    node: sealed.event.clone(),
                    signer,
                };
                match board.apply(&entry) {
                    Verdict::Admit | Verdict::Conflict(_) => {}
                    other => return Err(corrupt(format!("replay: {other:?}"))),
                }
                chain.advance(
                    sealed.record.content_id().map_err(enc)?,
                    &sealed.record.payload,
                );
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            key,
            board,
            chain,
            log,
            resolver,
            poisoned: false,
        })
    }

    /// The flock id.
    #[must_use]
    pub fn flock(&self) -> ContentId {
        self.board.flock()
    }

    /// The derived board.
    #[must_use]
    pub fn board(&self) -> &Board {
        &self.board
    }

    /// The server's agent public key.
    #[must_use]
    pub fn server_pub(&self) -> [u8; 32] {
        self.chain.server_pub
    }

    /// The latest admission record's id (the genesis id before any): what
    /// the next record must extend.
    #[must_use]
    pub fn head_record(&self) -> ContentId {
        self.chain.prev
    }

    /// How many events are admitted.
    #[must_use]
    pub fn admitted(&self) -> u64 {
        self.chain.next_index - 1
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.chain.epoch
    }

    /// Test-only: arm a crash for the next append.
    #[doc(hidden)]
    pub fn plan_crash(&mut self, plan: Option<CrashPlan>) {
        self.log.plan(plan);
    }

    /// One admission transaction: duplicate lookup, signer class, then the
    /// model's checks (writer chain, references, table), then one frame and
    /// one fsync.
    ///
    /// # Errors
    /// [`ServerError::Signer`], [`ServerError::Refused`] (also journaled in
    /// the refusals file), I/O. After an I/O failure the server stops.
    pub fn admit(
        &mut self,
        node: MerkleNode<Event>,
        sig: Assertion,
    ) -> Result<Receipt, ServerError> {
        if self.poisoned {
            return Err(ServerError::Poisoned);
        }
        let cid = node.content_id().map_err(enc)?;
        if let Some(done) = self.board.get(&cid) {
            return Ok(Receipt {
                index: done.index,
                duplicate: true,
                conflict: None,
            });
        }
        let signer: Signer = self
            .resolver
            .resolve(
                &self.board,
                &self.chain.server_pub,
                &sig,
                &cid,
                self.chain.epoch,
            )
            .map_err(ServerError::Signer)?;
        let conflict = match admit(&self.board, &node, &signer) {
            Verdict::Admit => None,
            Verdict::Conflict(c) => Some(c),
            Verdict::Duplicate(index) => {
                return Ok(Receipt {
                    index,
                    duplicate: true,
                    conflict: None,
                })
            }
            Verdict::Refuse(r) => {
                self.journal_refusal(&cid, &node, &r)?;
                return Err(ServerError::Refused(r));
            }
        };
        let epoch = self.chain.epoch_for(node.payload.kind);
        let index = self.chain.next_index;
        let sealed = seal(&self.key, self.chain.prev, index, epoch, node.clone(), sig)?;
        let record_id = sealed.record.content_id().map_err(enc)?;
        let record = sealed.record.payload.clone();
        if let Err(e) = self.log.append(&Frame {
            sealed: vec![sealed],
        }) {
            self.poisoned = true;
            return Err(e);
        }
        self.chain.advance(record_id, &record);
        self.board.apply(&LogEntry { node, signer });
        Ok(Receipt {
            index,
            duplicate: false,
            conflict,
        })
    }

    /// Refused events are not in the signed chain; they are kept in a
    /// side journal so a fork attempt can be seen.
    fn journal_refusal(
        &self,
        cid: &ContentId,
        node: &MerkleNode<Event>,
        why: &Refusal,
    ) -> Result<(), ServerError> {
        let line = serde_json::json!({
            "event": cid.to_string(),
            "author": node.payload.author,
            "refusal": format!("{why:?}"),
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(REFUSALS_FILE))?;
        writeln!(f, "{line}")?;
        f.sync_data()?;
        Ok(())
    }
}
