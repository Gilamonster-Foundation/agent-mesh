//! The **revocation log**: a user-signed, append-only chain of
//! [`MerkleNode`]s naming revoked agents and generation bumps.
//!
//! Identity is the node's [`ContentId`]; each node is signed by the user named
//! in the genesis entry, over `REVOCATION_DOMAIN || cid_bytes` — the same
//! detached-signature shape as [`crate::Assertion`]. The JSON form of a
//! [`RevocationLog`] is a container only: nothing in it is trusted until
//! [`RevocationLog::verify`] recomputes every id and checks every signature.
//! See `docs/decisions/revocation.md`.

use std::collections::BTreeSet;

use content_addressable::{ContentId, MerkleNode};
use serde::{Deserialize, Serialize};

use crate::agent_key::{CertChain, Issuer, SerdeSig};
use crate::{Fingerprint, MeshError, Result, UserKey, UserPublic};

/// Domain tag: a revocation signature can't be replayed as any other signature.
const REVOCATION_DOMAIN: &[u8] = b"agent-mesh/revocation/v1\0";

/// One entry of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationEntry {
    /// First node only: names the user whose key signs the whole log.
    Genesis {
        /// The log's owner.
        user: UserPublic,
    },
    /// The agent with this key fingerprint is revoked, wherever it sits in a chain.
    Revoke {
        /// Fingerprint of the revoked agent's public key.
        agent: Fingerprint,
    },
    /// The current generation moves to `current`; certs scoped to older ones lapse.
    Generation {
        /// The new generation. Must exceed every earlier one (0 before any bump).
        current: u64,
    },
}

/// A log node and its detached signature (beside the node, never inside it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEntry {
    node: MerkleNode<RevocationEntry>,
    sig: SerdeSig,
}

/// The ordered, signed nodes of one user's revocation log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationLog {
    entries: Vec<SignedEntry>,
}

/// What a verified log says: who owns it, where it ends, what is revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationState {
    /// Fingerprint of the user that signed the log.
    pub user: Fingerprint,
    /// Id of the last node.
    pub head: ContentId,
    /// Number of nodes, genesis included.
    pub len: u64,
    /// Current generation (0 before any bump).
    pub generation: u64,
    /// Fingerprints of revoked agents.
    pub revoked: BTreeSet<Fingerprint>,
}

/// The head a consumer last saw and persisted, for rollback/fork detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// Fingerprint of the log's user.
    pub user: Fingerprint,
    /// Number of nodes seen.
    pub len: u64,
    /// Id of the last node seen.
    pub head: ContentId,
}

fn bad(msg: &str) -> MeshError {
    MeshError::RevocationState(msg.into())
}

fn message(cid: &ContentId) -> Vec<u8> {
    let mut m = REVOCATION_DOMAIN.to_vec();
    m.extend_from_slice(&cid.to_bytes());
    m
}

fn sign_node(user: &UserKey, node: MerkleNode<RevocationEntry>) -> Result<SignedEntry> {
    let id = node.id().map_err(|e| MeshError::Encoding(e.to_string()))?;
    Ok(SignedEntry {
        node,
        sig: SerdeSig(user.sign(&message(&id))),
    })
}

impl RevocationState {
    /// The [`Seen`] record a consumer should persist after accepting this state.
    #[must_use]
    pub fn seen(&self) -> Seen {
        Seen {
            user: self.user,
            len: self.len,
            head: self.head,
        }
    }
}

impl RevocationLog {
    /// A new log owned by `user`: just the signed genesis node.
    ///
    /// # Errors
    /// [`MeshError::Encoding`] if the node cannot be encoded.
    pub fn genesis(user: &UserKey) -> Result<Self> {
        let node = MerkleNode::genesis(RevocationEntry::Genesis {
            user: user.public(),
        });
        Ok(Self {
            entries: vec![sign_node(user, node)?],
        })
    }

    /// Append `entry`, signed by `user`, parented on the current head.
    ///
    /// # Errors
    /// [`MeshError::RevocationState`] if `user` does not own this log, the log
    /// is not valid, `entry` is a `Genesis`, or a `Generation` does not exceed
    /// the current one. Nothing is appended on error.
    pub fn append(&mut self, user: &UserKey, entry: RevocationEntry) -> Result<()> {
        let state = self.verify()?;
        if user.fingerprint() != state.user {
            return Err(bad("appending key is not the log's user"));
        }
        match &entry {
            RevocationEntry::Genesis { .. } => return Err(bad("genesis only starts a log")),
            RevocationEntry::Generation { current } if *current <= state.generation => {
                return Err(bad("generation must strictly increase"))
            }
            _ => {}
        }
        self.entries
            .push(sign_node(user, MerkleNode::new(entry, [state.head]))?);
        Ok(())
    }

    /// Check the whole log and fold it into a [`RevocationState`].
    ///
    /// Fail-closed: genesis first, each parent is the previous id, every
    /// signature verifies under the genesis user, generations strictly increase.
    ///
    /// # Errors
    /// [`MeshError::RevocationState`] for a structural break;
    /// [`MeshError::BadSignature`] for a signature that does not verify.
    pub fn verify(&self) -> Result<RevocationState> {
        let first = self.entries.first().ok_or_else(|| bad("missing genesis"))?;
        let RevocationEntry::Genesis { user } = first.node.payload() else {
            return Err(bad("first node is not a genesis"));
        };
        let mut state = RevocationState {
            user: user.fingerprint(),
            head: Self::check_link(user, first, None)?,
            len: 1,
            generation: 0,
            revoked: BTreeSet::new(),
        };
        for e in &self.entries[1..] {
            state.head = Self::check_link(user, e, Some(state.head))?;
            state.len += 1;
            match e.node.payload() {
                RevocationEntry::Genesis { .. } => return Err(bad("second genesis")),
                RevocationEntry::Revoke { agent } => {
                    state.revoked.insert(*agent);
                }
                RevocationEntry::Generation { current } => {
                    if *current <= state.generation {
                        return Err(bad("generation does not increase"));
                    }
                    state.generation = *current;
                }
            }
        }
        Ok(state)
    }

    /// One node: parents are exactly `{prev}` (none for genesis), signature good.
    /// Returns the node's recomputed id.
    fn check_link(
        user: &UserPublic,
        e: &SignedEntry,
        prev: Option<ContentId>,
    ) -> Result<ContentId> {
        if !e.node.parents().iter().copied().eq(prev) {
            return Err(bad("broken parent link"));
        }
        let id = e
            .node
            .id()
            .map_err(|err| MeshError::Encoding(err.to_string()))?;
        user.verify(&message(&id), &e.sig.0)?;
        Ok(id)
    }

    /// Refuse a log that is shorter than what the consumer `seen`, or whose
    /// node at that position is not the head they saw (a fork). A log that is
    /// itself invalid, or belongs to another user, is refused too.
    ///
    /// # Errors
    /// [`MeshError::RevocationState`] on rollback, fork, wrong user, or empty `seen`.
    pub fn extends(&self, seen: &Seen) -> Result<()> {
        let state = self.verify()?;
        if state.user != seen.user {
            return Err(bad("log belongs to a different user"));
        }
        if seen.len == 0 || state.len < seen.len {
            return Err(bad("log is shorter than what was seen (rollback)"));
        }
        let at = &self.entries[usize::try_from(seen.len - 1).map_err(|_| bad("seen too long"))?];
        let id = at
            .node
            .id()
            .map_err(|e| MeshError::Encoding(e.to_string()))?;
        if id != seen.head {
            return Err(bad("log forks from what was seen"));
        }
        Ok(())
    }
}

impl CertChain {
    /// Verify the chain, then check it against `state`: same user, **no link**
    /// (leaf or any delegating parent) revoked, and every link valid at
    /// `state.generation`. A chain scoped `Scope::All` ignores a generation
    /// bump; revoke such an agent per agent.
    ///
    /// # Errors
    /// [`MeshError::RevocationState`] for a different user;
    /// [`MeshError::Revoked`] if any link is revoked; otherwise whatever
    /// [`CertChain::verify_at`] returns.
    pub fn verify_with(&self, state: &RevocationState) -> Result<()> {
        if self.user_fingerprint() != state.user {
            return Err(bad("chain belongs to a different user"));
        }
        let mut link = self;
        loop {
            let agent = link.agent_fingerprint();
            if state.revoked.contains(&agent) {
                return Err(MeshError::Revoked { agent });
            }
            match &link.issuer {
                Issuer::User(_) => break,
                Issuer::Agent { parent, .. } => link = parent,
            }
        }
        self.verify_at(state.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentKey, AgentMetadata, Caveats, Scope};

    fn meta(caveats: Caveats) -> AgentMetadata {
        AgentMetadata {
            role: "r".into(),
            host: "h".into(),
            capabilities: vec![],
            issued_at: "2026-10-26T00:00:00Z".into(),
            expires_at: None,
            caveats,
        }
    }

    fn scoped(gen: u64) -> Caveats {
        let mut c = Caveats::top();
        c.valid_for_generation = Scope::Only([gen].into());
        c
    }

    fn revoke(user: &UserKey, log: &mut RevocationLog, k: &AgentKey) {
        let agent = k.fingerprint();
        log.append(user, RevocationEntry::Revoke { agent }).unwrap();
    }

    fn is_state_err(r: Result<impl std::fmt::Debug>) -> bool {
        matches!(r, Err(MeshError::RevocationState(_)))
    }

    #[test]
    fn fresh_log_verifies_and_accepts_chain() {
        let user = UserKey::generate();
        let log = RevocationLog::genesis(&user).unwrap();
        let st = log.verify().unwrap();
        assert_eq!((st.len, st.generation), (1, 0));
        let a = AgentKey::issue(&user, meta(Caveats::top()));
        a.cert().verify_with(&st).unwrap();
    }

    #[test]
    fn revoked_leaf_refused() {
        let user = UserKey::generate();
        let a = AgentKey::issue(&user, meta(Caveats::top()));
        let mut log = RevocationLog::genesis(&user).unwrap();
        revoke(&user, &mut log, &a);
        let err = a.cert().verify_with(&log.verify().unwrap()).unwrap_err();
        assert!(matches!(err, MeshError::Revoked { agent } if agent == a.fingerprint()));
    }

    #[test]
    fn revoked_parent_refuses_delegated_child() {
        let user = UserKey::generate();
        let parent = AgentKey::issue(&user, meta(Caveats::top()));
        let child = parent.delegate(meta(Caveats::top())).unwrap();
        let mut log = RevocationLog::genesis(&user).unwrap();
        revoke(&user, &mut log, &parent);
        let err = child
            .cert()
            .verify_with(&log.verify().unwrap())
            .unwrap_err();
        assert!(matches!(err, MeshError::Revoked { agent } if agent == parent.fingerprint()));
    }

    #[test]
    fn generation_bump_refuses_old_scope_but_not_all() {
        let user = UserKey::generate();
        let old = AgentKey::issue(&user, meta(scoped(0)));
        let all = AgentKey::issue(&user, meta(Caveats::top()));
        let mut log = RevocationLog::genesis(&user).unwrap();
        log.append(&user, RevocationEntry::Generation { current: 1 })
            .unwrap();
        let st = log.verify().unwrap();
        assert!(matches!(
            old.cert().verify_with(&st),
            Err(MeshError::Generation(_))
        ));
        all.cert().verify_with(&st).unwrap();
        AgentKey::issue(&user, meta(scoped(1)))
            .cert()
            .verify_with(&st)
            .unwrap();
    }

    #[test]
    fn chain_of_another_user_refused() {
        let user = UserKey::generate();
        let a = AgentKey::issue(&UserKey::generate(), meta(Caveats::top()));
        let st = RevocationLog::genesis(&user).unwrap().verify().unwrap();
        assert!(is_state_err(a.cert().verify_with(&st)));
    }

    #[test]
    fn log_signed_by_different_user_refused() {
        let user = UserKey::generate();
        let mut log = RevocationLog::genesis(&user).unwrap();
        let other = UserKey::generate();
        assert!(is_state_err(
            log.append(&other, RevocationEntry::Generation { current: 1 })
        ));
        // forged: node signed by someone else under the genesis user's name
        let node = MerkleNode::new(
            RevocationEntry::Generation { current: 1 },
            [log.verify().unwrap().head],
        );
        log.entries.push(sign_node(&other, node).unwrap());
        assert!(matches!(log.verify(), Err(MeshError::BadSignature)));
    }

    #[test]
    fn tampered_node_refused() {
        let user = UserKey::generate();
        let a = AgentKey::issue(&user, meta(Caveats::top()));
        let mut log = RevocationLog::genesis(&user).unwrap();
        revoke(&user, &mut log, &a);
        let b = AgentKey::issue(&user, meta(Caveats::top()));
        log.entries[1].node.payload = RevocationEntry::Revoke {
            agent: b.fingerprint(),
        };
        assert!(matches!(log.verify(), Err(MeshError::BadSignature)));
    }

    #[test]
    fn reordered_log_refused() {
        let user = UserKey::generate();
        let mut log = RevocationLog::genesis(&user).unwrap();
        for g in 1..=2 {
            log.append(&user, RevocationEntry::Generation { current: g })
                .unwrap();
        }
        log.entries.swap(1, 2);
        assert!(is_state_err(log.verify()));
    }

    #[test]
    fn non_increasing_generation_refused() {
        let user = UserKey::generate();
        let mut log = RevocationLog::genesis(&user).unwrap();
        log.append(&user, RevocationEntry::Generation { current: 2 })
            .unwrap();
        assert!(is_state_err(
            log.append(&user, RevocationEntry::Generation { current: 2 })
        ));
        // properly parented and signed, but not increasing
        let node = MerkleNode::new(
            RevocationEntry::Generation { current: 1 },
            [log.verify().unwrap().head],
        );
        log.entries.push(sign_node(&user, node).unwrap());
        assert!(is_state_err(log.verify()));
    }

    #[test]
    fn missing_genesis_refused() {
        let user = UserKey::generate();
        assert!(is_state_err(RevocationLog { entries: vec![] }.verify()));
        let mut log = RevocationLog::genesis(&user).unwrap();
        log.append(&user, RevocationEntry::Generation { current: 1 })
            .unwrap();
        log.entries.remove(0);
        assert!(is_state_err(log.verify()));
    }

    #[test]
    fn extends_refuses_shorter_and_forked_accepts_extension() {
        let user = UserKey::generate();
        let mut log = RevocationLog::genesis(&user).unwrap();
        let base = log.clone();
        log.append(&user, RevocationEntry::Generation { current: 1 })
            .unwrap();
        let seen = log.verify().unwrap().seen();
        assert!(is_state_err(base.extends(&seen)));
        let mut fork = base.clone();
        fork.append(&user, RevocationEntry::Generation { current: 7 })
            .unwrap();
        assert!(is_state_err(fork.extends(&seen)));
        let mut longer = log.clone();
        longer
            .append(&user, RevocationEntry::Generation { current: 2 })
            .unwrap();
        longer.extends(&seen).unwrap();
        log.extends(&seen).unwrap();
    }

    #[test]
    fn extends_refuses_other_user_and_json_roundtrips() {
        let user = UserKey::generate();
        let mut log = RevocationLog::genesis(&user).unwrap();
        log.append(&user, RevocationEntry::Generation { current: 1 })
            .unwrap();
        let mut seen = log.verify().unwrap().seen();
        let back: RevocationLog =
            serde_json::from_str(&serde_json::to_string(&log).unwrap()).unwrap();
        assert_eq!(back, log);
        back.verify().unwrap();
        seen.user = UserKey::generate().fingerprint();
        assert!(is_state_err(log.extends(&seen)));
    }
}
