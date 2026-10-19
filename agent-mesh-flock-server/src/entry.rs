//! The entry points: invite, enroll, end a session, renew. Each is a plain
//! call here; the SSH stream that carries them is step 5.

use crate::frame::cert_cid;
use crate::server::Server;
use crate::sessions::{session_caveats, token_digest, InviteInfo, SessionInfo, Status};
use crate::state::{drops_member, Spec};
use crate::ServerError;
use agent_mesh_flock::{Body, EndReason, HandoffApproval, Kind, Member};
use agent_mesh_protocol::agent_key::PossessionChallenge;
use agent_mesh_protocol::Assertion;
use agent_mesh_protocol::{AgentMetadata, CertChain, Fingerprint};
use content_addressable::{ContentId, MerkleNode};
use ed25519_dalek::Signature;
use rand::rngs::OsRng;
use rand::RngCore;

/// What a challenge was issued for, and so what answering it may do.
pub(crate) enum Purpose {
    Enroll(InviteInfo),
    Renew { session: String, epoch: u64 },
}

/// A challenge the server issued and has not yet consumed.
pub(crate) struct Held {
    pub challenge: PossessionChallenge,
    pub purpose: Purpose,
}

/// A fresh invite. The token is shown once and never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invited {
    /// The bearer token.
    pub token: String,
    /// The `invite` event.
    pub event: ContentId,
}

/// A session the server has certified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    /// The session key's fingerprint, hex.
    pub session: String,
    /// Its certificate, bounded to the epoch it was issued in.
    pub cert: CertChain,
    /// A replacement session: it signs nothing until a hand-off.
    pub pending: bool,
}

fn refuse<T>(why: &str) -> Result<T, ServerError> {
    Err(ServerError::Session(why.into()))
}

impl Server {
    /// Record an invite for `member` and return its token. The event carries
    /// only the token's digest; the token itself is never stored, so neither
    /// the log nor the server can hand it out again.
    ///
    /// Who may ask for an invite (the roster role) is the caller's to
    /// establish: this is the server-side primitive the CLI wraps (step 7).
    ///
    /// # Errors
    /// The member is not on the roster, or I/O.
    pub fn invite(&mut self, member: &str) -> Result<Invited, ServerError> {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let token = hex::encode(raw);
        let ids = self.transact(vec![Spec {
            kind: Kind::Invite,
            refs: vec![],
            body: Body::Invite {
                member: member.to_owned(),
                verifier: token_digest(&token),
            },
        }])?;
        Ok(Invited {
            token,
            event: ids[0],
        })
    }

    /// Steps 2-3 of enrollment: a token, the member it claims and the
    /// session's public key. Only now does the server mint the possession
    /// challenge, bound to that key.
    ///
    /// # Errors
    /// Unknown, used or other-member token; a key already enrolled.
    pub fn enroll_begin(
        &mut self,
        token: &str,
        member: &str,
        pubkey: [u8; 32],
    ) -> Result<PossessionChallenge, ServerError> {
        let Some(invite) = self.st.sessions.invite(&token_digest(token)) else {
            return refuse("unknown invite token");
        };
        if invite.consumed {
            return refuse("invite token already consumed");
        }
        if invite.member != member {
            return refuse("invite token is for another member");
        }
        if self
            .st
            .sessions
            .get(&Fingerprint::of_bytes(&pubkey).hex())
            .is_some()
        {
            return refuse("key already enrolled");
        }
        Ok(self.issue(pubkey, Purpose::Enroll(invite)))
    }

    /// Step 4: consume the challenge, certify the key and admit
    /// `session-start`, which consumes the token, in one transaction.
    ///
    /// # Errors
    /// A challenge the server did not issue (or already used), a bad proof,
    /// a token consumed meanwhile.
    pub fn enroll_finish(
        &mut self,
        challenge: &PossessionChallenge,
        proof: &Signature,
    ) -> Result<Enrolled, ServerError> {
        let Purpose::Enroll(invite) = self.take(challenge)? else {
            return refuse("challenge was not issued for enrollment");
        };
        let cert = self.certify(challenge, proof, &invite.member)?;
        let session = cert.agent_fingerprint().hex();
        self.transact(vec![Spec {
            kind: Kind::SessionStart,
            refs: vec![("invite", invite.event)],
            body: Body::SessionStart {
                member: invite.member,
                session: session.clone(),
                cert: cert.clone(),
            },
        }])?;
        let pending = self
            .st
            .sessions
            .get(&session)
            .is_some_and(|s| s.status == Status::Pending);
        Ok(Enrolled {
            session,
            cert,
            pending,
        })
    }

    /// End `session` and bump the epoch: `session-end` then `epoch`, one
    /// frame, one fsync. Authority shrank, so every other certificate is now
    /// behind and must be renewed.
    ///
    /// # Errors
    /// No such live session, or I/O.
    pub fn end_session(&mut self, session: &str, reason: EndReason) -> Result<(), ServerError> {
        let Some(info) = self.live(session) else {
            return refuse("no such live session");
        };
        let next = self.st.chain.epoch + 1;
        self.transact(vec![
            Spec {
                kind: Kind::SessionEnd,
                refs: vec![("session", info.start)],
                body: Body::SessionEnd {
                    session: session.to_owned(),
                    reason,
                },
            },
            Spec {
                kind: Kind::Epoch,
                refs: vec![],
                body: Body::Epoch { epoch: next },
            },
        ])?;
        Ok(())
    }

    /// The renewal exchange after a bump: a challenge for every live session
    /// whose certificate is behind the epoch (the server sends each over that
    /// session's stream).
    pub fn renewal_challenges(&mut self) -> Vec<(String, PossessionChallenge)> {
        let epoch = self.st.chain.epoch;
        let due: Vec<_> = self
            .st
            .sessions
            .live()
            .filter(|(_, _, certified)| *certified < epoch)
            .map(|(s, pubkey, _)| (s.to_owned(), pubkey))
            .collect();
        due.into_iter()
            .map(|(session, pubkey)| {
                let purpose = Purpose::Renew {
                    session: session.clone(),
                    epoch,
                };
                (session, self.issue(pubkey, purpose))
            })
            .collect()
    }

    /// The `renew` entry: a session that missed bumps presents an earlier
    /// certificate and, if the log recorded it and the session has not ended,
    /// gets a challenge for the current epoch.
    ///
    /// # Errors
    /// An unknown certificate, an ended session, a session already current.
    pub fn renew_begin(&mut self, last: &CertChain) -> Result<PossessionChallenge, ServerError> {
        let session = last.agent_fingerprint().hex();
        let Some(info) = self.live(&session) else {
            return refuse("no such live session");
        };
        if !self.st.sessions.issued(&session, &cert_cid(last)?) {
            return refuse("not a certificate the log recorded for this session");
        }
        let epoch = self.st.chain.epoch;
        if info.epoch >= epoch {
            return refuse("session is already certified for this epoch");
        }
        Ok(self.issue(info.pubkey, Purpose::Renew { session, epoch }))
    }

    /// Answer a renewal challenge; the new certificate is logged in a
    /// `renewal` event.
    ///
    /// # Errors
    /// A challenge raced by a bump or a session end, a bad proof.
    pub fn renew_finish(
        &mut self,
        challenge: &PossessionChallenge,
        proof: &Signature,
    ) -> Result<CertChain, ServerError> {
        let Purpose::Renew { session, epoch } = self.take(challenge)? else {
            return refuse("challenge was not issued for renewal");
        };
        if epoch != self.st.chain.epoch {
            return refuse("the epoch moved since this challenge was issued");
        }
        let Some(info) = self.live(&session) else {
            return refuse("the session ended since this challenge was issued");
        };
        let cert = self.certify(challenge, proof, &info.member)?;
        self.transact(vec![Spec {
            kind: Kind::Renewal,
            refs: vec![("session", info.start)],
            body: Body::Renewal {
                session,
                epoch,
                cert: cert.clone(),
            },
        }])?;
        Ok(cert)
    }

    /// Record an operator device's certificate in the log, so an `answer` it
    /// signs verifies on replay. Registration grants no authority: the
    /// roster's `devices` decide which keys count.
    ///
    /// # Errors
    /// A certificate that is not a device certificate of this flock's user,
    /// one already registered, or I/O.
    pub fn register_device(&mut self, cert: CertChain) -> Result<ContentId, ServerError> {
        let ids = self.transact(vec![Spec {
            kind: Kind::DeviceCert,
            refs: vec![],
            body: Body::DeviceCert { cert },
        }])?;
        Ok(ids[0])
    }

    /// Replace the roster with a server-signed `roster` event. This is the
    /// only way operator `devices` change (the shepherd's roster events must
    /// leave them as they are).
    ///
    /// # Errors
    /// A roster the model refuses, or I/O.
    pub fn replace_roster(&mut self, members: Vec<Member>) -> Result<ContentId, ServerError> {
        let replaces = self.st.board.roster_id();
        let drops = drops_member(self.st.board.members(), &members);
        let mut specs = vec![Spec {
            kind: Kind::Roster,
            refs: vec![("replaces", replaces)],
            body: Body::Roster { members },
        }];
        if drops {
            specs.push(Spec {
                kind: Kind::Epoch,
                refs: vec![],
                body: Body::Epoch {
                    epoch: self.st.chain.epoch + 1,
                },
            });
        }
        let ids = self.transact(specs)?;
        Ok(ids[0])
    }

    /// Move a member's role from one session to another, on the roster
    /// authority's single-use approval: `handoff` then `epoch`, one frame.
    ///
    /// # Errors
    /// An approval that is not valid for this flock's current state, or I/O.
    pub fn handoff(
        &mut self,
        approval: MerkleNode<HandoffApproval>,
        sig: Assertion,
    ) -> Result<ContentId, ServerError> {
        let a = approval.payload.clone();
        let (Some(from), Some(to)) = (self.st.sessions.get(&a.from), self.st.sessions.get(&a.to))
        else {
            return refuse("handoff names an unknown session");
        };
        let next = self.st.chain.epoch + 1;
        let ids = self.transact(vec![
            Spec {
                kind: Kind::Handoff,
                refs: vec![("from", from.start), ("resume", a.resume), ("to", to.start)],
                body: Body::Handoff {
                    from: a.from,
                    to: a.to,
                    resume: a.resume,
                    context: a.context,
                    approval: Box::new(approval),
                    approval_sig: Box::new(sig),
                },
            },
            Spec {
                kind: Kind::Epoch,
                refs: vec![],
                body: Body::Epoch { epoch: next },
            },
        ])?;
        Ok(ids[0])
    }

    fn live(&self, session: &str) -> Option<SessionInfo> {
        self.st
            .sessions
            .get(session)
            .filter(|s| s.status != Status::Ended)
    }

    fn issue(&mut self, pubkey: [u8; 32], purpose: Purpose) -> PossessionChallenge {
        let challenge = self.key.possession_challenge(pubkey);
        self.challenges.insert(
            challenge.nonce,
            Held {
                challenge: challenge.clone(),
                purpose,
            },
        );
        challenge
    }

    /// Consume a challenge: it must be exactly one this server issued.
    fn take(&mut self, challenge: &PossessionChallenge) -> Result<Purpose, ServerError> {
        match self.challenges.remove(&challenge.nonce) {
            Some(held) if held.challenge == *challenge => Ok(held.purpose),
            _ => refuse("challenge was not issued by this server, or was already used"),
        }
    }

    /// Verify possession and mint a certificate bounded to the current epoch.
    fn certify(
        &self,
        challenge: &PossessionChallenge,
        proof: &Signature,
        member: &str,
    ) -> Result<CertChain, ServerError> {
        let server = self.key.cert();
        let meta = AgentMetadata {
            role: member.to_owned(),
            host: server.metadata.host.clone(),
            capabilities: vec![],
            issued_at: server.metadata.issued_at.clone(),
            expires_at: None,
            caveats: session_caveats(self.st.chain.epoch),
        };
        self.key
            .delegate_external(challenge, proof, meta)
            .map_err(|e| ServerError::Session(e.to_string()))
    }
}
