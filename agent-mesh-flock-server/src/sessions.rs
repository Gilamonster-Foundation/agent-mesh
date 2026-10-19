//! The session table, derived from the admitted log in replay order.
//!
//! Nothing here is stored: every reader that folds the same log in the same
//! order gets the same table, so a session that ended at index 9 was still a
//! session at index 8. Two questions are answered from it: who signed an
//! event ([`Sessions::resolve`]) and whether a server event is legal given
//! what came before ([`Sessions::check`]).

use crate::chain::Chain;
use crate::frame::cert_cid;
use agent_mesh_flock::{Board, Body, Event, Role, Signer, SignerClass};
use agent_mesh_protocol::{Assertion, Caveats, CertChain, Issuer, Scope, UserPublic};
use content_addressable::{ContentAddressable, ContentId, RawContentId};
use std::collections::{BTreeMap, BTreeSet};

/// Where a session stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// May sign.
    Active,
    /// A replacement: signs nothing until a hand-off activates it.
    Pending,
    /// Over. Never renewed, never signs.
    Ended,
}

#[derive(Debug, Clone)]
struct Session {
    member: String,
    pubkey: [u8; 32],
    start: ContentId,
    status: Status,
    certs: BTreeSet<ContentId>,
    epoch: u64,
    /// The `handoff` that activated it: its first event must have it as `prev`.
    activated_by: Option<ContentId>,
}

#[derive(Debug, Clone)]
struct Invite {
    member: String,
    consumed: bool,
}

/// An invite as the server looks it up by token digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteInfo {
    /// The `invite` event.
    pub event: ContentId,
    /// The member it enrolls.
    pub member: String,
    /// A `session-start` already consumed it.
    pub consumed: bool,
}

/// A live session as the server renews it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The member.
    pub member: String,
    /// Its public key.
    pub pubkey: [u8; 32],
    /// Its `session-start` event.
    pub start: ContentId,
    /// Its status.
    pub status: Status,
    /// The epoch of its latest certificate.
    pub epoch: u64,
}

/// Invites and sessions, rebuilt from the log.
#[derive(Debug, Clone, Default)]
pub struct Sessions {
    invites: BTreeMap<ContentId, Invite>,
    verifiers: BTreeMap<RawContentId, ContentId>,
    sessions: BTreeMap<String, Session>,
    seen: BTreeSet<String>,
    /// The session that holds each member's role (set by the first
    /// session and moved only by a hand-off; an ended holder still holds).
    holders: BTreeMap<String, String>,
    /// Approvals already consumed by a hand-off.
    approvals: BTreeSet<ContentId>,
    /// Every certificate a `session-start` or `renewal` put in the log, by
    /// the id a record cites it with.
    chains: BTreeMap<ContentId, CertChain>,
}

impl Sessions {
    /// The certificate chain the log recorded under `cid`.
    #[must_use]
    pub fn cert(&self, cid: &ContentId) -> Option<&CertChain> {
        self.chains.get(cid)
    }
}

/// The digest an `invite` event carries for a bearer token.
#[must_use]
pub fn token_digest(token: &str) -> RawContentId {
    RawContentId::from_content(token.as_bytes())
}

/// What a session certificate must be: `top`, bounded to `epoch`.
fn bounded(epoch: u64) -> Caveats {
    Caveats {
        valid_for_generation: Scope::only([epoch]),
        ..Caveats::top()
    }
}

/// The metadata caveats for a session certificate valid at `epoch` only.
#[must_use]
pub fn session_caveats(epoch: u64) -> Caveats {
    bounded(epoch)
}

fn cert_ok(cert: &CertChain, session: &str, epoch: u64, server: &[u8; 32]) -> Result<(), String> {
    if cert.agent_fingerprint().hex() != session {
        return Err("certificate is for another key".into());
    }
    cert.verify_at(epoch)
        .map_err(|e| format!("certificate: {e}"))?;
    match &cert.issuer {
        Issuer::Agent { pubkey, .. } if pubkey == server => {}
        _ => return Err("certificate is not issued by the server key".into()),
    }
    if cert.metadata.caveats != bounded(epoch) {
        return Err("certificate is not bounded to this epoch alone".into());
    }
    Ok(())
}

fn refs_are(ev: &Event, want: &[(&str, ContentId)]) -> Result<(), String> {
    let got: Vec<_> = ev.refs.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    if got == want {
        Ok(())
    } else {
        Err("references are not the ones this event takes".into())
    }
}

impl Sessions {
    /// Who signed `event`: the server, or a session that is not ended, with
    /// a certificate valid at `epoch`.
    ///
    /// # Errors
    /// Why the signature is not acceptable.
    pub fn resolve(
        &self,
        sig: &Assertion,
        event: &ContentId,
        server: &[u8; 32],
        user: &UserPublic,
        epoch: u64,
    ) -> Result<Signer, String> {
        let fingerprint = sig.author().agent_fingerprint();
        let class = if &sig.author().agent_pubkey == server {
            SignerClass::Server
        } else if matches!(sig.author().issuer, Issuer::User(_)) {
            // an operator device: certified directly by the flock's user key
            // and registered in the log, so replay can find the certificate.
            // Whether the roster lists it is the admission table's question.
            let presented = cert_cid(sig.author()).map_err(|e| e.to_string())?;
            if !self.chains.contains_key(&presented) {
                return Err("device certificate is not registered in the log".into());
            }
            sig.verify_user(event, user, epoch)
                .map_err(|e| e.to_string())?;
            return Ok(Signer {
                fingerprint,
                class: SignerClass::Operator,
            });
        } else {
            let s = self
                .sessions
                .get(&fingerprint.hex())
                .ok_or("not a session of this flock")?;
            if s.status == Status::Ended {
                return Err("session ended".into());
            }
            // only a certificate the log recorded for this session (its
            // session-start or a renewal): a peer cannot certify it
            let presented = cert_cid(sig.author()).map_err(|e| e.to_string())?;
            if !s.certs.contains(&presented) {
                return Err("certificate was not issued to this session by the server".into());
            }
            SignerClass::Session {
                member: s.member.clone(),
                pending: s.status == Status::Pending,
            }
        };
        sig.verify(event, server, epoch)
            .map_err(|e| e.to_string())?;
        Ok(Signer { fingerprint, class })
    }

    /// Whether a server event is legal now, at record epoch `epoch`.
    ///
    /// # Errors
    /// Why it is not.
    pub fn check(
        &self,
        board: &Board,
        ev: &Event,
        epoch: u64,
        chain: &Chain,
    ) -> Result<(), String> {
        let server = &chain.server_pub;
        let live = |session: &str| {
            self.sessions
                .get(session)
                .filter(|s| s.status != Status::Ended)
                .ok_or_else(|| String::from("no such live session"))
        };
        match &ev.body {
            Body::Invite { member, verifier } => {
                if !board.members().iter().any(|m| &m.name == member) {
                    return Err("invite for a member not on the roster".into());
                }
                refs_are(ev, &[])?;
                if self.verifiers.contains_key(verifier) {
                    return Err("invite verifier already in the log".into());
                }
            }
            Body::SessionStart {
                member,
                session,
                cert,
            } => {
                let (id, invite) = ev
                    .refs
                    .get("invite")
                    .and_then(|id| self.invites.get(id).map(|i| (*id, i)))
                    .ok_or("session-start names no known invite")?;
                refs_are(ev, &[("invite", id)])?;
                if invite.consumed {
                    return Err("invite already consumed".into());
                }
                if &invite.member != member {
                    return Err("invite is for another member".into());
                }
                if self.sessions.contains_key(session) {
                    return Err("session key already enrolled".into());
                }
                cert_ok(cert, session, epoch, server)?;
            }
            Body::SessionEnd { session, .. } => {
                let s = live(session)?;
                refs_are(ev, &[("session", s.start)])?;
            }
            Body::Epoch { epoch: e } => {
                refs_are(ev, &[])?;
                if *e != epoch {
                    return Err("epoch body is not the record epoch".into());
                }
            }
            Body::Renewal {
                session,
                epoch: e,
                cert,
            } => {
                let s = live(session)?;
                refs_are(ev, &[("session", s.start)])?;
                if *e != epoch {
                    return Err("renewal is not for the current epoch".into());
                }
                if s.epoch >= epoch {
                    return Err("session is already certified for this epoch".into());
                }
                cert_ok(cert, session, epoch, server)?;
            }
            Body::DeviceCert { cert } => {
                refs_are(ev, &[])?;
                match &cert.issuer {
                    Issuer::User(u) if *u == chain.user => {}
                    _ => return Err("not a device certificate of this flock's user".into()),
                }
                if &cert.agent_pubkey == server {
                    return Err("the server key is not an operator device".into());
                }
                cert.verify_at(epoch)
                    .map_err(|e| format!("certificate: {e}"))?;
                let cid = cert_cid(cert).map_err(|e| e.to_string())?;
                if self.chains.contains_key(&cid) {
                    return Err("device certificate already registered".into());
                }
            }
            Body::Handoff {
                from,
                to,
                resume,
                context,
                approval,
                approval_sig,
            } => {
                let ap_id = approval.content_id().map_err(|e| e.to_string())?;
                let a = &approval.payload;
                if !approval.parents.is_empty() || a.flock != board.flock() {
                    return Err("approval is not for this flock".into());
                }
                if (&a.from, &a.to, &a.resume, &a.context) != (from, to, resume, context) {
                    return Err("handoff differs from the approval it cites".into());
                }
                if a.context.is_none() {
                    return Err("handoff cites no context file".into());
                }
                if self.approvals.contains(&ap_id) {
                    return Err("approval already consumed".into());
                }
                let (Some(f), Some(t)) = (self.sessions.get(from), self.sessions.get(to)) else {
                    return Err("handoff names an unknown session".into());
                };
                if f.member != a.member || t.member != a.member {
                    return Err("sessions do not belong to the approved member".into());
                }
                if self.holders.get(&a.member) != Some(from) {
                    return Err("from is not the member's current holder".into());
                }
                if t.status != Status::Pending {
                    return Err("to is not a pending replacement".into());
                }
                if *resume != board.head_of(from).unwrap_or(f.start) {
                    return Err("resume is not the old session's last head".into());
                }
                refs_are(
                    ev,
                    &[("from", f.start), ("resume", *resume), ("to", t.start)],
                )?;
                let role = board
                    .members()
                    .iter()
                    .find(|m| m.name == a.member)
                    .map(|m| m.role)
                    .ok_or("member is not on the roster")?;
                self.approver_ok(role, board, &ap_id, approval_sig, chain, epoch)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// The roster's hand-off authority signed it: an active shepherd session
    /// for a helper, or a listed operator device for a shepherd. Everything
    /// else fails closed. A key merely certified by the flock's user key is
    /// not a device; the roster at this point in the log must list it.
    fn approver_ok(
        &self,
        role: Role,
        board: &Board,
        ap_id: &ContentId,
        sig: &Assertion,
        chain: &Chain,
        epoch: u64,
    ) -> Result<(), String> {
        if matches!(sig.author().issuer, Issuer::User(_)) {
            let fp = sig.author().agent_fingerprint();
            if !board
                .members()
                .iter()
                .any(|m| m.role == Role::Operator && m.devices.contains(&fp))
            {
                return Err(
                    "key is certified by the flock's user but is not a listed operator device"
                        .into(),
                );
            }
            sig.verify_user(ap_id, &chain.user, epoch)
                .map_err(|e| format!("approval: {e}"))?;
            return if role == Role::Shepherd {
                Ok(())
            } else {
                Err("an operator device approves a shepherd hand-off only".into())
            };
        }
        let signer = self.resolve(sig, ap_id, &chain.server_pub, &chain.user, epoch)?;
        let SignerClass::Session {
            member,
            pending: false,
        } = signer.class
        else {
            return Err("approval is not signed by a roster authority".into());
        };
        let approver_role = board
            .members()
            .iter()
            .find(|m| m.name == member)
            .map(|m| m.role);
        if approver_role == Some(Role::Shepherd) && role == Role::Helper {
            Ok(())
        } else {
            Err("only a shepherd approves a hand-off, and only a helper's".into())
        }
    }

    /// What `session`'s next event must have as `prev`: its own head, or, before
    /// its first event, the hand-off that activated it.
    #[must_use]
    pub fn chain_head(&self, board: &Board, session: &str) -> Option<ContentId> {
        board
            .head_of(session)
            .or_else(|| self.sessions.get(session)?.activated_by)
    }

    /// A session's first event. One a hand-off activated writes exactly that
    /// hand-off as `prev`, so a zombie cannot fork the chain; one no hand-off
    /// activated writes no `prev`, so it cannot claim a causal link to a
    /// hand-off that was not its own.
    ///
    /// # Errors
    /// The first event does not follow the rule.
    pub fn first_link(&self, board: &Board, ev: &Event) -> Result<(), String> {
        let Some(session) = self.sessions.get(&ev.author) else {
            return Ok(());
        };
        if board.head_of(&ev.author).is_some() {
            return Ok(());
        }
        match (session.activated_by, ev.prev) {
            (Some(h), prev) if prev != Some(h) => {
                Err("the first event after a hand-off must have prev = the handoff".into())
            }
            (None, Some(_)) => Err(
                "a session no hand-off activated cannot chain its first event onto a hand-off"
                    .into(),
            ),
            _ => Ok(()),
        }
    }

    /// Record an admitted server event. Call only after [`Self::check`].
    ///
    /// # Errors
    /// A certificate that cannot be encoded.
    pub fn observe(&mut self, id: ContentId, ev: &Event, epoch: u64) -> Result<(), String> {
        match &ev.body {
            Body::Invite { member, verifier } => {
                self.verifiers.insert(*verifier, id);
                self.invites.insert(
                    id,
                    Invite {
                        member: member.clone(),
                        consumed: false,
                    },
                );
            }
            Body::SessionStart {
                member,
                session,
                cert,
            } => {
                if let Some(i) = ev.refs.get("invite").and_then(|i| self.invites.get_mut(i)) {
                    i.consumed = true;
                }
                let status = if self.seen.insert(member.clone()) {
                    self.holders.insert(member.clone(), session.clone());
                    Status::Active
                } else {
                    Status::Pending
                };
                let cid = cert_cid(cert).map_err(|e| e.to_string())?;
                self.chains.insert(cid, cert.clone());
                let certs = BTreeSet::from([cid]);
                self.sessions.insert(
                    session.clone(),
                    Session {
                        member: member.clone(),
                        pubkey: cert.agent_pubkey,
                        start: id,
                        status,
                        certs,
                        epoch,
                        activated_by: None,
                    },
                );
            }
            Body::SessionEnd { session, .. } => {
                if let Some(s) = self.sessions.get_mut(session) {
                    s.status = Status::Ended;
                }
            }
            Body::Handoff {
                from, to, approval, ..
            } => {
                self.approvals
                    .insert(approval.content_id().map_err(|e| e.to_string())?);
                if let Some(s) = self.sessions.get_mut(from) {
                    s.status = Status::Ended;
                }
                if let Some(s) = self.sessions.get_mut(to) {
                    s.status = Status::Active;
                    s.activated_by = Some(id);
                    self.holders.insert(s.member.clone(), to.clone());
                }
            }
            Body::DeviceCert { cert } => {
                let cid = cert_cid(cert).map_err(|e| e.to_string())?;
                self.chains.insert(cid, cert.clone());
            }
            Body::Renewal {
                session,
                epoch,
                cert,
            } => {
                if let Some(s) = self.sessions.get_mut(session) {
                    let cid = cert_cid(cert).map_err(|e| e.to_string())?;
                    self.chains.insert(cid, cert.clone());
                    s.certs.insert(cid);
                    s.epoch = *epoch;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The invite a token digest names.
    #[must_use]
    pub fn invite(&self, verifier: &RawContentId) -> Option<InviteInfo> {
        let event = *self.verifiers.get(verifier)?;
        let i = self.invites.get(&event)?;
        Some(InviteInfo {
            event,
            member: i.member.clone(),
            consumed: i.consumed,
        })
    }

    /// One session.
    #[must_use]
    pub fn get(&self, session: &str) -> Option<SessionInfo> {
        self.sessions.get(session).map(|s| SessionInfo {
            member: s.member.clone(),
            pubkey: s.pubkey,
            start: s.start,
            status: s.status,
            epoch: s.epoch,
        })
    }

    /// Whether `cert` is one the log recorded for `session`.
    #[must_use]
    pub fn issued(&self, session: &str, cert: &ContentId) -> bool {
        self.sessions
            .get(session)
            .is_some_and(|s| s.certs.contains(cert))
    }

    /// Every session that has not ended: fingerprint, public key and the
    /// epoch of its latest certificate.
    pub fn live(&self) -> impl Iterator<Item = (&str, [u8; 32], u64)> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.status != Status::Ended)
            .map(|(k, s)| (k.as_str(), s.pubkey, s.epoch))
    }
}
