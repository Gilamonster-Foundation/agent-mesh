//! A flock in a temp dir. Every key is generated at runtime.
#![allow(dead_code)]

use agent_mesh_flock::{Body, Event, Kind, Member, Role};
use agent_mesh_flock_server::{init, load_server_key, InitSpec, Server, KEY_FILE, LOG_FILE};
use agent_mesh_protocol::agent_key::PossessionChallenge;
use agent_mesh_protocol::{AgentKey, AgentMetadata, Assertion, Caveats, CertChain, UserKey};
use content_addressable::{ContentAddressable, ContentId, MerkleNode, RawContentId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tempfile::TempDir;

pub const ROSTER: &[(&str, Role)] = &[
    ("shep", Role::Shepherd),
    ("h1", Role::Helper),
    ("herdr", Role::Adapter),
];

pub struct Env {
    pub tmp: TempDir,
    pub flock: ContentId,
    pub at: u64,
}

pub fn meta(role: &str) -> AgentMetadata {
    AgentMetadata {
        role: role.into(),
        host: "fixture".into(),
        capabilities: vec![],
        issued_at: "2026-10-15T00:00:00Z".into(),
        expires_at: None,
        caveats: Caveats::top(),
    }
}

pub fn spec() -> InitSpec {
    InitSpec {
        name: "fixture".into(),
        roster: ROSTER
            .iter()
            .map(|(n, r)| Member {
                name: (*n).into(),
                role: *r,
            })
            .collect(),
        salt: "s".into(),
        host: "fixture".into(),
        issued_at: "2026-10-15T00:00:00Z".into(),
    }
}

/// A session key held the way a session process holds it: the seed stays
/// here, the certificate comes from the server and is replaced on renewal.
pub struct Enrolment {
    pub sk: SigningKey,
    pub key: AgentKey,
    pub session: String,
    pub pending: bool,
}

impl Enrolment {
    pub fn prove(&self, ch: &PossessionChallenge) -> Signature {
        self.sk.sign(&ch.signing_bytes())
    }
    /// Take a renewed certificate.
    pub fn recertify(&mut self, cert: CertChain) {
        self.key = AgentKey::from_seed_and_cert(&self.sk.to_bytes(), cert).unwrap();
    }
}

/// Invite `member`, then enroll a fresh key through the two-step exchange.
pub fn enroll(server: &mut Server, member: &str) -> Enrolment {
    let invite = server.invite(member).unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let ch = server
        .enroll_begin(&invite.token, member, sk.verifying_key().to_bytes())
        .unwrap();
    let proof = sk.sign(&ch.signing_bytes());
    let done = server.enroll_finish(&ch, &proof).unwrap();
    let key = AgentKey::from_seed_and_cert(&sk.to_bytes(), done.cert).unwrap();
    Enrolment {
        sk,
        key,
        session: done.session,
        pending: done.pending,
    }
}

impl Env {
    pub fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let user = UserKey::generate();
        let flock = init(tmp.path(), &user, spec()).unwrap();
        Self { tmp, flock, at: 0 }
    }

    pub fn dir(&self) -> PathBuf {
        self.tmp.path().to_path_buf()
    }
    pub fn log_path(&self) -> PathBuf {
        self.tmp.path().join(LOG_FILE)
    }
    pub fn log_len(&self) -> u64 {
        std::fs::metadata(self.log_path()).unwrap().len()
    }
    pub fn open(&self) -> Server {
        Server::open(self.tmp.path()).unwrap()
    }
    pub fn server_key(&self) -> AgentKey {
        load_server_key(&self.tmp.path().join(KEY_FILE)).unwrap()
    }
    /// A session for `member`, enrolled through `server`.
    pub fn session(&self, server: &mut Server, member: &str) -> AgentKey {
        enroll(server, member).key
    }

    /// `key`'s event of `kind`, chained after `prev`, with its signature.
    pub fn event(
        &mut self,
        key: &AgentKey,
        kind: Kind,
        prev: Option<ContentId>,
        refs: &[(&str, ContentId)],
        body: Body,
    ) -> (MerkleNode<Event>, Assertion) {
        self.at += 1;
        let node = Event {
            flock: self.flock,
            kind,
            author: key.fingerprint().hex(),
            prev,
            refs: refs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), *v))
                .collect::<BTreeMap<_, _>>(),
            files: vec![],
            at: self.at,
            body,
        }
        .node();
        let sig = Assertion::sign(key, &node.content_id().unwrap());
        (node, sig)
    }

    /// A server-signed `invite` for `h1` whose verifier is `note`'s digest:
    /// the cheapest server event that needs no session.
    pub fn server_event(&mut self, note: &str) -> (MerkleNode<Event>, Assertion) {
        let key = self.server_key();
        self.event(
            &key,
            Kind::Invite,
            None,
            &[],
            Body::Invite {
                member: "h1".into(),
                verifier: RawContentId::from_content(note.as_bytes()),
            },
        )
    }

    pub fn brief(
        &mut self,
        key: &AgentKey,
        prev: Option<ContentId>,
        lane: &str,
    ) -> (MerkleNode<Event>, Assertion) {
        self.event(
            key,
            Kind::Brief,
            prev,
            &[],
            Body::Brief {
                to: "h1".into(),
                lane: lane.into(),
            },
        )
    }
}

pub fn id(node: &MerkleNode<Event>) -> ContentId {
    node.content_id().unwrap()
}

/// Every whole frame in the log file, decoded.
pub fn read_frames(env: &Env) -> Vec<agent_mesh_flock_server::Frame> {
    let bytes = std::fs::read(env.log_path()).unwrap();
    let mut at = 0;
    let mut out = Vec::new();
    while at < bytes.len() {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let payload = &bytes[at + 8..at + 8 + len];
        out.push(content_addressable::canonical::from_canonical_dagcbor_checked(payload).unwrap());
        at += 8 + len;
    }
    out
}

/// End `e`'s session and answer the renewal exchange for every other live
/// session in `others`, the way a connected session would.
pub fn bump_and_renew(server: &mut Server, ended: &Enrolment, others: &mut [&mut Enrolment]) {
    server
        .end_session(&ended.session, agent_mesh_flock::EndReason::Closed)
        .unwrap();
    for (session, ch) in server.renewal_challenges() {
        if let Some(e) = others.iter_mut().find(|e| e.session == session) {
            let cert = server.renew_finish(&ch, &e.prove(&ch)).unwrap();
            e.recertify(cert);
        }
    }
}
