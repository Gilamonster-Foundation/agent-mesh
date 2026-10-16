//! A flock in a temp dir. Every key is generated at runtime.
#![allow(dead_code)]

use agent_mesh_flock::{Board, Body, Event, Kind, Member, Role, Signer, SignerClass};
use agent_mesh_flock_server::{
    init, load_server_key, InitSpec, Server, ServerOnly, SignerResolver, KEY_FILE, LOG_FILE,
};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Assertion, Caveats, Fingerprint, UserKey};
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

pub const ROSTER: &[(&str, Role)] = &[
    ("shep", Role::Shepherd),
    ("h1", Role::Helper),
    ("herdr", Role::Adapter),
];

pub struct Env {
    pub tmp: TempDir,
    pub flock: ContentId,
    pub sessions: Sessions,
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

/// Test session table: member sessions certified by the server, plus flags.
/// fingerprint hex -> (member, pending, ended)
type Table = HashMap<String, (String, bool, bool)>;

#[derive(Clone, Default)]
pub struct Sessions(Arc<Mutex<Table>>);

impl Sessions {
    pub fn add(&self, key: &AgentKey, member: &str, pending: bool) {
        self.0
            .lock()
            .unwrap()
            .insert(key.fingerprint().hex(), (member.into(), pending, false));
    }
    pub fn end(&self, key: &AgentKey) {
        if let Some(s) = self.0.lock().unwrap().get_mut(&key.fingerprint().hex()) {
            s.2 = true;
        }
    }
}

impl SignerResolver for Sessions {
    fn resolve(
        &self,
        board: &Board,
        server_pub: &[u8; 32],
        sig: &Assertion,
        event: &ContentId,
        epoch: u64,
    ) -> Result<Signer, String> {
        let fp = Fingerprint::of_bytes(&sig.author().agent_pubkey);
        if &sig.author().agent_pubkey == server_pub {
            return ServerOnly.resolve(board, server_pub, sig, event, epoch);
        }
        sig.verify(event, server_pub, epoch)
            .map_err(|e| e.to_string())?;
        match self.0.lock().unwrap().get(&fp.hex()) {
            Some((_, _, true)) => Err("session ended".into()),
            Some((member, pending, false)) => Ok(Signer {
                fingerprint: fp,
                class: SignerClass::Session {
                    member: member.clone(),
                    pending: *pending,
                },
            }),
            None => Err("unknown session".into()),
        }
    }
}

impl Env {
    pub fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let user = UserKey::generate();
        let flock = init(tmp.path(), &user, spec()).unwrap();
        Self {
            tmp,
            flock,
            sessions: Sessions::default(),
            at: 0,
        }
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
        Server::open(self.tmp.path(), Box::new(self.sessions.clone())).unwrap()
    }
    pub fn server_key(&self) -> AgentKey {
        load_server_key(&self.tmp.path().join(KEY_FILE)).unwrap()
    }
    /// A session key certified by the server, registered in the table.
    pub fn session(&self, member: &str, pending: bool) -> AgentKey {
        let key = self.server_key().delegate(meta(member)).unwrap();
        self.sessions.add(&key, member, pending);
        key
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

    /// A server-signed bookkeeping event (`invite`), the one kind step 3 can
    /// admit without a session table.
    pub fn server_event(&mut self, note: &str) -> (MerkleNode<Event>, Assertion) {
        let key = self.server_key();
        self.event(
            &key,
            Kind::Invite,
            None,
            &[],
            Body::Server { note: note.into() },
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
