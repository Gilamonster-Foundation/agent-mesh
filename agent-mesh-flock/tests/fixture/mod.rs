//! A flock for the table tests: a generated user key, derived agent keys, a
//! roster of one member per role. Nothing here is key-independent-pinned.
#![allow(dead_code)]

use agent_mesh_flock::{
    Board, Body, Event, Genesis, Kind, LogEntry, Member, Role, Signer, SignerClass, Verdict,
};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, Fingerprint, UserKey};
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use std::collections::BTreeMap;

pub const ROSTER: &[(&str, Role)] = &[
    ("shep", Role::Shepherd),
    ("rev", Role::Reviewer),
    ("h1", Role::Helper),
    ("h2", Role::Helper),
    ("herdr", Role::Adapter),
];

pub struct Fx {
    pub user: UserKey,
    pub server: AgentKey,
    pub genesis: MerkleNode<Genesis>,
    pub flock: ContentId,
    pub board: Board,
    pub log: Vec<LogEntry>,
    pub at: u64,
}

/// A fresh user key per fixture: test keys are generated in memory.
pub fn user() -> UserKey {
    UserKey::generate()
}

fn issue(user: &UserKey, label: &str) -> AgentKey {
    AgentKey::issue_derived(
        user,
        label,
        AgentMetadata {
            role: label.into(),
            host: "fixture".into(),
            capabilities: vec![],
            issued_at: "2026-10-15T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    )
}

pub fn genesis_of(server: &AgentKey, op: Fingerprint) -> MerkleNode<Genesis> {
    Genesis {
        kind: "genesis".into(),
        name: "fixture".into(),
        server_cert: server.cert().clone(),
        roster: ROSTER
            .iter()
            .map(|(n, r)| Member {
                name: (*n).into(),
                role: *r,
                devices: vec![],
                delegate: false,
            })
            // the operator, whose one device is the fixture's "op" key
            .chain([Member {
                name: "op".into(),
                role: Role::Operator,
                devices: vec![op],
                delegate: false,
            }])
            .collect(),
        salt: "s".into(),
    }
    .node()
}

impl Fx {
    pub fn new() -> Self {
        let user = user();
        let server = issue(&user, "server");
        let genesis = genesis_of(&server, issue(&user, "op").fingerprint());
        let board = Board::new(&genesis).unwrap();
        let flock = board.flock();
        Self {
            user,
            server,
            genesis,
            flock,
            board,
            log: Vec::new(),
            at: 0,
        }
    }

    pub fn key(&self, who: &str) -> AgentKey {
        issue(&self.user, who)
    }

    pub fn fp(&self, who: &str) -> String {
        self.key(who).fingerprint().hex()
    }

    pub fn signer(&self, who: &str, pending: bool) -> Signer {
        let class = match who {
            "server" => SignerClass::Server,
            "op" => SignerClass::Operator,
            m => SignerClass::Session {
                member: m.into(),
                pending,
            },
        };
        Signer {
            fingerprint: self.key(who).fingerprint(),
            class,
        }
    }

    /// An event by `who` chained to their current head.
    pub fn event(
        &mut self,
        who: &str,
        kind: Kind,
        body: Body,
        refs: &[(&str, ContentId)],
    ) -> Event {
        self.at += 1;
        let author = self.fp(who);
        Event {
            flock: self.flock,
            kind,
            author: author.clone(),
            prev: if who == "op" {
                None
            } else {
                self.board.head_of(&author)
            },
            refs: refs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), *v))
                .collect::<BTreeMap<_, _>>(),
            files: vec![],
            at: self.at,
            body,
        }
    }

    /// Ask the table without recording.
    pub fn judge(
        &mut self,
        who: &str,
        kind: Kind,
        body: Body,
        refs: &[(&str, ContentId)],
    ) -> Verdict {
        let node = self.event(who, kind, body, refs).node();
        agent_mesh_flock::admit(&self.board, &node, &self.signer(who, false))
    }

    /// Admit and record; panics unless admitted or conflict. Returns the id.
    pub fn emit(
        &mut self,
        who: &str,
        kind: Kind,
        body: Body,
        refs: &[(&str, ContentId)],
    ) -> ContentId {
        let node = self.event(who, kind, body, refs).node();
        let id = node.content_id().unwrap();
        let entry = LogEntry {
            node,
            signer: self.signer(who, false),
        };
        match self.board.apply(&entry) {
            Verdict::Admit | Verdict::Conflict(_) => {}
            other => panic!("{who} {kind:?} not admitted: {other:?}"),
        }
        self.log.push(entry);
        id
    }

    pub fn brief(&mut self, to: &str, lane: &str) -> ContentId {
        self.emit(
            "shep",
            Kind::Brief,
            Body::Brief {
                to: to.into(),
                lane: lane.into(),
            },
            &[],
        )
    }

    pub fn review(&mut self, to: &str, lane: &str, head: &str) -> ContentId {
        self.emit(
            "shep",
            Kind::Review,
            Body::Review {
                to: to.into(),
                lane: lane.into(),
                head: head.into(),
            },
            &[],
        )
    }
}
