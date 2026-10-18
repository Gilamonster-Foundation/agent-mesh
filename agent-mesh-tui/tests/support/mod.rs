//! A real flock on disk, built with a real server, for the views to read.
#![allow(dead_code)]

use agent_mesh_flock::{Body, Event, Kind, Member, Role};
use agent_mesh_flock_server::{init, InitSpec, Server};
use agent_mesh_protocol::{AgentKey, Assertion, UserKey};
use content_addressable::{ContentAddressable as _, ContentId};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::TempDir;

pub struct Who {
    pub key: AgentKey,
    pub session: String,
}

pub struct Fixture {
    pub dir: TempDir,
    pub server: Server,
    at: u64,
}

fn member(name: &str, role: Role) -> Member {
    Member {
        name: name.into(),
        role,
        devices: vec![],
    }
}

impl Fixture {
    /// A flock named `fx` with shep, h1, h2, rev, herdr and a spare `watcher`.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let spec = InitSpec {
            name: "fx".into(),
            roster: vec![
                member("shep", Role::Shepherd),
                member("h1", Role::Helper),
                member("h2", Role::Helper),
                member("rev", Role::Reviewer),
                member("herdr", Role::Adapter),
                member("watcher", Role::Reviewer),
                member("spare", Role::Helper),
            ],
            salt: "00".into(),
            host: "h".into(),
            issued_at: "t".into(),
        };
        init(dir.path(), &UserKey::generate(), spec).unwrap();
        let server = Server::open(dir.path()).unwrap();
        Self { dir, server, at: 0 }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn enroll(&mut self, member: &str) -> Who {
        let invite = self.server.invite(member).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let ch = self
            .server
            .enroll_begin(&invite.token, member, sk.verifying_key().to_bytes())
            .unwrap();
        let done = self
            .server
            .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
            .unwrap();
        Who {
            key: AgentKey::from_seed_and_cert(&sk.to_bytes(), done.cert).unwrap(),
            session: done.session,
        }
    }

    pub fn emit(
        &mut self,
        who: &Who,
        kind: Kind,
        refs: &[(&str, ContentId)],
        body: Body,
    ) -> ContentId {
        self.at += 1;
        let node = Event {
            flock: self.server.flock(),
            kind,
            author: who.session.clone(),
            prev: self.server.board().head_of(&who.session),
            refs: refs
                .iter()
                .map(|(r, c)| ((*r).to_owned(), *c))
                .collect::<BTreeMap<_, _>>(),
            files: vec![],
            at: self.at,
            body,
        }
        .node();
        let id = node.content_id().unwrap();
        let sig = Assertion::sign(&who.key, &id);
        self.server.admit(node, sig).unwrap();
        id
    }
}

/// A flock with some life in it: a brief acked and being worked, a second
/// brief nobody has taken, a job and an ask open, an adapter saying it is idle
/// and a replacement session waiting.
pub fn busy() -> (Fixture, Vec<Who>) {
    let mut f = Fixture::new();
    let shep = f.enroll("shep");
    let h1 = f.enroll("h1");
    let rev = f.enroll("rev");
    let herdr = f.enroll("herdr");
    let _h1_spare = f.enroll("h1"); // a replacement: pending
    let brief = f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "l1".into(),
        },
    );
    f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h2".into(),
            lane: "l2".into(),
        },
    );
    f.emit(&h1, Kind::Ack, &[("of", brief)], Body::Ack);
    // a job that finished: it must not count as open work
    let done = f.emit(
        &shep,
        Kind::Job,
        &[],
        Body::Job {
            lane: "l9".into(),
            label: "push".into(),
        },
    );
    f.emit(
        &shep,
        Kind::JobEnd,
        &[("job", done)],
        Body::JobEnd {
            code: Some(0),
            signal: None,
        },
    );
    f.emit(
        &h1,
        Kind::Job,
        &[],
        Body::Job {
            lane: "l1".into(),
            label: "build".into(),
        },
    );
    f.emit(
        &h1,
        Kind::Ask,
        &[("about", brief)],
        Body::Ask {
            lane: Some("l1".into()),
            text: "which branch?".into(),
        },
    );
    f.emit(
        &herdr,
        Kind::Status,
        &[],
        Body::Status {
            text: "idle".into(),
        },
    );
    // last, because ending a session raises the epoch and every other
    // certificate is behind it afterwards
    // a member whose active session ended and whose replacement still waits
    let old = f.enroll("spare");
    let _waiting = f.enroll("spare");
    f.server
        .end_session(&old.session, agent_mesh_flock::EndReason::Closed)
        .unwrap();
    (f, vec![shep, h1, rev, herdr])
}

/// Blank the flock id's characters: they differ with every generated key, and
/// nothing else in a screen does.
pub fn mask_id(text: &str) -> String {
    text.lines()
        .map(|l| match l.find(" · id ") {
            Some(i) => {
                let start = i + " · id ".len();
                let end = l[start..].find(' ').map_or(l.len(), |n| start + n);
                format!("{}{}{}", &l[..start], "·".repeat(end - start), &l[end..])
            }
            None => l.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Compare `actual` with `tests/snapshots/<name>.txt`; `UPDATE_SNAPSHOTS=1`
/// rewrites it.
pub fn assert_snapshot(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (UPDATE_SNAPSHOTS=1 writes it)", path.display()));
    assert_eq!(
        actual, want,
        "screen differs from {name}.txt (UPDATE_SNAPSHOTS=1 rewrites it)"
    );
}
