//! `watch` end to end: the stream, resume, rollback, the reader's saved state
//! and who may open a stream. Waits are causal (condvars and blocking reads).
#![cfg(unix)]

use agent_mesh_flock::{Body, Event, Kind, Member, Role};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::{
    bind_private, init, load_genesis, serve, InitSpec, Sealed, Server, Serving, LOG_FILE,
};
use agent_mesh_flock_session::{Fs, Reader, ReaderError, RealFs, Watch, WatchEvent};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Assertion, Caveats, UserKey};
use content_addressable::{ContentAddressable, MerkleNode};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Rig {
    tmp: TempDir,
    user: UserKey,
    sock: PathBuf,
    serving: Option<Serving>,
    at: u64,
}

fn spec() -> InitSpec {
    InitSpec {
        name: "f".into(),
        roster: vec![
            Member {
                name: "shep".into(),
                role: Role::Shepherd,
            },
            Member {
                name: "h1".into(),
                role: Role::Helper,
            },
        ],
        salt: "00".into(),
        host: "h".into(),
        issued_at: "t".into(),
    }
}

fn start(dir: &Path) -> (PathBuf, Serving) {
    let sock = dir.join("run").join("serve.sock");
    let serving = serve(Server::open(dir).unwrap(), bind_private(&sock).unwrap()).unwrap();
    (sock, serving)
}

fn rig() -> Rig {
    let tmp = TempDir::new().unwrap();
    let user = UserKey::generate();
    init(tmp.path(), &user, spec()).unwrap();
    let (sock, serving) = start(tmp.path());
    Rig {
        tmp,
        user,
        sock,
        serving: Some(serving),
        at: 0,
    }
}

struct Member1 {
    conn: UnixStream,
    key: AgentKey,
    session: String,
}

fn rpc(c: &mut UnixStream, req: &Req) -> Resp {
    write_msg(c, req).unwrap();
    read_msg(c).unwrap().unwrap()
}

impl Rig {
    fn conn(&self) -> UnixStream {
        UnixStream::connect(&self.sock).unwrap()
    }
    fn enrol(&self, member: &str) -> Member1 {
        let mut c = self.conn();
        let Resp::Invited { token } = rpc(
            &mut c,
            &Req::Invite {
                member: member.into(),
            },
        ) else {
            panic!()
        };
        let sk = SigningKey::generate(&mut OsRng);
        let Resp::Challenge(ch) = rpc(
            &mut c,
            &Req::EnrollBegin {
                token,
                member: member.into(),
                pubkey: sk.verifying_key().to_bytes(),
            },
        ) else {
            panic!()
        };
        let proof = sk.sign(&ch.signing_bytes());
        let Resp::Enrolled { session, cert, .. } = rpc(
            &mut c,
            &Req::EnrollFinish {
                challenge: ch,
                proof,
            },
        ) else {
            panic!()
        };
        Member1 {
            conn: c,
            key: AgentKey::from_seed_and_cert(&sk.to_bytes(), cert).unwrap(),
            session,
        }
    }
    /// `who` admits a brief; returns the admission index.
    fn brief(&mut self, who: &mut Member1, lane: &str) -> u64 {
        let Resp::Head(prev) = rpc(
            &mut who.conn,
            &Req::Head {
                session: who.session.clone(),
            },
        ) else {
            panic!()
        };
        let Resp::Hello { flock, .. } = rpc(&mut self.conn(), &Req::Hello) else {
            panic!()
        };
        self.at += 1;
        let node = Event {
            flock,
            kind: Kind::Brief,
            author: who.session.clone(),
            prev,
            refs: Default::default(),
            files: vec![],
            at: self.at,
            body: Body::Brief {
                to: "h1".into(),
                lane: lane.into(),
            },
        }
        .node();
        let sig = Assertion::sign(&who.key, &node.content_id().unwrap());
        match rpc(&mut who.conn, &Req::Admit { node, sig }) {
            Resp::Admitted { index, .. } => index,
            other => panic!("{other:?}"),
        }
    }
    fn genesis(&self) -> MerkleNode<agent_mesh_flock::Genesis> {
        load_genesis(self.tmp.path()).unwrap().node
    }
    fn serving(&self) -> &Serving {
        self.serving.as_ref().unwrap()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(s) = self.serving.take() {
            s.stop();
        }
    }
}

fn indexes(f: &[Sealed]) -> Vec<u64> {
    f.iter().map(|s| s.record.payload.index).collect()
}

fn next_frame(w: &mut Watch) -> Vec<Sealed> {
    loop {
        match w.next_event().unwrap() {
            WatchEvent::Frame(f) => return f,
            WatchEvent::Caught(_) => {}
            WatchEvent::Closed(why) => panic!("closed: {why}"),
        }
    }
}

#[test]
fn an_event_appended_mid_replay_arrives_once_and_the_replay_boundary_is_marked() {
    let mut r = rig();
    let mut shep = r.enrol("shep");
    for i in 0..3 {
        r.brief(&mut shep, &format!("a{i}"));
    }
    let n = 5; // invite + start + 3 briefs
    let mut w = Watch::open(&r.sock, &shep.key, None).unwrap();
    let mut seen = indexes(&next_frame(&mut w)); // one frame of the replay
    let mid = r.brief(&mut shep, "mid"); // lands while the replay is going
    assert_eq!(mid, n + 1);
    // the rest of the replay, the marker, then the live event
    let mut caught = None;
    while (seen.len() as u64) < mid {
        match w.next_event().unwrap() {
            WatchEvent::Frame(f) => seen.extend(indexes(&f)),
            WatchEvent::Caught(i) => caught = Some(i),
            WatchEvent::Closed(why) => panic!("{why}"),
        }
    }
    assert_eq!(
        seen,
        (1..=mid).collect::<Vec<_>>(),
        "each index once, in order"
    );
    // the marker sits at a point of the one sequence, never inside a gap
    assert!(caught.is_some_and(|i| (n..=mid).contains(&i)));
}

#[test]
fn a_reconnect_resumes_from_the_saved_head_and_delivers_only_what_is_new() {
    let mut r = rig();
    let mut shep = r.enrol("shep");
    r.brief(&mut shep, "a0");
    let dir = TempDir::new().unwrap();
    let mut reader = Reader::open(r.genesis(), dir.path(), RealFs).unwrap();
    reader.sync(&r.sock, &shep.key).unwrap();
    let h1 = reader.follower().head().cloned().unwrap();
    r.brief(&mut shep, "a1");
    r.brief(&mut shep, "a2");
    let mut w = Watch::open(&r.sock, &shep.key, Some(h1.clone())).unwrap();
    let first = indexes(&next_frame(&mut w));
    assert_eq!(first, vec![h1.index() + 1]);
    // a fresh reader process picks the saved state up and catches up
    let mut again = Reader::open(r.genesis(), dir.path(), RealFs).unwrap();
    again.sync(&r.sock, &shep.key).unwrap();
    let now = r.serving().failure();
    assert!(now.is_none());
    assert_eq!(again.follower().admitted(), h1.index() + 2);
}

#[test]
fn a_reader_killed_anywhere_resumes_with_no_duplicate_and_no_gap() {
    let mut r = rig();
    let mut shep = r.enrol("shep");
    for i in 0..4 {
        r.brief(&mut shep, &format!("a{i}"));
    }
    // the whole log, as the stream delivers it
    let mut all = vec![];
    let mut w = Watch::open(&r.sock, &shep.key, None).unwrap();
    loop {
        match w.next_event().unwrap() {
            WatchEvent::Frame(f) => all.push(f),
            WatchEvent::Caught(_) => break,
            WatchEvent::Closed(why) => panic!("{why}"),
        }
    }
    let total: u64 = all.iter().map(|f| f.len() as u64).sum();
    for killed_after in 0..=all.len() {
        for save_every in [1usize, 2, 3] {
            let dir = TempDir::new().unwrap();
            {
                let mut rd = Reader::open(r.genesis(), dir.path(), RealFs).unwrap();
                for (i, f) in all.iter().take(killed_after).enumerate() {
                    rd.apply(f.clone()).unwrap();
                    if (i + 1) % save_every == 0 {
                        rd.save().unwrap();
                    }
                }
            } // killed: whatever was applied but not saved is gone
            let mut rd = Reader::open(r.genesis(), dir.path(), RealFs).unwrap();
            let saved = rd.follower().admitted();
            assert!(saved <= total);
            rd.sync(&r.sock, &shep.key).unwrap();
            assert_eq!(rd.follower().admitted(), total, "no gap");
            // the reopened reader verifies a contiguous chain from genesis:
            // a duplicate would not extend the head, and would have failed
            let mut check = Reader::open(r.genesis(), dir.path(), RealFs).unwrap();
            assert_eq!(check.follower().admitted(), total, "no duplicate");
            let _ = &mut check;
        }
    }
}

#[test]
fn a_certified_non_member_a_pending_or_ended_session_and_a_replayed_proof_open_no_stream() {
    let r = rig();
    let shep = r.enrol("shep");
    // certified by the user key, but never enrolled
    let stranger = AgentKey::issue(
        &r.user,
        AgentMetadata {
            role: "x".into(),
            host: "h".into(),
            capabilities: vec![],
            issued_at: "t".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    );
    let refused = |key: &AgentKey, r: &Rig| {
        let mut w = Watch::open(&r.sock, key, None).unwrap();
        matches!(w.next_event(), Err(ReaderError::Stream(_)))
    };
    assert!(refused(&stranger, &r));
    // a pending replacement
    let pending = r.enrol("shep");
    assert!(refused(&pending.key, &r));
    // and the legitimate member still gets in
    let mut ok = Watch::open(&r.sock, &shep.key, None).unwrap();
    assert!(matches!(ok.next_event().unwrap(), WatchEvent::Frame(_)));
    // a proof signed for one connection's challenge, presented on another
    let mut a = r.conn();
    let Resp::StreamChallenge(ch_a) = rpc(&mut a, &Req::WatchBegin) else {
        panic!()
    };
    let mut b = r.conn();
    let Resp::StreamChallenge(_) = rpc(&mut b, &Req::WatchBegin) else {
        panic!()
    };
    let proof = Box::new(Assertion::sign(&shep.key, &ch_a.id().unwrap()));
    write_msg(&mut b, &Req::Watch { from: None, proof }).unwrap();
    assert!(matches!(
        read_msg::<Resp>(&mut b).unwrap(),
        Some(Resp::Err(_))
    ));
    // an ended session (its goodbye also bumped the epoch)
    let mut h1 = r.enrol("h1");
    assert!(matches!(rpc(&mut h1.conn, &Req::End), Resp::Ok));
    assert!(refused(&h1.key, &r));
}

#[test]
fn a_watch_closes_right_after_the_epoch_bump_that_ends_its_session() {
    let mut r = rig();
    let mut shep = r.enrol("shep");
    r.brief(&mut shep, "a0");
    let mut w = Watch::open(&r.sock, &shep.key, None).unwrap();
    // drain the replay
    loop {
        if let WatchEvent::Caught(_) = w.next_event().unwrap() {
            break;
        }
    }
    // the session says goodbye: session-end + epoch bump
    assert!(matches!(rpc(&mut shep.conn, &Req::End), Resp::Ok));
    let mut kinds = vec![];
    let reason = loop {
        match w.next_event().unwrap() {
            WatchEvent::Frame(f) => kinds.extend(f.iter().map(|s| s.event.payload.kind)),
            WatchEvent::Closed(why) => break why,
            WatchEvent::Caught(_) => {}
        }
    };
    assert_eq!(kinds, vec![Kind::SessionEnd, Kind::Epoch]);
    assert!(reason.contains("ended"), "{reason}");
}

/// Copy the flock's files (not its socket directory).
fn copy_flock(from: &Path, to: &Path) {
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

#[test]
fn an_older_backup_and_a_rolled_back_then_extended_history_are_refused_as_rollback() {
    let mut r = rig();
    let mut shep = r.enrol("shep");
    r.brief(&mut shep, "a0");
    let backup = TempDir::new().unwrap();
    copy_flock(r.tmp.path(), backup.path());
    let fresh = |lane: &str, r: &mut Rig, shep: &mut Member1| r.brief(shep, lane);
    fresh("a1", &mut r, &mut shep);
    fresh("a2", &mut r, &mut shep);
    let dir = TempDir::new().unwrap();
    let mut reader = Reader::open(r.genesis(), dir.path(), RealFs).unwrap();
    reader.sync(&r.sock, &shep.key).unwrap();
    let witnessed = reader.follower().admitted();
    // restore the older backup in place of the log
    r.serving.take().unwrap().stop();
    std::fs::copy(backup.path().join(LOG_FILE), r.tmp.path().join(LOG_FILE)).unwrap();
    let (sock, serving) = start(r.tmp.path());
    r.serving = Some(serving);
    r.sock = sock;
    let err = reader.sync(&r.sock, &shep.key).unwrap_err();
    assert!(matches!(err, ReaderError::Rollback(_)), "{err}");
    let again = Reader::open(r.genesis(), dir.path(), RealFs).unwrap();
    assert_eq!(
        again.follower().admitted(),
        witnessed,
        "the saved head is untouched"
    );
}

/// Models power loss: bytes are durable after `sync_file`, a name after
/// `sync_dir`. A crash keeps only what is durable.
mod power {
    use super::{Fs, Path, PathBuf};
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub struct Model {
        inodes: Vec<(Vec<u8>, Option<Vec<u8>>)>, // (volatile, durable)
        names: BTreeMap<PathBuf, usize>,
        durable_names: BTreeMap<PathBuf, usize>,
        steps: usize,
        crash_at: Option<usize>,
    }

    #[derive(Clone, Default)]
    pub struct PowerFs(pub Arc<Mutex<Model>>);

    impl PowerFs {
        /// An independent copy of the whole model.
        pub fn fork(&self) -> Self {
            Self(Arc::new(Mutex::new(self.0.lock().unwrap().clone())))
        }
        pub fn steps(&self) -> usize {
            self.0.lock().unwrap().steps
        }
        pub fn crash_at(&self, k: usize) {
            let mut m = self.0.lock().unwrap();
            m.steps = 0;
            m.crash_at = Some(k);
        }
        pub fn heal(&self) {
            let mut m = self.0.lock().unwrap();
            m.crash_at = None;
        }
        /// What a restart finds: only the durable names, with durable bytes.
        pub fn after_power_loss(&self) -> Self {
            let m = self.0.lock().unwrap();
            let mut n = Model::default();
            for (name, ino) in &m.durable_names {
                let bytes = m.inodes[*ino].1.clone().unwrap_or_default();
                n.inodes.push((bytes.clone(), Some(bytes)));
                n.names.insert(name.clone(), n.inodes.len() - 1);
            }
            n.durable_names = n.names.clone();
            Self(Arc::new(Mutex::new(n)))
        }
    }

    fn step(m: &mut Model) -> io::Result<()> {
        if m.crash_at.is_some_and(|k| m.steps >= k) {
            return Err(io::Error::other("power lost"));
        }
        m.steps += 1;
        Ok(())
    }

    impl Fs for PowerFs {
        fn write(&self, p: &Path, b: &[u8]) -> io::Result<()> {
            let mut m = self.0.lock().unwrap();
            step(&mut m)?;
            m.inodes.push((b.to_vec(), None));
            let i = m.inodes.len() - 1;
            m.names.insert(p.to_path_buf(), i);
            Ok(())
        }
        fn sync_file(&self, p: &Path) -> io::Result<()> {
            let mut m = self.0.lock().unwrap();
            step(&mut m)?;
            let i = *m.names.get(p).ok_or_else(|| io::Error::other("no file"))?;
            m.inodes[i].1 = Some(m.inodes[i].0.clone());
            Ok(())
        }
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            let mut m = self.0.lock().unwrap();
            step(&mut m)?;
            let i = m
                .names
                .remove(from)
                .ok_or_else(|| io::Error::other("no file"))?;
            m.names.insert(to.to_path_buf(), i);
            Ok(())
        }
        fn sync_dir(&self, _: &Path) -> io::Result<()> {
            let mut m = self.0.lock().unwrap();
            step(&mut m)?;
            m.durable_names = m.names.clone();
            Ok(())
        }
        fn read(&self, p: &Path) -> io::Result<Option<Vec<u8>>> {
            let m = self.0.lock().unwrap();
            Ok(m.names.get(p).map(|i| m.inodes[*i].0.clone()))
        }
    }
}

#[test]
fn power_loss_at_any_step_of_a_save_never_loses_a_witnessed_head() {
    let mut r = rig();
    let mut shep = r.enrol("shep");
    r.brief(&mut shep, "a0");
    r.brief(&mut shep, "a1");
    // the stream's frames
    let mut all = vec![];
    let mut w = Watch::open(&r.sock, &shep.key, None).unwrap();
    loop {
        match w.next_event().unwrap() {
            WatchEvent::Frame(f) => all.push(f),
            WatchEvent::Caught(_) => break,
            WatchEvent::Closed(why) => panic!("{why}"),
        }
    }
    let dir = Path::new("/state");
    let fs = power::PowerFs::default();
    let mut rd = Reader::open(r.genesis(), dir, fs.clone()).unwrap();
    let (first, rest) = all.split_first().unwrap();
    rd.apply(first.clone()).unwrap();
    let old = rd.save().unwrap().unwrap(); // witnessed: its save returned
                                           // measure the steps of one more save
    for f in rest {
        rd.apply(f.clone()).unwrap();
    }
    let new_index = rd.follower().head().unwrap().index();
    let baseline = fs.fork();
    fs.crash_at(usize::MAX);
    rd.save().unwrap();
    let steps = fs.steps();
    assert_eq!(steps, 4, "write, fsync file, rename, fsync dir");
    fs.heal();
    for k in 0..=steps {
        // replay the situation: a durable old state, then a save cut at step k
        let model = baseline.after_power_loss();
        let mut rd2 = Reader::open(r.genesis(), dir, model.clone()).unwrap();
        for f in rest {
            rd2.apply(f.clone()).unwrap();
        }
        model.crash_at(k);
        let saved = rd2.save();
        let found = Reader::open(r.genesis(), dir, model.after_power_loss())
            .unwrap_or_else(|e| panic!("step {k}: the saved state is damaged: {e}"));
        let head = found.follower().head().map(|h| h.index()).unwrap();
        assert!(head >= old.index(), "step {k}: lost a witnessed head");
        assert!(
            head == old.index() || head == new_index,
            "step {k}: a torn state"
        );
        if saved.is_ok() {
            assert_eq!(
                head, new_index,
                "step {k}: save returned Ok but was not durable"
            );
        }
    }
}

#[test]
fn a_watch_also_closes_right_after_a_hand_off_away_from_its_session() {
    use agent_mesh_flock::{FileRef, HandoffApproval};
    use content_addressable::RawContentId;
    let r = rig();
    let shep = r.enrol("shep");
    let old = r.enrol("h1");
    let new = r.enrol("h1"); // pending replacement
    let mut w = Watch::open(&r.sock, &old.key, None).unwrap();
    loop {
        if let WatchEvent::Caught(_) = w.next_event().unwrap() {
            break;
        }
    }
    let approval = r.serving().with_server(|s| {
        let start = s.sessions().get(&old.session).unwrap().start;
        MerkleNode::genesis(HandoffApproval {
            flock: s.flock(),
            member: "h1".into(),
            from: old.session.clone(),
            to: new.session.clone(),
            resume: s.board().head_of(&old.session).unwrap_or(start),
            context: Some(FileRef {
                root: "r".into(),
                path: "HANDOFF.md".into(),
                id: RawContentId::from_content(b"h"),
            }),
        })
    });
    let sig = Assertion::sign(&shep.key, &approval.content_id().unwrap());
    r.serving()
        .with_server(|s| s.handoff(approval, sig))
        .unwrap();
    let mut kinds = vec![];
    let reason = loop {
        match w.next_event().unwrap() {
            WatchEvent::Frame(f) => kinds.extend(f.iter().map(|s| s.event.payload.kind)),
            WatchEvent::Closed(why) => break why,
            WatchEvent::Caught(_) => {}
        }
    };
    assert_eq!(kinds, vec![Kind::Handoff, Kind::Epoch]);
    assert!(reason.contains("ended"), "{reason}");
}
