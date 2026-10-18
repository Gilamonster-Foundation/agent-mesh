//! A roster that drops a member carries its epoch bump in the same frame.
#![cfg(unix)]
mod support;

use agent_mesh_flock::{Body, Kind};
use agent_mesh_flock_server::{encode, FollowError, Follower, Frame, Sealed, Server, ServerError};
use std::io::Write;
use support::{enroll, Env};

/// Every frame in the log, oldest first.
fn frames(server: &Server) -> Vec<Vec<Sealed>> {
    let j = server.journal();
    let mut c = j.cursor_from(None).unwrap();
    let mut out = vec![];
    while c.delivered() < j.len() {
        out.push(c.next_frame().unwrap().0.to_vec());
    }
    out
}

fn kinds(f: &[Sealed]) -> Vec<Kind> {
    f.iter().map(|s| s.event.payload.kind).collect()
}

fn without(server: &Server, name: &str) -> Vec<agent_mesh_flock::Member> {
    let mut r = server.board().members().to_vec();
    r.retain(|m| m.name != name);
    r
}

#[test]
fn the_server_roster_path_that_drops_a_member_emits_the_bump_and_closes_its_watch() {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let h1 = enroll(&mut server, "h1");
    let roster = without(&server, "h1");
    server.replace_roster(roster).unwrap();
    let all = frames(&server);
    let last = all.last().unwrap();
    assert_eq!(kinds(last), vec![Kind::Roster, Kind::Epoch]);
    // what the watch stream closes on: an epoch-bearing frame whose
    // eligible set no longer holds the dropped member's session
    let j = server.journal();
    let mut c = j.cursor_from(None).unwrap();
    let mut seen = None;
    while c.delivered() < j.len() {
        seen = Some(c.next_frame().unwrap());
    }
    let (frame, eligible) = seen.unwrap();
    assert!(frame.iter().any(|s| s.event.payload.kind == Kind::Epoch));
    assert!(!eligible.contains(&h1.session));
    assert!(eligible.contains(&shep.session));
}

#[test]
fn a_shepherds_roster_event_that_drops_a_member_is_sealed_with_the_bump() {
    let mut f = Env::new();
    let mut server = f.open();
    let shep = enroll(&mut server, "shep");
    let _h1 = enroll(&mut server, "h1");
    let roster = without(&server, "h1");
    let replaces = server.board().roster_id();
    let (n, s) = f.event(
        &shep.key,
        Kind::Roster,
        None,
        &[("replaces", replaces)],
        Body::Roster { members: roster },
    );
    server.admit(n, s).unwrap();
    let all = frames(&server);
    assert_eq!(kinds(all.last().unwrap()), vec![Kind::Roster, Kind::Epoch]);
    assert!(server.board().members().iter().all(|m| m.name != "h1"));
}

#[test]
fn a_roster_that_only_adds_a_member_needs_no_bump() {
    let env = Env::new();
    let mut server = env.open();
    let _shep = enroll(&mut server, "shep");
    let mut roster = server.board().members().to_vec();
    roster.push(agent_mesh_flock::Member {
        name: "h2".into(),
        role: agent_mesh_flock::Role::Helper,
        devices: vec![],
    });
    server.replace_roster(roster).unwrap();
    let all = frames(&server);
    assert_eq!(kinds(all.last().unwrap()), vec![Kind::Roster]);
}

/// The log with the dropping roster's frame split into `[roster]` and
/// `[epoch]`: every record is genuine and signed, only the shape is wrong.
fn split_log(server: &Server) -> Vec<Frame> {
    let mut out = vec![];
    for fr in frames(server) {
        if fr.len() == 2 && fr[0].event.payload.kind == Kind::Roster {
            out.push(Frame {
                sealed: vec![fr[0].clone()],
            });
            out.push(Frame {
                sealed: vec![fr[1].clone()],
            });
        } else {
            out.push(Frame { sealed: fr });
        }
    }
    out
}

#[test]
fn a_log_whose_dropping_roster_lacks_its_bump_is_refused_by_both_readers() {
    let env = Env::new();
    let mut server = env.open();
    let _shep = enroll(&mut server, "shep");
    let _h1 = enroll(&mut server, "h1");
    let roster = without(&server, "h1");
    server.replace_roster(roster).unwrap();
    let split = split_log(&server);
    assert!(split.iter().any(|f| f.sealed.len() == 1
        && f.sealed[0].event.payload.kind == Kind::Roster
        && f.sealed[0].record.payload.index == server.admitted() - 1));
    // Follower
    let genesis = agent_mesh_flock_server::load_genesis(env.tmp.path())
        .unwrap()
        .node;
    let mut fol = Follower::new(&genesis).unwrap();
    let mut refused = false;
    for fr in &split {
        if let Err(e) = fol.apply(&fr.sealed) {
            assert!(matches!(e, FollowError::Invalid(_)), "{e:?}");
            refused = true;
            break;
        }
    }
    assert!(refused, "the follower must refuse the unbumped drop");
    // Server::open
    drop(server);
    let bytes: Vec<u8> = split.iter().flat_map(|f| encode(f).unwrap()).collect();
    let mut log = std::fs::File::create(env.log_path()).unwrap();
    log.write_all(&bytes).unwrap();
    drop(log);
    assert!(matches!(
        Server::open(&env.dir()),
        Err(ServerError::Corrupt { .. })
    ));
}

#[test]
fn a_follower_replays_the_bumped_frame_to_the_same_head() {
    let env = Env::new();
    let mut server = env.open();
    let _shep = enroll(&mut server, "shep");
    let _h1 = enroll(&mut server, "h1");
    let roster = without(&server, "h1");
    server.replace_roster(roster).unwrap();
    let genesis = agent_mesh_flock_server::load_genesis(env.tmp.path())
        .unwrap()
        .node;
    let mut fol = Follower::new(&genesis).unwrap();
    for fr in frames(&server) {
        fol.apply(&fr).unwrap();
    }
    assert_eq!(fol.admitted(), server.admitted());
    assert_eq!(fol.epoch(), server.epoch());
    assert!(fol.board().members().iter().all(|m| m.name != "h1"));
}

#[test]
fn swapping_one_member_for_another_still_drops_a_name_and_bumps() {
    let env = Env::new();
    let mut server = env.open();
    let _shep = enroll(&mut server, "shep");
    let mut roster = without(&server, "h1");
    roster.push(agent_mesh_flock::Member {
        name: "h2".into(),
        role: agent_mesh_flock::Role::Helper,
        devices: vec![],
    });
    server.replace_roster(roster).unwrap();
    let all = frames(&server);
    assert_eq!(kinds(all.last().unwrap()), vec![Kind::Roster, Kind::Epoch]);
}
