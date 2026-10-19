//! `amesh flock panes`: the roster joined to herdr's pane list.

use crate::herdr::{self, Gap, Herdr, Pane};
use agent_mesh_flock::text::{inert, inert_lines};
use agent_mesh_flock::{AttemptView, Body};
use agent_mesh_flock_server::{Snapshot, Status};
use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(super) fn panes(
    home: &std::path::Path,
    name: &str,
    dir: Option<PathBuf>,
    tab: Option<&str>,
    maps: &[String],
) -> Result<()> {
    let dir = dir.unwrap_or_else(|| home.join("flocks").join(name));
    let explicit = maps
        .iter()
        .map(|m| {
            m.split_once('=')
                .map(|(who, pane)| (who.to_owned(), pane.to_owned()))
                .ok_or_else(|| anyhow!("--map '{m}' must be member=pane"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let snap =
        Snapshot::read(&dir).with_context(|| format!("read the log in {}", dir.display()))?;
    let live = Herdr(herdr::System).panes()?;
    print!("{}", inert_lines(&render(&snap, &live, &explicit, tab)?));
    Ok(())
}

/// The joined view: verified flock columns beside herdr's unverified ones.
fn render(
    snap: &Snapshot,
    live: &[Pane],
    explicit: &BTreeMap<String, String>,
    tab: Option<&str>,
) -> Result<String> {
    use std::fmt::Write as _;
    let board = snap.board();
    let flock = board.flock().to_string();
    let mut out = format!(
        "flock {} · log ✓ {} · epoch {}{}\n",
        &flock[..flock.len().min(16)],
        snap.admitted(),
        snap.epoch(),
        if snap.torn() {
            " · torn tail unread"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "{:<10} {:<9} {:<8} {:<8} {:<16} FLOCK (verified)",
        "MEMBER", "ROLE", "PANE", "VIA", "HERDR (claimed)"
    );
    let claims = announced(snap, live, tab);
    let mut effective = claims.clone();
    effective.extend(explicit.iter().map(|(k, v)| (k.clone(), v.clone())));
    for (member, pane) in herdr::join(board.members(), live, &effective, tab)? {
        let via = match &pane {
            Ok(_) if explicit.contains_key(&member.name) => "map",
            Ok(_) if claims.contains_key(&member.name) => "session",
            Ok(_) => "label",
            Err(_) => "-",
        };
        let (id, claimed) = match &pane {
            Ok(p) => (
                p.pane_id.clone(),
                format!(
                    "{} {}",
                    p.agent().unwrap_or("-"),
                    p.agent_status.as_deref().unwrap_or("-")
                ),
            ),
            Err(Gap::NoPane) => ("-".into(), "no pane".into()),
            Err(Gap::Ambiguous(n)) => ("-".into(), format!("ambiguous ({n})")),
            Err(Gap::Gone(id)) => ("-".into(), format!("{id} gone")),
        };
        let _ = writeln!(
            out,
            "{:<10} {:<9} {:<8} {:<8} {:<16} {}",
            inert(&member.name),
            format!("{:?}", member.role).to_lowercase(),
            inert(&id),
            via,
            inert(&claimed),
            inert(&flock_state(snap, &member.name))
        );
    }
    Ok(out)
}

/// The pane each member's active session last claimed, when herdr still has
/// that pane (and it is in `tab`, if one is given). Only the active session
/// counts: an ended or pending session's claim says nothing about who holds
/// the role now. The claim is the session's word, signed; herdr and the log
/// cannot confirm the pane.
fn announced(snap: &Snapshot, live: &[Pane], tab: Option<&str>) -> BTreeMap<String, String> {
    let sessions = snap.sessions();
    let mut latest: BTreeMap<&str, (u64, &str)> = BTreeMap::new();
    for e in snap.board().entries() {
        let Body::Pane { pane, .. } = &e.event.body else {
            continue;
        };
        let author = e.event.author.as_str();
        if latest.get(author).is_none_or(|(i, _)| e.index > *i) {
            latest.insert(author, (e.index, pane));
        }
    }
    latest
        .into_iter()
        .filter_map(|(author, (_, pane))| {
            let s = sessions
                .get(author)
                .filter(|s| s.status == Status::Active)
                // a roster change can drop a member whose session is still
                // Active in the table: its claim is not about anyone now
                .filter(|s| snap.board().members().iter().any(|m| m.name == s.member))?;
            let p = live.iter().find(|p| p.pane_id == pane)?;
            (tab.is_none() || tab == Some(p.tab_id.as_str())).then(|| (s.member, pane.to_owned()))
        })
        .collect()
}

/// The member's session status and its lanes, from the verified log.
fn flock_state(snap: &Snapshot, member: &str) -> String {
    let sessions = snap.sessions();
    // A member can hold one active session and pending replacements; the log
    // iterates them by fingerprint, so count them rather than take the first.
    let (mut active, mut pending) = (0, 0);
    for s in sessions
        .live()
        .filter_map(|(s, _, _)| sessions.get(s))
        .filter(|s| s.member == member)
    {
        match s.status {
            Status::Active => active += 1,
            Status::Pending => pending += 1,
            Status::Ended => {}
        }
    }
    let session = match (active, pending) {
        (0, 0) => "no session".to_owned(),
        (0, _) => "session pending".to_owned(),
        (_, 0) => "session active".to_owned(),
        (_, n) => format!("session active (+{n} pending)"),
    };
    let lanes: Vec<String> = snap
        .board()
        .lanes()
        .into_iter()
        .filter(|l| addressed_to(snap, &l.latest, member))
        .map(|l| format!("{} {}", l.lane, l.latest.label()))
        .collect();
    if lanes.is_empty() {
        session
    } else {
        format!("{session} · {}", lanes.join(", "))
    }
}

fn addressed_to(snap: &Snapshot, attempt: &AttemptView, member: &str) -> bool {
    snap.board()
        .get(&attempt.brief)
        .is_some_and(|e| matches!(&e.event.body, Body::Brief { to, .. } if to == member))
}

#[cfg(all(test, unix))] // flock init is unix-only
mod tests {
    use super::*;
    use crate::flock::parse_member;
    use agent_mesh_flock::EndReason;
    use agent_mesh_flock_server::Server;
    use agent_mesh_flock_server::{init as flock_init, InitSpec};
    use agent_mesh_protocol::UserKey;
    use agent_mesh_protocol::{AgentKey, Fingerprint};
    use content_addressable::ContentAddressable as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn flock() -> (TempDir, Server) {
        let dir = TempDir::new().unwrap();
        let roster = ["shep:shepherd", "h1:helper"]
            .map(|m| parse_member(m).unwrap())
            .to_vec();
        let spec = InitSpec {
            name: "t".into(),
            roster,
            salt: "s".into(),
            host: "fixture".into(),
            issued_at: "2026-10-15T00:00:00Z".into(),
        };
        flock_init(dir.path(), &UserKey::generate(), spec).unwrap();
        let server = Server::open(dir.path()).unwrap();
        (dir, server)
    }

    fn session_id(sk: &SigningKey) -> String {
        Fingerprint::of_bytes(&sk.verifying_key().to_bytes()).hex()
    }

    /// Enroll `sk` for `member`; returns its session id.
    fn enroll(server: &mut Server, member: &str, sk: &SigningKey) -> String {
        let invite = server.invite(member).unwrap();
        let ch = server
            .enroll_begin(&invite.token, member, sk.verifying_key().to_bytes())
            .unwrap();
        let proof = sk.sign(&ch.signing_bytes());
        server.enroll_finish(&ch, &proof).unwrap().session
    }

    fn row(dir: &TempDir, member: &str) -> String {
        let snap = Snapshot::read(dir.path()).unwrap();
        let out = render(&snap, &[], &BTreeMap::new(), None).unwrap();
        out.lines()
            .find(|l| l.starts_with(member))
            .unwrap()
            .to_owned()
    }

    /// PR #126: sessions iterate by fingerprint, so a pending replacement
    /// that sorts before the active holder used to hide it. Two keys are
    /// chosen up front and the larger id enrolls first (active), the smaller
    /// second (pending): the adverse order, every run.
    #[test]
    fn a_pending_replacement_that_sorts_first_does_not_hide_the_active_holder() {
        let mut keys = [
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        ];
        keys.sort_by_key(session_id);
        let [small, large] = keys;
        let (dir, mut server) = flock();
        let active = enroll(&mut server, "h1", &large);
        let pending = enroll(&mut server, "h1", &small);
        assert!(active > pending, "fixture: the adverse order");
        let row = row(&dir, "h1");
        assert!(row.contains("session active (+1 pending)"), "{row}");
    }

    #[test]
    fn a_member_with_only_a_pending_session_shows_pending() {
        let (dir, mut server) = flock();
        let first = enroll(&mut server, "h1", &SigningKey::generate(&mut OsRng));
        server.end_session(&first, EndReason::Closed).unwrap();
        enroll(&mut server, "h1", &SigningKey::generate(&mut OsRng)); // any session after the first starts pending
        let row = row(&dir, "h1");
        assert!(row.contains("session pending"), "{row}");
        assert!(!row.contains("active"), "{row}");
    }

    /// Enroll a fresh key for `member`, keeping the certified key to sign with.
    fn enroll_key(server: &mut Server, member: &str) -> AgentKey {
        let sk = SigningKey::generate(&mut OsRng);
        let invite = server.invite(member).unwrap();
        let ch = server
            .enroll_begin(&invite.token, member, sk.verifying_key().to_bytes())
            .unwrap();
        let done = server
            .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
            .unwrap();
        AgentKey::from_seed_and_cert(&sk.to_bytes(), done.cert).unwrap()
    }

    /// `key`'s session claims to be in `pane`.
    fn claim(server: &mut Server, key: &AgentKey, pane: &str, tab: &str) {
        let author = key.fingerprint().hex();
        let node = agent_mesh_flock::Event {
            flock: server.flock(),
            kind: agent_mesh_flock::Kind::Pane,
            prev: server.board().head_of(&author),
            author,
            refs: BTreeMap::new(),
            files: vec![],
            at: 0,
            body: Body::Pane {
                pane: pane.into(),
                tab: tab.into(),
            },
        }
        .node();
        let sig = agent_mesh_protocol::Assertion::sign(key, &node.content_id().unwrap());
        server.admit(node, sig).unwrap();
    }

    fn herdr_pane(id: &str, tab: &str, label: Option<&str>) -> Pane {
        Pane {
            pane_id: id.into(),
            tab_id: tab.into(),
            label: label.map(Into::into),
            agent: Some("newt".into()),
            agent_session: None,
            agent_status: Some("idle".into()),
        }
    }

    fn view(dir: &TempDir, live: &[Pane], map: &[(&str, &str)], tab: Option<&str>) -> String {
        let snap = Snapshot::read(dir.path()).unwrap();
        let explicit = map
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect();
        render(&snap, live, &explicit, tab).unwrap()
    }

    fn line<'a>(out: &'a str, member: &str) -> &'a str {
        out.lines().find(|l| l.starts_with(member)).unwrap()
    }

    #[test]
    fn a_sessions_signed_claim_links_its_pane_without_a_label() {
        let (dir, mut server) = flock();
        let key = enroll_key(&mut server, "h1");
        claim(&mut server, &key, "w1:p9", "w1:t1");
        claim(&mut server, &key, "w1:p7", "w1:t1"); // the later claim stands
        let live = [
            herdr_pane("w1:p7", "w1:t1", None),
            herdr_pane("w1:p9", "w1:t1", None),
        ];
        let out = view(&dir, &live, &[], None);
        let l = line(&out, "h1");
        assert!(l.contains("w1:p7") && l.contains("session"), "{l}");
    }

    #[test]
    fn a_claim_by_an_ended_or_pending_session_links_nothing() {
        let (dir, mut server) = flock();
        let old = enroll_key(&mut server, "h1");
        claim(&mut server, &old, "w1:p1", "w1:t1");
        let newer = enroll_key(&mut server, "h1"); // pending replacement
        let live = [
            herdr_pane("w1:p1", "w1:t1", None),
            herdr_pane("w1:p2", "w1:t1", None),
        ];
        let after_pending = view(&dir, &live, &[], None);
        assert!(line(&after_pending, "h1").contains("w1:p1")); // old still holds the role
        server
            .end_session(&old.fingerprint().hex(), EndReason::Lost)
            .unwrap();
        let out = view(&dir, &live, &[], None);
        assert!(line(&out, "h1").contains("no pane"), "{}", line(&out, "h1"));
        let _ = newer;
    }

    #[test]
    fn a_claim_for_a_pane_herdr_lacks_or_outside_the_tab_is_ignored() {
        let (dir, mut server) = flock();
        let key = enroll_key(&mut server, "h1");
        claim(&mut server, &key, "w1:p9", "w1:ta");
        let gone = view(&dir, &[herdr_pane("w1:p1", "w1:ta", Some("h1"))], &[], None);
        let l = line(&gone, "h1");
        assert!(l.contains("w1:p1") && l.contains("label"), "{l}");
        let live = [herdr_pane("w1:p9", "w1:ta", None)];
        let other_tab = view(&dir, &live, &[], Some("w1:tb"));
        assert!(line(&other_tab, "h1").contains("no pane"));
    }

    #[test]
    fn an_explicit_map_beats_a_claim_and_a_claim_beats_a_label() {
        let (dir, mut server) = flock();
        let key = enroll_key(&mut server, "h1");
        claim(&mut server, &key, "w1:p2", "w1:t1");
        let live = [
            herdr_pane("w1:p1", "w1:t1", Some("h1")),
            herdr_pane("w1:p2", "w1:t1", None),
            herdr_pane("w1:p3", "w1:t1", None),
        ];
        let by_claim = view(&dir, &live, &[], None);
        let l = line(&by_claim, "h1");
        assert!(l.contains("w1:p2") && l.contains("session"), "{l}");
        let by_map = view(&dir, &live, &[("h1", "w1:p3")], None);
        let l = line(&by_map, "h1");
        assert!(l.contains("w1:p3") && l.contains("map"), "{l}");
    }

    #[test]
    fn two_sessions_claiming_one_pane_are_both_ambiguous() {
        let (dir, mut server) = flock();
        let (a, b) = (
            enroll_key(&mut server, "h1"),
            enroll_key(&mut server, "shep"),
        );
        claim(&mut server, &a, "w1:p1", "w1:t1");
        claim(&mut server, &b, "w1:p1", "w1:t1");
        let out = view(&dir, &[herdr_pane("w1:p1", "w1:t1", None)], &[], None);
        assert!(line(&out, "h1").contains("ambiguous (2)"));
        assert!(line(&out, "shep").contains("ambiguous (2)"));
    }

    /// PR #131: a member dropped by a roster event keeps an Active session
    /// until removal-driven epoch bumps exist; its old claim used to reach
    /// `join` as an off-roster `--map` and blank the whole view.
    #[test]
    fn a_claim_by_a_member_the_roster_dropped_does_not_break_the_view() {
        let (dir, mut server) = flock();
        let (shep, h1) = (
            enroll_key(&mut server, "shep"),
            enroll_key(&mut server, "h1"),
        );
        claim(&mut server, &h1, "w1:p1", "w1:t1");
        claim(&mut server, &shep, "w1:p2", "w1:t1");
        // the shepherd signs a roster that keeps only the shepherd
        let author = shep.fingerprint().hex();
        let node = agent_mesh_flock::Event {
            flock: server.flock(),
            kind: agent_mesh_flock::Kind::Roster,
            prev: server.board().head_of(&author),
            author,
            refs: BTreeMap::from([("replaces".to_owned(), server.board().roster_id())]),
            files: vec![],
            at: 0,
            body: Body::Roster {
                members: vec![agent_mesh_flock::Member {
                    name: "shep".into(),
                    role: agent_mesh_flock::Role::Shepherd,
                    devices: vec![],
                }],
            },
        }
        .node();
        let sig = agent_mesh_protocol::Assertion::sign(&shep, &node.content_id().unwrap());
        server.admit(node, sig).unwrap();
        let live = [
            herdr_pane("w1:p1", "w1:t1", None),
            herdr_pane("w1:p2", "w1:t1", None),
        ];
        let out = view(&dir, &live, &[], None);
        assert!(line(&out, "shep").contains("w1:p2"), "{out}");
        assert!(!out.contains("h1"), "{out}");
        // an explicit --map for someone off the roster is still an error
        let snap = Snapshot::read(dir.path()).unwrap();
        let bad = BTreeMap::from([("h1".to_owned(), "w1:p1".to_owned())]);
        assert!(render(&snap, &live, &bad, None).is_err());
    }
}
