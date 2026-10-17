//! `amesh flock` — the flock server's command line.

use crate::herdr::{self, Gap, Herdr, Pane};
use crate::util;
use agent_mesh_flock::{AttemptView, Body, Member, Role};
use agent_mesh_flock_server::{init as flock_init, InitSpec, Snapshot, Status};
use agent_mesh_protocol::UserKey;
use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use rand::RngCore;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// `amesh flock` subcommands.
#[derive(Subcommand, Debug)]
pub enum FlockCommand {
    /// Create a flock: mint its server key and genesis, once (like `git init`).
    Init {
        /// Flock name.
        #[arg(long)]
        name: String,
        /// A roster member as `name:role` (repeatable). Roles: shepherd,
        /// reviewer, helper, adapter, operator.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
        /// Flock directory (defaults to `<home>/flocks/<name>`).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show the roster next to the herdr panes that carry its members.
    /// Read-only: reads the log without its lock and asks herdr only to list.
    Panes {
        /// Flock name.
        #[arg(long)]
        name: String,
        /// Flock directory (defaults to `<home>/flocks/<name>`).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Only panes in this herdr tab (pane labels repeat across tabs).
        #[arg(long)]
        tab: Option<String>,
        /// Map a member to a pane id, `member=pane` (repeatable). Otherwise a
        /// member is the pane whose label is its name.
        #[arg(long = "map")]
        maps: Vec<String>,
    },
}

/// Dispatch a flock subcommand.
pub fn run(home: PathBuf, cmd: FlockCommand) -> Result<()> {
    match cmd {
        FlockCommand::Init { name, members, dir } => init(home, name, &members, dir),
        FlockCommand::Panes {
            name,
            dir,
            tab,
            maps,
        } => panes(&home, &name, dir, tab.as_deref(), &maps),
    }
}

fn parse_member(spec: &str) -> Result<Member> {
    let (name, role) = spec
        .split_once(':')
        .filter(|(n, _)| !n.is_empty())
        .ok_or_else(|| anyhow!("member '{spec}' must be name:role"))?;
    let role: Role =
        serde_json::from_value(serde_json::Value::String(role.into())).map_err(|_| {
            anyhow!(
                "unknown role '{role}' — expected shepherd, reviewer, helper, adapter or operator"
            )
        })?;
    Ok(Member {
        name: name.into(),
        role,
    })
}

fn init(home: PathBuf, name: String, members: &[String], dir: Option<PathBuf>) -> Result<()> {
    let roster = members
        .iter()
        .map(|m| parse_member(m))
        .collect::<Result<Vec<_>>>()?;
    let key_path = home.join("user.key");
    let user = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first?", key_path.display()))?;
    let dir = dir.unwrap_or_else(|| home.join("flocks").join(&name));
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let spec = InitSpec {
        name,
        roster,
        salt: hex::encode(salt),
        host: util::current_hostname(),
        issued_at: util::now_rfc3339(),
    };
    let flock = flock_init(&dir, &user, spec)
        .with_context(|| format!("init flock in {}", dir.display()))?;
    println!("flock id: {flock}");
    println!("dir:      {}", dir.display());
    Ok(())
}

fn panes(
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
    print!("{}", render(&snap, &live, &explicit, tab)?);
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
        "{:<10} {:<9} {:<8} {:<16} FLOCK (verified)",
        "MEMBER", "ROLE", "PANE", "HERDR (claimed)"
    );
    for (member, pane) in herdr::join(board.members(), live, explicit, tab)? {
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
            "{:<10} {:<9} {:<8} {:<16} {}",
            member.name,
            format!("{:?}", member.role).to_lowercase(),
            id,
            claimed,
            flock_state(snap, &member.name)
        );
    }
    Ok(out)
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
    use agent_mesh_flock::EndReason;
    use agent_mesh_flock_server::Server;
    use agent_mesh_protocol::Fingerprint;
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
}
