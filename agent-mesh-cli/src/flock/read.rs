//! Commands that read: the verified log, replayed without its lock, beside
//! the running server. The member comes from the session, never a flag.

use super::discover::Where;
use agent_mesh_flock::{AttemptState, Body, Entry, Kind};
use agent_mesh_flock_server::Snapshot;
use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::path::Path;

fn snapshot(home: &Path, w: &Where) -> Result<Snapshot> {
    let dir = w.dir(home)?;
    Snapshot::read(&dir).with_context(|| format!("read the log in {}", dir.display()))
}

fn kind_name(k: Kind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn detail(e: &Entry) -> String {
    match &e.event.body {
        Body::Brief { to, lane } => format!("to {to} lane {lane}"),
        Body::Review { to, lane, head } => format!("to {to} lane {lane} head {head}"),
        Body::Result { outcome } => format!("{outcome:?}").to_lowercase(),
        Body::Verdict { head, approved } => {
            format!("{} {head}", if *approved { "approved" } else { "rejected" })
        }
        Body::Job { lane, label } => format!("lane {lane} {label}"),
        Body::JobEnd { code, signal } => match (code, signal) {
            (Some(c), None) => format!("exit {c}"),
            (None, Some(s)) => format!("signal {s}"),
            _ => "unreadable exit".to_owned(),
        },
        Body::Ask { text, .. } | Body::Status { text } => text.clone(),
        _ => String::new(),
    }
}

/// One event as `log` and `watch` print it.
pub(super) fn line(e: &Entry) -> String {
    format!(
        "{:>4} {} {:<13} {:<8} {}{}",
        e.index,
        e.id,
        kind_name(e.event.kind),
        e.member.as_deref().unwrap_or("server"),
        detail(e),
        if e.conflict.is_some() {
            " [conflict]"
        } else {
            ""
        }
    )
}

/// The admitted events from index `from`, in admission order.
pub fn log(home: &Path, w: &Where, from: u64) -> Result<()> {
    let snap = snapshot(home, w)?;
    let mut out = String::new();
    for e in snap.board().entries().filter(|e| e.index >= from) {
        let _ = writeln!(out, "{}", line(e));
    }
    print!("{out}");
    Ok(())
}

/// Lanes and where they stand.
pub fn status(home: &Path, w: &Where) -> Result<()> {
    let snap = snapshot(home, w)?;
    let board = snap.board();
    println!("log ✓ {} · epoch {}", snap.admitted(), snap.epoch());
    for l in board.lanes() {
        let to = match board.get(&l.latest.brief).map(|e| &e.event.body) {
            Some(Body::Brief { to, .. }) => to.as_str(),
            _ => "?",
        };
        println!(
            "{:<12} {:<22} to {to}  {}",
            l.lane,
            l.latest.label(),
            l.latest.brief
        );
    }
    Ok(())
}

/// What is addressed to this session's member and still open.
pub fn inbox(home: &Path, w: &Where) -> Result<()> {
    // inbox is always about a flock: name one, and the session must be its own
    w.dir(home)?;
    let (_, me) = w.session(home)?;
    let snap = snapshot(home, w)?;
    let board = snap.board();
    for e in board.entries().filter(|e| e.conflict.is_none()) {
        let state = match &e.event.body {
            Body::Brief { to, .. } if *to == me.member => match board.attempt(&e.id) {
                Some(a) if matches!(a.state, AttemptState::Completed | AttemptState::Failed) => {
                    continue
                }
                Some(a) => a.label(),
                None => continue,
            },
            Body::Review { to, .. } if *to == me.member && board.closer_of(&e.id).is_none() => {
                "open".to_owned()
            }
            _ => continue,
        };
        println!(
            "{} {:<7} from {:<8} {}  {state}",
            e.id,
            kind_name(e.event.kind),
            e.member.as_deref().unwrap_or("?"),
            detail(e)
        );
    }
    Ok(())
}
