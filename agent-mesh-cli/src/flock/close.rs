//! Which brief a `result` (or review a `verdict`) is for. A closer sent to a
//! target that is already closed is admitted as a conflict that closes
//! nothing, and the lane stays open: correct, but easy to do by accident on a
//! fix round, when a lane has an old closed brief and a new open one. So the
//! CLI resolves the target from the verified log (the stream, so also from an attached flock) instead of trusting the id it
//! was handed, and refuses (before sending anything) the one that cannot work.

use super::discover::Where;
use agent_mesh_flock::text::inert;
use agent_mesh_flock::{Board, Body, Entry, Kind};
use agent_mesh_flock_server::private_dir;
use agent_mesh_flock_session::{session_prover, Reader, RealFs, Seen};
use anyhow::{anyhow, bail, Context, Result};
use content_addressable::{ContentAddressable as _, ContentId, MerkleNode};
use std::path::{Path, PathBuf};

/// What is being closed.
#[derive(Clone, Copy)]
pub enum Closing {
    /// A brief, by a `result`.
    Brief,
    /// A review, by a `verdict`.
    Review,
}

impl Closing {
    fn kind(self) -> Kind {
        match self {
            Self::Brief => Kind::Brief,
            Self::Review => Kind::Review,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Brief => "brief",
            Self::Review => "review",
        }
    }

    fn closer(self) -> &'static str {
        match self {
            Self::Brief => "result",
            Self::Review => "verdict",
        }
    }
}

/// The flock directory: the one named, else the one the session socket lives
/// in (`<dir>/run/session-*.sock`).
fn flock_dir(home: &Path, w: &Where, socket: &Path) -> Result<PathBuf> {
    if let Ok(dir) = w.dir(home) {
        return Ok(dir);
    }
    socket
        .parent()
        .filter(|run| run.file_name().is_some_and(|n| n == "run"))
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("say which flock: --dir <path> or --name <flock>"))
}

/// The board as the verified stream shows it, caught up: the same path
/// `watch` takes, so it works on an attached flock directory (a pinned genesis
/// and a proxy socket, no local log) as at home. The reader keeps its own
/// state under `<dir>/close/`, apart from `watch`'s.
fn verified_board(dir: &Path, socket: &Path, member: &str) -> Result<Board> {
    let genesis = agent_mesh_flock_server::load_genesis(dir)
        .map_err(|e| anyhow!("read the genesis in {}: {e}", dir.display()))?
        .node;
    let id = MerkleNode::genesis(member.to_owned())
        .content_id()
        .map_err(|e| anyhow!("name the reader directory: {e}"))?;
    let base = dir.join("close");
    let state = base.join(id.to_string());
    for d in [&base, &state] {
        private_dir(d).with_context(|| format!("reader directory {}", d.display()))?;
    }
    let mut reader = Reader::open(genesis, &state, RealFs).map_err(|e| anyhow!("{e}"))?;
    let mut board = None;
    reader
        .follow(
            &dir.join("run").join("serve.sock"),
            &session_prover(socket),
            true,
            &mut |seen| {
                if let Seen::Caught(_, f) = seen {
                    board = Some(f.board().clone());
                }
            },
        )
        .map_err(|e| anyhow!("{e}"))?;
    board.ok_or_else(|| anyhow!("the stream ended before the log was caught up"))
}

/// `(id, lane)` of `e` if it is a `closing` addressed to `member`.
fn mine<'a>(e: &'a Entry, closing: Closing, member: &str) -> Option<(ContentId, &'a str)> {
    if e.conflict.is_some() || e.event.kind != closing.kind() {
        return None;
    }
    match &e.event.body {
        Body::Brief { to, lane } | Body::Review { to, lane, .. } if to == member => {
            Some((e.id, lane))
        }
        _ => None,
    }
}

fn open_in(board: &Board, closing: Closing, member: &str, lane: &str) -> Vec<ContentId> {
    board
        .entries()
        .filter_map(|e| mine(e, closing, member))
        .filter(|(id, l)| *l == lane && board.closer_of(id).is_none())
        .map(|(id, _)| id)
        .collect()
}

/// The content id to close: `cid` if it names an open target, or the one open
/// target of `member` in `lane`.
///
/// # Errors
/// Neither or both were given; the lane has no open target or several; the
/// named target is already closed (the message names what closed it and the
/// open one in its lane); the log cannot be read.
pub fn pick(
    home: &Path,
    w: &Where,
    closing: Closing,
    cid: Option<&str>,
    lane: Option<&str>,
) -> Result<String> {
    let (socket, me) = w.session(home)?;
    let dir = flock_dir(home, w, &socket)?;
    let board = &verified_board(&dir, &socket, &me.member).context(
        "read the verified log (the target is resolved from it before anything is sent)",
    )?;
    let (noun, closer) = (closing.noun(), closing.closer());
    match (cid, lane) {
        (None, Some(lane)) => {
            let open = open_in(board, closing, &me.member, lane);
            match open.as_slice() {
                [one] => Ok(one.to_string()),
                [] => {
                    let closed: Vec<String> = board
                        .entries()
                        .filter_map(|e| mine(e, closing, &me.member))
                        .filter(|(_, l)| *l == lane)
                        .map(|(id, _)| id.to_string())
                        .collect();
                    if closed.is_empty() {
                        bail!(
                            "no {noun} for {} in lane {}: nothing is addressed to this member there",
                            inert(&me.member),
                            inert(lane)
                        )
                    }
                    bail!(
                        "no open {noun} for {} in lane {}: already closed: {}",
                        inert(&me.member),
                        inert(lane),
                        closed.join(", ")
                    )
                }
                many => bail!(
                    "{} open {noun}s for {} in lane {}; name one by id:\n  {}",
                    many.len(),
                    inert(&me.member),
                    inert(lane),
                    many.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n  ")
                ),
            }
        }
        (Some(cid), None) => {
            if let Ok(id) = cid.parse::<ContentId>() {
                if let Some(first) = board.closer_of(&id) {
                    let lane = board
                        .get(&id)
                        .and_then(|e| mine(e, closing, &me.member))
                        .map(|(_, l)| l.to_owned());
                    let hint = lane
                        .as_deref()
                        .map(|l| (l, open_in(board, closing, &me.member, l)))
                        .filter(|(_, open)| !open.is_empty())
                        .map(|(l, open)| {
                            format!(
                                "; the open {noun} in lane {} is {} (or use --lane {})",
                                inert(l),
                                open.iter()
                                    .map(ToString::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                inert(l)
                            )
                        })
                        .unwrap_or_default();
                    bail!(
                        "{noun} {id} is already closed (by {first}): a second {closer} would be admitted as a conflict that closes nothing and the lane would stay open{hint}"
                    );
                }
            }
            Ok(cid.to_owned())
        }
        _ => bail!("name the {noun} by id or by --lane, not both and not neither"),
    }
}
