//! `amesh flock nudge`: the herdr adapter. It follows the verified log as the
//! adapter member's session (the session signs; this process holds no key),
//! finds briefs and reviews whose addressee has done nothing about them, runs
//! the nudge sequence (`nudge.rs`) and emits what it found through the session.
//!
//! It keeps no state of its own beyond the reader's saved head: what still
//! needs a nudge is derived from the log, so a restart never nudges an event
//! twice. An event that was refused or timed out has nothing in the log citing
//! it (only a `status`), so a restart tries it again once; within one run
//! every event is tried once, with no timers and no retries.

use super::discover::Where;
use super::nudge::{nudge, Job, Outcome, Scope, Target};
use super::panes::{claims, parse_maps};
use crate::herdr::{HerdrControl, System};
use agent_mesh_flock::{Board, Body, Kind, Role};
use agent_mesh_flock_server::private_dir;
use agent_mesh_flock_session::{call, session_prover, CtlReq, CtlResp, Reader, RealFs, Seen};
use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use content_addressable::{ContentAddressable as _, ContentId, MerkleNode};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Args, Debug, Clone)]
pub struct Opts {
    /// Seconds to wait for a pane to go idle before giving up on that nudge.
    #[arg(long, default_value_t = 120)]
    pub wait_timeout: u64,
    /// Map a member to a pane id, `member=pane` (repeatable).
    #[arg(long = "map")]
    pub maps: Vec<String>,
    /// Never nudge here: `tab:<id>`, `workspace:<id>` or `pane:<id>`
    /// (repeatable; also `<home>/herdr-nudge.deny`).
    #[arg(long)]
    pub deny: Vec<String>,
    /// Only nudge here when any is given (repeatable; also
    /// `<home>/herdr-nudge.allow`).
    #[arg(long)]
    pub allow: Vec<String>,
    /// Handle what is pending once caught up, then stop.
    #[arg(long)]
    pub once: bool,
}

/// Briefs and reviews that need a nudge, in admission order: addressed to a
/// roster member who is nudged at all, not an operator's or an adapter's, and
/// with nothing to show they were handled (an `ack`, a `nudged` or a
/// `nudge-misfire` citing them, or, for a brief, a result).
fn pending(board: &Board) -> Vec<(ContentId, String)> {
    let handled = |id: &ContentId| {
        board.closer_of(id).is_some()
            || board.entries().any(|e| {
                matches!(e.event.kind, Kind::Ack | Kind::Nudged | Kind::NudgeMisfire)
                    && e.event.refs.get("of") == Some(id)
            })
    };
    board
        .entries()
        .filter(|e| e.conflict.is_none())
        .filter_map(|e| match &e.event.body {
            Body::Brief { to, .. } | Body::Review { to, .. } => Some((e.id, to)),
            _ => None,
        })
        .filter(|(_, to)| {
            board
                .members()
                .iter()
                .any(|m| &m.name == *to && !matches!(m.role, Role::Operator | Role::Adapter))
        })
        .filter(|(id, _)| !handled(id))
        .map(|(id, to)| (id, to.clone()))
        .collect()
}

/// What to record for `outcome`, as an `Emit`.
fn record(of: ContentId, outcome: Outcome) -> (Kind, BTreeMap<String, ContentId>, Body) {
    let cites = BTreeMap::from([("of".to_owned(), of)]);
    match outcome {
        Outcome::Nudged { target } => (Kind::Nudged, cites, Body::Nudged { target }),
        Outcome::Misfire {
            target,
            expected,
            found,
        } => (
            Kind::NudgeMisfire,
            cites,
            Body::NudgeMisfire {
                target,
                expected,
                found,
            },
        ),
        Outcome::Status(text) => (
            Kind::Status,
            BTreeMap::new(),
            Body::Status {
                text: format!("{text} (of {of})"),
            },
        ),
    }
}

struct Ctx<'a> {
    socket: &'a Path,
    wait_ms: u64,
    explicit: BTreeMap<String, String>,
    own_pane: Option<String>,
    scope: Scope,
}

impl Ctx<'_> {
    /// Nudge everything pending that this run has not tried.
    fn act(
        &self,
        board: &Board,
        sessions: &agent_mesh_flock_server::Sessions,
        tried: &mut BTreeSet<ContentId>,
    ) {
        let claimed = claims(board, sessions);
        for (id, to) in pending(board) {
            if !tried.insert(id) {
                continue;
            }
            let outcome = nudge(
                &HerdrControl(System),
                &Job {
                    target: Target {
                        roster: board.members(),
                        member: &to,
                        claims: &claimed,
                        explicit: &self.explicit,
                        own_pane: self.own_pane.as_deref(),
                        scope: &self.scope,
                    },
                    of: &id,
                    wait_ms: self.wait_ms,
                },
            );
            let (kind, refs, body) = record(id, outcome);
            let said = format!("{kind:?}");
            match call(self.socket, &CtlReq::Emit { kind, refs, body }) {
                Ok(CtlResp::Admitted { event, index }) => {
                    println!("{said} of {id}: admitted {event} at {index}");
                }
                // admission said no, or the session is gone: say so and go on;
                // this event is not tried again in this run
                Ok(_) | Err(_) => eprintln!("{said} of {id}: not recorded"),
            }
        }
    }
}

pub fn run(home: &Path, w: &Where, opts: &Opts) -> Result<()> {
    let dir = w.dir(home)?;
    let (socket, me) = w.session(home)?;
    let genesis = agent_mesh_flock_server::load_genesis(&dir)
        .map_err(|e| anyhow!("read the genesis in {}: {e}", dir.display()))?
        .node;
    let id = MerkleNode::genesis(me.member.clone())
        .content_id()
        .map_err(|e| anyhow!("name the reader directory: {e}"))?;
    let base = dir.join("nudge");
    let state: PathBuf = base.join(id.to_string());
    for d in [&base, &state] {
        private_dir(d).with_context(|| format!("reader directory {}", d.display()))?;
    }
    let mut reader = Reader::open(genesis, &state, RealFs).map_err(|e| anyhow!("{e}"))?;
    // fail early: admission would refuse a nudge from anyone else anyway
    let role = reader
        .follower()
        .board()
        .members()
        .iter()
        .find(|m| m.name == me.member)
        .map(|m| m.role);
    if role != Some(Role::Adapter) {
        bail!(
            "'{}' is not the adapter: run `nudge` as the session of the roster's adapter member",
            agent_mesh_flock::text::inert(&me.member)
        );
    }
    let ctx = Ctx {
        socket: &socket,
        wait_ms: opts.wait_timeout.saturating_mul(1000),
        explicit: parse_maps(&opts.maps)?,
        own_pane: std::env::var("HERDR_PANE_ID").ok(),
        scope: Scope::load(home, &opts.deny, &opts.allow)?,
    };
    let (serve, prove) = (dir.join("run").join("serve.sock"), session_prover(&socket));
    let (mut live, mut tried) = (false, BTreeSet::new());
    let reason = reader
        .follow(&serve, &prove, opts.once, &mut |seen| {
            let f = match seen {
                Seen::Frame(_, f) => f,
                Seen::Caught(_, f) => {
                    live = true;
                    f
                }
            };
            // nothing is decided from a partial replay: a `nudged` may still
            // be on its way
            if live {
                ctx.act(f.board(), f.sessions(), &mut tried);
            }
        })
        .map_err(|e| anyhow!("{e}"))?;
    if opts.once {
        return Ok(());
    }
    Err(anyhow!("the stream closed: {reason}"))
}
