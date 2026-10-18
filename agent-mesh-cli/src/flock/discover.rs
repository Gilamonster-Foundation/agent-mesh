//! Finding the session to talk to, and the flock directory to read.
//!
//! Never guesses: zero or several live sessions is an error that names them.

use agent_mesh_flock_session::{call, CtlReq, CtlResp};
use anyhow::{anyhow, bail, Result};
use clap::Args;
use content_addressable::{ContentAddressable as _, ContentId};
use std::path::{Path, PathBuf};

/// Which flock, and which session of it.
#[derive(Args, Debug, Clone, Default)]
pub struct Where {
    /// Flock directory.
    #[arg(long)]
    pub dir: Option<PathBuf>,
    /// Flock name (directory `<home>/flocks/<name>`).
    #[arg(long)]
    pub name: Option<String>,
    /// The session's socket. Otherwise `AMESH_FLOCK_SESSION`, otherwise the
    /// one live session in the flock directory.
    #[arg(long, env = "AMESH_FLOCK_SESSION")]
    pub session: Option<PathBuf>,
}

/// Who a session says it is.
pub struct Who {
    pub flock: ContentId,
    pub member: String,
    pub session: String,
    pub pending: bool,
}

impl Where {
    /// The flock directory.
    pub fn dir(&self, home: &Path) -> Result<PathBuf> {
        match (&self.dir, &self.name) {
            (Some(d), _) => Ok(d.clone()),
            (None, Some(n)) => Ok(home.join("flocks").join(n)),
            (None, None) => bail!("say which flock: --dir <path> or --name <flock>"),
        }
    }

    /// The flock id the caller named, if they named a flock at all.
    fn named(&self, home: &Path) -> Result<Option<ContentId>> {
        if self.dir.is_none() && self.name.is_none() {
            return Ok(None);
        }
        let dir = self.dir(home)?;
        let g = agent_mesh_flock_server::load_genesis(&dir)
            .map_err(|e| anyhow!("read the genesis in {}: {e}", dir.display()))?;
        Ok(Some(g.node.content_id()?))
    }

    /// The session to use and who it says it is. When a flock is named
    /// (`--dir`/`--name`) the session must belong to it: a session of another
    /// flock is refused before anything is sent. With no flock named the
    /// session alone decides. This is destination checking; whether the event
    /// is allowed is admission's job.
    pub fn session(&self, home: &Path) -> Result<(PathBuf, Who)> {
        let want = self.named(home)?;
        let belongs = |me: &Who| want.is_none_or(|w| w == me.flock);
        if let Some(socket) = &self.session {
            let me = who(socket)?;
            if !belongs(&me) {
                bail!(
                    "{} is a session of another flock than the one named",
                    socket.display()
                );
            }
            return Ok((socket.clone(), me));
        }
        let dir = self.dir(home).map_err(|_| {
            anyhow!("say which session: --session <socket>, AMESH_FLOCK_SESSION, or --dir/--name")
        })?;
        let run = dir.join("run");
        let mut live = vec![];
        for e in std::fs::read_dir(&run)
            .map_err(|e| anyhow!("cannot read {}: {e}", run.display()))?
            .flatten()
        {
            let p = e.path();
            let named = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("session-") && n.ends_with(".sock"));
            // a killed session leaves its socket file behind: skip what does not
            // answer, and what answers for another flock
            if let Some(me) = named.then(|| who(&p).ok()).flatten().filter(|m| belongs(m)) {
                live.push((p, me));
            }
        }
        live.sort_by(|a, b| a.0.cmp(&b.0));
        match live.len() {
            1 => Ok(live.remove(0)),
            0 => bail!(
                "no live session in {} (is `amesh flock session` running?)",
                run.display()
            ),
            _ => bail!(
                "several live sessions; pick one with --session:\n  {}",
                live.iter()
                    .map(|(p, _)| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\n  ")
            ),
        }
    }
}

/// Ask a session who it is.
pub fn who(socket: &Path) -> Result<Who> {
    match call(socket, &CtlReq::Whoami)? {
        CtlResp::Who {
            flock,
            member,
            session,
            pending,
        } => Ok(Who {
            flock,
            member,
            session,
            pending,
        }),
        _ => bail!("the session answered something else"),
    }
}
