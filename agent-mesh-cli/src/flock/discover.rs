//! Finding the session to talk to, and the flock directory to read.
//!
//! Never guesses: zero or several live sessions is an error that names them.

use agent_mesh_flock_session::{call, CtlReq, CtlResp};
use anyhow::{anyhow, bail, Result};
use clap::Args;
use content_addressable::ContentId;
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

    /// The session socket to use.
    pub fn socket(&self, home: &Path) -> Result<PathBuf> {
        if let Some(s) = &self.session {
            return Ok(s.clone());
        }
        let dir = self.dir(home).map_err(|_| {
            anyhow!("say which session: --session <socket>, AMESH_FLOCK_SESSION, or --dir/--name")
        })?;
        let mut live = vec![];
        let run = dir.join("run");
        for e in std::fs::read_dir(&run)
            .map_err(|e| anyhow!("cannot read {}: {e}", run.display()))?
            .flatten()
        {
            let p = e.path();
            let named = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("session-") && n.ends_with(".sock"));
            // a killed session leaves its socket file behind: skip what does not answer
            if named && who(&p).is_ok() {
                live.push(p);
            }
        }
        live.sort();
        match live.as_slice() {
            [one] => Ok(one.clone()),
            [] => bail!(
                "no live session in {} (is `amesh flock session` running?)",
                run.display()
            ),
            many => bail!(
                "several live sessions; pick one with --session:\n  {}",
                many.iter()
                    .map(|p| p.display().to_string())
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
