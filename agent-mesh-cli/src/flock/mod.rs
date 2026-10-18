//! `amesh flock` — the flock server's command line.

use crate::util;
use agent_mesh_flock::{Member, Role};
use agent_mesh_flock_server::{init as flock_init, InitSpec};
use agent_mesh_protocol::UserKey;
use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use rand::RngCore;
use std::path::PathBuf;

mod panes;

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
    /// Serve the flock's log on a local socket (owns the log; run once).
    #[cfg(unix)]
    Serve {
        /// Flock directory.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Mint an invite for a member through the running server; prints the
    /// token once.
    #[cfg(unix)]
    Invite {
        /// Flock directory.
        #[arg(long)]
        dir: PathBuf,
        /// The roster member.
        member: String,
    },
    /// Hold one session key in memory and serve the CLI over a socket
    /// (like ssh-agent -D). The key is locked in RAM; core dumps are off.
    #[cfg(unix)]
    Session {
        /// Flock directory (where the server's socket is).
        #[arg(long)]
        dir: PathBuf,
        /// The roster member to enroll as.
        #[arg(long)]
        member: String,
        /// Invite token. Prefer the environment: argv shows in `ps`.
        #[arg(long, env = "AMESH_FLOCK_TOKEN", hide_env_values = true)]
        token: String,
        /// Where to listen (default: `<dir>/run/session-<pid>.sock`).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Carry on if memory cannot be locked: the key may reach swap.
        #[arg(long)]
        allow_unlocked: bool,
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
        #[cfg(unix)]
        FlockCommand::Serve { dir } => unix::serve(&dir),
        #[cfg(unix)]
        FlockCommand::Invite { dir, member } => unix::invite(&dir, &member),
        #[cfg(unix)]
        FlockCommand::Session {
            dir,
            member,
            token,
            socket,
            allow_unlocked,
        } => unix::session(&dir, &member, &token, socket, allow_unlocked),
        FlockCommand::Panes {
            name,
            dir,
            tab,
            maps,
        } => panes::panes(&home, &name, dir, tab.as_deref(), &maps),
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
        devices: vec![],
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

#[cfg(unix)]
mod unix {
    use super::{anyhow, Context, PathBuf, Result};
    use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
    use agent_mesh_flock_server::{bind_private, serve as serve_log, Server};
    use agent_mesh_flock_session::Policy;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    fn sock(dir: &Path) -> PathBuf {
        dir.join("run").join("serve.sock")
    }

    pub fn serve(dir: &Path) -> Result<()> {
        let server = Server::open(dir).with_context(|| format!("open {}", dir.display()))?;
        // The log lock is ours, so any socket file left behind is stale.
        let listener = bind_private(&sock(dir))?;
        println!("serving {}", sock(dir).display());
        match serve_log(server, listener)?.wait() {
            Some(why) => Err(anyhow!("stopped: could not persist: {why}")),
            None => Ok(()),
        }
    }

    pub fn invite(dir: &Path, member: &str) -> Result<()> {
        let mut c = UnixStream::connect(sock(dir)).context("is `amesh flock serve` running?")?;
        write_msg(
            &mut c,
            &Req::Invite {
                member: member.into(),
            },
        )?;
        match read_msg::<Resp>(&mut c)? {
            Some(Resp::Invited { token }) => println!("{token}"),
            Some(Resp::Err(why)) => return Err(anyhow!("refused: {why}")),
            _ => return Err(anyhow!("unexpected answer")),
        }
        Ok(())
    }

    pub fn session(
        dir: &Path,
        member: &str,
        token: &str,
        socket: Option<PathBuf>,
        allow_unlocked: bool,
    ) -> Result<()> {
        let path = socket.unwrap_or_else(|| {
            dir.join("run")
                .join(format!("session-{}.sock", std::process::id()))
        });
        let listener = bind_private(&path)?;
        let policy = if allow_unlocked {
            eprintln!("warning: --allow-unlocked: the session key may be swapped to disk");
            Policy::AllowUnlocked
        } else {
            Policy::Locked
        };
        // herdr sets both in every pane; either alone is not a claim.
        let pane = std::env::var("HERDR_PANE_ID")
            .ok()
            .zip(std::env::var("HERDR_TAB_ID").ok());
        let result = agent_mesh_flock_session::run(
            &sock(dir),
            token,
            member,
            policy,
            &listener,
            pane,
            |s| {
                println!("session: {}", s.id());
                println!("socket: {}", path.display());
            },
        );
        let _ = std::fs::remove_file(&path);
        result.map_err(Into::into)
    }
}
