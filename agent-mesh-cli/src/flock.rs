//! `amesh flock` — the flock server's command line.

use crate::util;
use agent_mesh_flock::{Member, Role};
use agent_mesh_flock_server::{init as flock_init, InitSpec};
use agent_mesh_protocol::UserKey;
use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use rand::RngCore;
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
}

/// Dispatch a flock subcommand.
pub fn run(home: PathBuf, cmd: FlockCommand) -> Result<()> {
    match cmd {
        FlockCommand::Init { name, members, dir } => init(home, name, &members, dir),
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
