//! `amesh revoke` and `amesh revocation …` — the user's signed revocation log.
//!
//! The log is the JSON container from `agent_mesh_protocol::revocation`, kept
//! beside `user.key` as `revocation.json`. Every write verifies what is on
//! disk first, appends, and saves by temp file + fsync + rename + directory
//! fsync, refusing a log that does not extend the one already there. History
//! is never rewritten. Commands sign with the loaded user key; no key
//! material is printed or written.

use agent_mesh_protocol::{Fingerprint, RevocationEntry, RevocationLog, RevocationState, UserKey};
use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use std::io::Write;
use std::path::{Path, PathBuf};

/// File name of the log, beside `user.key`.
const LOG_FILE: &str = "revocation.json";

/// `amesh revocation <command>`.
#[derive(Subcommand, Debug)]
pub enum RevocationCommand {
    /// Write a genesis log for an existing user key that has none.
    Init,
    /// Move the generation up by one; certs scoped to older generations lapse.
    Bump,
    /// Print the verified log: user, length, head, generation, revoked set.
    Show,
    /// Write a copy of the verified log to `path` (atomically).
    Export {
        /// Destination file.
        path: PathBuf,
    },
}

/// Dispatch `amesh revocation …`.
pub fn run(home: &Path, command: RevocationCommand) -> Result<()> {
    match command {
        RevocationCommand::Init => init(home),
        RevocationCommand::Bump => bump(home),
        RevocationCommand::Show => show(home),
        RevocationCommand::Export { path } => export(home, &path),
    }
}

/// Write the genesis log next to `key_path` (used by `amesh keygen`).
pub fn init_beside(key_path: &Path, key: &UserKey) -> Result<()> {
    let path = key_path.with_file_name(LOG_FILE);
    save(&path, &RevocationLog::genesis(key)?)?;
    println!("revocation log:   {}", path.display());
    Ok(())
}

fn init(home: &Path) -> Result<()> {
    let path = home.join(LOG_FILE);
    if path.exists() {
        bail!("revocation log already exists at {}", path.display());
    }
    let key = load_key(home)?;
    save(&path, &RevocationLog::genesis(&key)?)?;
    println!("created revocation log at {}", path.display());
    Ok(())
}

/// `amesh revoke <agent-fingerprint>`.
pub fn revoke(home: &Path, agent: &str) -> Result<()> {
    let agent: Fingerprint = agent
        .parse()
        .map_err(|e| anyhow!("bad agent fingerprint: {e}"))?;
    let key = load_key(home)?;
    let (path, mut log, state) = load_log(home)?;
    if state.revoked.contains(&agent) {
        println!("already revoked: {}", agent.hex());
        return Ok(());
    }
    log.append(&key, RevocationEntry::Revoke { agent })?;
    save(&path, &log)?;
    println!("revoked {}", agent.hex());
    Ok(())
}

fn bump(home: &Path) -> Result<()> {
    let key = load_key(home)?;
    let (path, mut log, state) = load_log(home)?;
    let current = state.generation + 1;
    log.append(&key, RevocationEntry::Generation { current })?;
    save(&path, &log)?;
    println!("generation {current}");
    Ok(())
}

fn show(home: &Path) -> Result<()> {
    let (_, _, st) = load_log(home)?;
    println!("user:       {}", st.user.hex());
    println!("length:     {}", st.len);
    println!("head:       {}", st.head);
    println!("generation: {}", st.generation);
    println!("revoked:    {}", st.revoked.len());
    for a in &st.revoked {
        println!("  {}", a.hex());
    }
    Ok(())
}

fn export(home: &Path, dest: &Path) -> Result<()> {
    let (_, log, _) = load_log(home)?;
    save(dest, &log)?;
    println!("exported to {}", dest.display());
    Ok(())
}

fn load_key(home: &Path) -> Result<UserKey> {
    let p = home.join("user.key");
    UserKey::load(&p).with_context(|| format!("load {} — run `amesh keygen` first?", p.display()))
}

/// Read and verify the log; a log that fails `verify()` stops the command.
fn load_log(home: &Path) -> Result<(PathBuf, RevocationLog, RevocationState)> {
    let path = home.join(LOG_FILE);
    let log = read(&path)?.with_context(|| {
        format!(
            "no revocation log at {} — run `amesh revocation init`",
            path.display()
        )
    })?;
    let state = log
        .verify()
        .with_context(|| format!("{} failed verification; refusing", path.display()))?;
    Ok((path, log, state))
}

fn read(path: &Path) -> Result<Option<RevocationLog>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(
            serde_json::from_str(&s).with_context(|| format!("parse {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Save `log` at `path` by temp file + fsync + rename + directory fsync.
/// If a log is already there it must verify and `log` must extend it.
fn save(path: &Path, log: &RevocationLog) -> Result<()> {
    log.verify().context("refusing to save an invalid log")?;
    if let Some(old) = read(path)? {
        let seen = old
            .verify()
            .with_context(|| format!("{} failed verification; refusing", path.display()))?
            .seen();
        log.extends(&seen)
            .with_context(|| format!("new log does not extend {}", path.display()))?;
        if old == *log {
            return Ok(());
        }
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut f = std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
    f.write_all(serde_json::to_string_pretty(log)?.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}
