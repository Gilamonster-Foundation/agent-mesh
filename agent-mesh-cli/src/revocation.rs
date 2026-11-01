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
    locked(&path, || save(&path, &RevocationLog::genesis(key)?))?;
    println!("revocation log:   {}", path.display());
    Ok(())
}

/// Refuse early if a log already sits where a fresh key's log would go: a new
/// key can never own it, so `amesh keygen` must fail before it writes the key.
pub fn preflight_new_key(key_path: &Path) -> Result<()> {
    let path = key_path.with_file_name(LOG_FILE);
    if path.exists() {
        bail!(
            "revocation log already exists at {} — move it aside before generating a new key",
            path.display()
        );
    }
    Ok(())
}

fn init(home: &Path) -> Result<()> {
    let path = home.join(LOG_FILE);
    let key = load_key(home)?;
    locked(&path, || {
        if path.exists() {
            bail!("revocation log already exists at {}", path.display());
        }
        save(&path, &RevocationLog::genesis(&key)?)
    })?;
    println!("created revocation log at {}", path.display());
    Ok(())
}

/// `amesh revoke <agent-fingerprint>`.
pub fn revoke(home: &Path, agent: &str) -> Result<()> {
    let agent: Fingerprint = agent
        .parse()
        .map_err(|e| anyhow!("bad agent fingerprint: {e}"))?;
    let key = load_key(home)?;
    let path = home.join(LOG_FILE);
    locked(&path, || {
        let (mut log, state) = load_log(&path)?;
        if state.revoked.contains(&agent) {
            println!("already revoked: {}", agent.hex());
            return Ok(());
        }
        log.append(&key, RevocationEntry::Revoke { agent })?;
        save(&path, &log)?;
        println!("revoked {}", agent.hex());
        Ok(())
    })
}

fn bump(home: &Path) -> Result<()> {
    let key = load_key(home)?;
    let path = home.join(LOG_FILE);
    locked(&path, || {
        let (mut log, state) = load_log(&path)?;
        let current = state.generation + 1;
        log.append(&key, RevocationEntry::Generation { current })?;
        save(&path, &log)?;
        println!("generation {current}");
        Ok(())
    })
}

fn show(home: &Path) -> Result<()> {
    let (_, st) = load_log(&home.join(LOG_FILE))?;
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
    let (log, _) = load_log(&home.join(LOG_FILE))?;
    locked(dest, || save(dest, &log))?;
    println!("exported to {}", dest.display());
    Ok(())
}

fn load_key(home: &Path) -> Result<UserKey> {
    let p = home.join("user.key");
    UserKey::load(&p).with_context(|| format!("load {} — run `amesh keygen` first?", p.display()))
}

/// Read and verify the log; a log that fails `verify()` stops the command.
fn load_log(path: &Path) -> Result<(RevocationLog, RevocationState)> {
    let log = read(path)?.with_context(|| {
        format!(
            "no revocation log at {} — run `amesh revocation init`",
            path.display()
        )
    })?;
    let state = log
        .verify()
        .with_context(|| format!("{} failed verification; refusing", path.display()))?;
    Ok((log, state))
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
    let dir = dir_of(path);
    std::fs::create_dir_all(dir)?;
    let (tmp, mut f) = create_tmp(dir, path)?;
    let written = f
        .write_all(serde_json::to_string_pretty(log)?.as_bytes())
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("write {}", path.display()));
    }
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// A fresh temp file beside `dest`: `create_new` (never follows or truncates an
/// existing path) under an unpredictable name, mode 0600 on Unix.
fn create_tmp(dir: &Path, dest: &Path) -> Result<(PathBuf, std::fs::File)> {
    let name = dest
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    for _ in 0..8 {
        let tmp = dir.join(format!(".{name}.{:032x}.tmp", rand::random::<u128>()));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        match o.open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("create {}", tmp.display())),
        }
    }
    bail!("could not create a temp file in {}", dir.display())
}

/// Run `f` holding an exclusive lock on `<path>.lock`, so read → extends-check
/// → rename is one step across processes. The lock file is never truncated and
/// is released when the handle drops.
fn locked<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let dir = dir_of(path);
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let lock_path = dir.join(format!("{name}.lock"));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("lock {}", lock_path.display()))?;
    f()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A pre-planted symlink at the old predictable temp name (`<stem>.tmp.<pid>`)
    /// must not be followed: its target stays byte-for-byte as it was.
    #[test]
    fn a_planted_tmp_symlink_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("user.key");
        std::fs::write(&victim, "precious").unwrap();
        let dest = dir.path().join("export.json");
        let planted = dest.with_extension(format!("tmp.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        let log = RevocationLog::genesis(&UserKey::generate()).unwrap();
        save(&dest, &log).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(read(&dest).unwrap().unwrap(), log);
    }
}
