//! `run -- <cmd>`: a job in the log with the command's real ending.

use super::discover::Where;
use super::emit::send;
use agent_mesh_flock::{Body, Kind};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::Command;

/// How a process ended, as the `job-end` records it.
fn ending(status: std::process::ExitStatus) -> (Option<i64>, Option<i32>) {
    match status.signal() {
        Some(s) => (None, Some(s)),
        None => (Some(i64::from(status.code().unwrap_or(-1))), None),
    }
}

/// Emit `job`, run the command with inherited stdio, emit `job-end`, and
/// return the status this process should exit with (128 + signal, like a
/// shell). Both events go through the one session chosen up front, so a
/// session of another flock than the one named is refused before anything
/// runs.
///
/// ponytail: if this process is itself killed, no `job-end` is written and
/// the job stays open. Upgrade: a supervisor that outlives the child.
pub fn run(
    home: &Path,
    w: &Where,
    lane: String,
    label: Option<String>,
    cmd: &[String],
) -> Result<i32> {
    let Some((prog, args)) = cmd.split_first() else {
        bail!("say what to run: amesh flock run --lane L -- <cmd> [args]");
    };
    let (socket, _) = w.session(home)?;
    let label = label.unwrap_or_else(|| prog.clone());
    let (job, _) = send(
        &socket,
        Kind::Job,
        BTreeMap::new(),
        Body::Job { lane, label },
    )?;
    eprintln!("job {job}");
    let (code, signal, exit, failure) = match Command::new(prog).args(args).status() {
        Ok(status) => {
            let (code, signal) = ending(status);
            let exit = signal.map_or_else(|| code.map_or(1, |c| c as i32), |s| 128 + s);
            (code, signal, exit, None)
        }
        // it never started: 127, as a shell says
        Err(e) => (
            Some(127),
            None,
            127,
            Some(format!("cannot run {prog}: {e}")),
        ),
    };
    let refs = BTreeMap::from([("job".to_owned(), job)]);
    let (end, _) = send(&socket, Kind::JobEnd, refs, Body::JobEnd { code, signal })?;
    eprintln!("job-end {end}");
    match failure {
        Some(why) => bail!(why),
        None => Ok(exit),
    }
}
