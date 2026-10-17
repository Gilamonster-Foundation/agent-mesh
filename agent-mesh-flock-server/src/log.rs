//! The log file: exclusive lock, append with one fsync, torn-tail cut.

use crate::frame::{self, Next};
use crate::{lock, ServerError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// Test-only: where an append dies. No clock, no sleeps; the write path is
/// simply stopped at a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPlan {
    /// Write the first `n` bytes of the frame, then die (no fsync).
    AfterBytes(usize),
    /// Write all of it, die before the fsync.
    BeforeSync,
    /// Write and fsync, die before the reply.
    AfterSync,
}

/// The open, locked log.
pub struct Log {
    file: File,
    end: u64,
    /// Where an incomplete final frame begins; cut by [`Log::commit_recovery`].
    cut: Option<u64>,
    plan: Option<CrashPlan>,
    /// How many times the file has been fsynced (recovery and appends): a
    /// test-visible witness that a barrier happened.
    syncs: u64,
}

impl Log {
    /// Open and lock `path` and parse every frame. Nothing is modified: an
    /// incomplete final frame is only noted, and cut by
    /// [`commit_recovery`](Self::commit_recovery) once the caller has verified
    /// everything before it. Returns the log and the whole frames with their
    /// byte offsets.
    ///
    /// # Errors
    /// [`ServerError::Locked`]; I/O; [`ServerError::Corrupt`] for damage in
    /// committed history.
    pub fn open<T: Serialize + DeserializeOwned>(
        path: &Path,
    ) -> Result<(Self, Vec<(u64, T)>), ServerError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        lock::lock_exclusive(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (frames, at, cut) = parse(&bytes)?;
        // Appends go to the end whatever the read left behind.
        let log = Self {
            file,
            end: at,
            cut,
            plan: None,
            syncs: 0,
        };
        Ok((log, frames))
    }

    /// Cut off the incomplete final frame, if there was one. Call only after
    /// the retained frames have been verified.
    ///
    /// # Errors
    /// I/O.
    pub fn commit_recovery(&mut self) -> Result<(), ServerError> {
        if let Some(at) = self.cut.take() {
            self.file.set_len(at)?;
            self.file.sync_all()?;
        } else {
            // Whole frames can be on disk without ever having been synced
            // (an append that died before its fsync). Once they are about
            // to be published to readers they must be durable.
            self.file.sync_data()?;
        }
        self.syncs += 1;
        Ok(())
    }

    /// How many fsyncs the log has done.
    #[must_use]
    pub fn syncs(&self) -> u64 {
        self.syncs
    }

    /// Arm a crash for the next append.
    pub fn plan(&mut self, plan: Option<CrashPlan>) {
        self.plan = plan;
    }

    /// Write one frame and fsync it.
    ///
    /// # Errors
    /// I/O, or the planned crash (as `Io` of kind `Other`).
    pub fn append<T: Serialize>(&mut self, value: &T) -> Result<(), ServerError> {
        use std::io::{Seek, SeekFrom};
        let bytes = frame::encode(value)?;
        self.file.seek(SeekFrom::Start(self.end))?;
        let crash = || ServerError::Io(std::io::Error::other("injected crash"));
        match self.plan.take() {
            Some(CrashPlan::AfterBytes(n)) => {
                self.file.write_all(&bytes[..n.min(bytes.len())])?;
                return Err(crash());
            }
            Some(CrashPlan::BeforeSync) => {
                self.file.write_all(&bytes)?;
                return Err(crash());
            }
            Some(CrashPlan::AfterSync) => {
                self.file.write_all(&bytes)?;
                self.file.sync_data()?;
                return Err(crash());
            }
            None => {}
        }
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        self.syncs += 1;
        self.end += bytes.len() as u64;
        Ok(())
    }
}

/// The whole frames with their offsets, where they end, and where an
/// incomplete final frame begins.
type Parsed<T> = (Vec<(u64, T)>, u64, Option<u64>);

/// Parse every whole frame in `bytes`.
fn parse<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<Parsed<T>, ServerError> {
    let mut frames = Vec::new();
    let mut at = 0usize;
    let mut cut = None;
    loop {
        match frame::next(bytes, at) {
            Ok(Next::End) => break,
            Ok(Next::Torn) => {
                cut = Some(at as u64);
                break;
            }
            Ok(Next::Frame(f, end)) => {
                frames.push((at as u64, f));
                at = end;
            }
            Err(why) => {
                return Err(ServerError::Corrupt {
                    offset: at as u64,
                    why,
                })
            }
        }
    }
    Ok((frames, at as u64, cut))
}

/// Read the whole frames of `path` without the lock and without writing:
/// whatever a concurrent append has half written is simply not there yet.
/// Returns the frames and whether an incomplete final frame was left unread.
///
/// # Errors
/// I/O, or [`ServerError::Corrupt`] for damage in committed history.
pub fn read_frames<T: Serialize + DeserializeOwned>(
    path: &Path,
) -> Result<(Vec<(u64, T)>, bool), ServerError> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    let (frames, _, cut) = parse(&bytes)?;
    Ok((frames, cut.is_some()))
}
