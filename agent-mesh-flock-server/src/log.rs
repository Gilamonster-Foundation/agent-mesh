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
        let mut frames = Vec::new();
        let mut at = 0usize;
        let mut cut = None;
        loop {
            match frame::next(&bytes, at) {
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
        // Appends go to the end whatever the read left behind.
        let log = Self {
            file,
            end: at as u64,
            cut,
            plan: None,
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
        }
        Ok(())
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
        self.end += bytes.len() as u64;
        Ok(())
    }
}
