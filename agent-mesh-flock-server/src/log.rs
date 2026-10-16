//! The log file: exclusive lock, append with one fsync, torn-tail cut.

use crate::frame::{self, Frame, Next};
use crate::{lock, ServerError};
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
    plan: Option<CrashPlan>,
}

impl Log {
    /// Open and lock `path`, read every frame and cut off a torn tail.
    /// Returns the log and the committed frames with their byte offsets.
    ///
    /// # Errors
    /// [`ServerError::Locked`]; I/O; [`ServerError::Corrupt`] for damage in
    /// committed history.
    pub fn open(path: &Path) -> Result<(Self, Vec<(u64, Frame)>), ServerError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        lock::lock_exclusive(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let mut frames = Vec::new();
        let mut at = 0usize;
        loop {
            match frame::next(&bytes, at) {
                Ok(Next::End) => break,
                Ok(Next::Torn) => {
                    file.set_len(at as u64)?;
                    file.sync_all()?;
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
            plan: None,
        };
        Ok((log, frames))
    }

    /// Arm a crash for the next append.
    pub fn plan(&mut self, plan: Option<CrashPlan>) {
        self.plan = plan;
    }

    /// Write one frame and fsync it.
    ///
    /// # Errors
    /// I/O, or the planned crash (as `Io` of kind `Other`).
    pub fn append(&mut self, frame: &Frame) -> Result<(), ServerError> {
        use std::io::{Seek, SeekFrom};
        let bytes = frame::encode(frame)?;
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
