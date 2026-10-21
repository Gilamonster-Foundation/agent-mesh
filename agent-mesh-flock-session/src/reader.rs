//! A flock reader: a verified prefix of the log, saved atomically, extended
//! from a stream. The saved file holds the verified frames themselves, so the
//! board is derived by replay and can never drift from them; a head counts as
//! witnessed only once its save has returned.
//!
//! ponytail: every save rewrites the whole file, O(log). Upgrade: delta
//! files, or a snapshot plus a tail.

use crate::fs::{save_atomic, Fs};
use crate::ReaderError;
use agent_mesh_flock::Genesis;
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp, StreamChallenge};
use agent_mesh_flock_server::{FollowError, Follower, Head, Sealed};
use agent_mesh_protocol::Assertion;
use content_addressable::canonical::{from_canonical_dagcbor_checked, to_canonical_dagcbor};
use content_addressable::MerkleNode;
use serde::{Deserialize, Serialize};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const FILE: &str = "reader.state";

/// Signs a stream challenge: the session process in production (the key never
/// leaves it), a held key in tests.
pub type Prover<'a> = &'a dyn Fn(&StreamChallenge) -> Result<Assertion, ReaderError>;

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    frames: Vec<Vec<Sealed>>,
}

/// A saved, verified prefix of a flock.
pub struct Reader<F: Fs> {
    fs: F,
    dir: PathBuf,
    genesis: MerkleNode<Genesis>,
    follower: Follower,
    frames: Vec<Vec<Sealed>>,
    /// Held for the reader's life: one checkpoint writer per directory.
    _lock: Box<dyn std::any::Any + Send>,
}

fn follow(e: FollowError) -> ReaderError {
    match e {
        FollowError::DoesNotExtend(w) => ReaderError::Rollback(w),
        FollowError::Invalid(w) => ReaderError::Invalid(w),
    }
}

impl<F: Fs> Reader<F> {
    /// Load the saved state in `dir` (none yet is an empty reader) and
    /// re-verify every frame in it from genesis.
    ///
    /// # Errors
    /// The saved state does not verify.
    pub fn open(genesis: MerkleNode<Genesis>, dir: &Path, fs: F) -> Result<Self, ReaderError> {
        let lock = fs.lock_dir(dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                ReaderError::Locked
            } else {
                ReaderError::Io(e)
            }
        })?;
        // Holding the lock, no one else is saving: a leftover temporary file is
        // a save that was interrupted before its rename, so its head was never
        // witnessed. Drop it; the saved state is the last durable one. Best
        // effort: if it cannot go (a directory sits there), the next save says
        // so as `Save`, which is the accurate error.
        let _ = fs.remove(&dir.join(format!("{FILE}.tmp")));
        let mut follower = Follower::new(&genesis)?;
        let frames = match fs.read(&dir.join(FILE))? {
            None => vec![],
            Some(bytes) => {
                // What is on disk may be visible without being durable: a save
                // whose directory fsync failed leaves its renamed file in place.
                // Verifying it proves it is intact, not that it will survive
                // power loss, so make it durable (the barriers a save ends
                // with) before it is shown as the saved prefix. If that fails
                // the reader does not open: nothing older is on hand to show
                // instead, and a head that might vanish must not be presented
                // as witnessed.
                let file = dir.join(FILE);
                fs.sync_file(&file)
                    .and_then(|()| fs.sync_dir(dir))
                    .map_err(ReaderError::Save)?;
                let cp: Checkpoint = from_canonical_dagcbor_checked(&bytes)
                    .map_err(|e| ReaderError::Invalid(format!("saved state: {e}")))?;
                for f in &cp.frames {
                    follower.apply(f).map_err(follow)?;
                }
                cp.frames
            }
        };
        Ok(Self {
            fs,
            dir: dir.to_path_buf(),
            genesis,
            follower,
            frames,
            _lock: lock,
        })
    }

    /// The verified prefix so far (what the stream resumes from).
    #[must_use]
    pub fn follower(&self) -> &Follower {
        &self.follower
    }

    /// Verify and apply one frame in memory. Not yet saved: a head counts
    /// only after [`save`](Self::save).
    ///
    /// # Errors
    /// [`ReaderError::Rollback`] when it does not extend the head.
    pub fn apply(&mut self, frame: Vec<Sealed>) -> Result<(), ReaderError> {
        self.follower.apply(&frame).map_err(follow)?;
        self.frames.push(frame);
        Ok(())
    }

    /// Apply a frame and save, as one step: if the save fails the reader goes
    /// back to the prefix it had, so nothing that was not saved is ever
    /// visible through [`follower`](Self::follower).
    fn apply_saved(&mut self, frame: Vec<Sealed>) -> Result<(), ReaderError> {
        let before = self.follower.clone();
        self.apply(frame)?;
        if let Err(e) = self.save() {
            self.frames.pop();
            self.follower = before;
            return Err(e);
        }
        Ok(())
    }

    /// Save atomically; returns the head now witnessed.
    ///
    /// # Errors
    /// I/O or encoding. Before the rename the previous save is intact; after it
    /// the new file may already be visible even if the directory fsync then
    /// fails, in which case the save is reported as failed and its head is not
    /// witnessed.
    pub fn save(&self) -> Result<Option<Head>, ReaderError> {
        let bytes = to_canonical_dagcbor(&Checkpoint {
            frames: self.frames.clone(),
        })
        .map_err(|e| ReaderError::Invalid(e.to_string()))?;
        save_atomic(&self.fs, &self.dir, FILE, &bytes).map_err(ReaderError::Save)?;
        Ok(self.follower.head().cloned())
    }

    /// The flock's genesis, as given at open.
    #[must_use]
    pub fn genesis(&self) -> &MerkleNode<Genesis> {
        &self.genesis
    }

    /// Open a stream from this reader's head, apply and save each frame, and
    /// return once the replay is caught up.
    ///
    /// # Errors
    /// Refused stream, rollback, an invalid frame, I/O.
    pub fn sync(&mut self, serve: &Path, prove: Prover<'_>) -> Result<(), ReaderError> {
        self.follow(serve, prove, true, &mut |_| {}).map(|_| ())
    }

    /// Like [`Self::sync`], but with `once` false keep going: every frame is
    /// verified, saved, then handed to `seen`, until the server closes the
    /// stream (its reason is returned). `seen` runs only after the save, so
    /// anything shown is already witnessed.
    ///
    /// # Errors
    /// Refused stream, rollback, an invalid frame, I/O.
    pub fn follow(
        &mut self,
        serve: &Path,
        prove: Prover<'_>,
        once: bool,
        seen: &mut dyn FnMut(Seen<'_>),
    ) -> Result<String, ReaderError> {
        self.follow_on(UnixStream::connect(serve)?, prove, once, seen)
    }

    /// [`Self::follow`] over a connection the caller made and keeps a clone
    /// of: shutting that clone down ends a read the server never answers,
    /// and this returns the error.
    ///
    /// # Errors
    /// As [`Self::follow`], and I/O when the caller closes the connection.
    pub fn follow_on(
        &mut self,
        conn: UnixStream,
        prove: Prover<'_>,
        once: bool,
        seen: &mut dyn FnMut(Seen<'_>),
    ) -> Result<String, ReaderError> {
        let mut w = Watch::open_on(conn, prove, self.follower.head().cloned())?;
        loop {
            match w.next_event()? {
                WatchEvent::Frame(f) => {
                    self.apply_saved(f.clone())?;
                    seen(Seen::Frame(&f, &self.follower));
                }
                WatchEvent::Caught(i) => {
                    // the marker must agree with what this reader verified
                    if i != self.follower.admitted() {
                        return Err(ReaderError::Invalid(format!(
                            "the server says caught up at {i}; this reader verified {}",
                            self.follower.admitted()
                        )));
                    }
                    seen(Seen::Caught(i, &self.follower));
                    if once {
                        return Ok("caught up".into());
                    }
                }
                WatchEvent::Closed(why) if once => return Err(ReaderError::Stream(why)),
                WatchEvent::Closed(why) => return Ok(why),
            }
        }
    }
}

/// What [`Reader::follow`] reports, after it is saved.
pub enum Seen<'a> {
    /// A verified, saved frame and the verified state after it.
    Frame(&'a [Sealed], &'a Follower),
    /// The replay is over, at this index, with the verified state.
    Caught(u64, &'a Follower),
}

/// What a stream delivers.
pub enum WatchEvent {
    /// One committed frame.
    Frame(Vec<Sealed>),
    /// The replay is over; the rest is live.
    Caught(u64),
    /// The server ended the stream.
    Closed(String),
}

/// An open stream.
pub struct Watch {
    conn: UnixStream,
}

impl Watch {
    /// Ask for a challenge, have `prove` sign it, and open the stream after
    /// `from`.
    ///
    /// # Errors
    /// Refused, or [`ReaderError::Rollback`] when the server is behind
    /// `from`.
    pub fn open(serve: &Path, prove: Prover<'_>, from: Option<Head>) -> Result<Self, ReaderError> {
        Self::open_on(UnixStream::connect(serve)?, prove, from)
    }

    /// [`Self::open`] on a connection the caller made, so it can keep a
    /// clone and shut it down to stop a blocked read.
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_on(
        mut conn: UnixStream,
        prove: Prover<'_>,
        from: Option<Head>,
    ) -> Result<Self, ReaderError> {
        write_msg(&mut conn, &Req::WatchBegin)?;
        let Some(Resp::StreamChallenge(ch)) = read_msg::<Resp>(&mut conn)? else {
            return Err(ReaderError::Stream("no challenge".into()));
        };
        let proof = Box::new(prove(&ch)?);
        write_msg(&mut conn, &Req::Watch { from, proof })?;
        Ok(Self { conn })
    }

    /// The next thing the server sends.
    ///
    /// # Errors
    /// A refusal, a rollback signal, or a broken stream.
    pub fn next_event(&mut self) -> Result<WatchEvent, ReaderError> {
        match read_msg::<Resp>(&mut self.conn)? {
            Some(Resp::Frame(f)) => Ok(WatchEvent::Frame(f)),
            Some(Resp::Caught { index }) => Ok(WatchEvent::Caught(index)),
            Some(Resp::Closed { reason }) => Ok(WatchEvent::Closed(reason)),
            Some(Resp::Behind { have }) => Err(ReaderError::Rollback(format!(
                "the server has {have} events, fewer than the saved head"
            ))),
            Some(Resp::Diverged) => Err(ReaderError::Rollback(
                "the server's history does not contain the saved head".into(),
            )),
            Some(Resp::Err(why)) => Err(ReaderError::Stream(why)),
            _ => Err(ReaderError::Stream("the stream ended".into())),
        }
    }
}
