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
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::{FollowError, Follower, Head, Sealed};
use agent_mesh_protocol::{AgentKey, Assertion};
use content_addressable::canonical::{from_canonical_dagcbor_checked, to_canonical_dagcbor};
use content_addressable::MerkleNode;
use serde::{Deserialize, Serialize};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const FILE: &str = "reader.state";

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
        let mut follower = Follower::new(&genesis)?;
        let frames = match fs.read(&dir.join(FILE))? {
            None => vec![],
            Some(bytes) => {
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

    /// Save atomically; returns the head now witnessed.
    ///
    /// # Errors
    /// I/O or encoding; the previous save is intact.
    pub fn save(&self) -> Result<Option<Head>, ReaderError> {
        let bytes = to_canonical_dagcbor(&Checkpoint {
            frames: self.frames.clone(),
        })
        .map_err(|e| ReaderError::Invalid(e.to_string()))?;
        save_atomic(&self.fs, &self.dir, FILE, &bytes)?;
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
    pub fn sync(&mut self, serve: &Path, key: &AgentKey) -> Result<(), ReaderError> {
        let mut w = Watch::open(serve, key, self.follower.head().cloned())?;
        loop {
            match w.next_event()? {
                WatchEvent::Frame(f) => {
                    self.apply(f)?;
                    self.save()?;
                }
                WatchEvent::Caught(_) => return Ok(()),
                WatchEvent::Closed(why) => return Err(ReaderError::Stream(why)),
            }
        }
    }
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
    /// Ask for a challenge, sign it with the session key, and open the
    /// stream after `from`.
    ///
    /// # Errors
    /// Refused, or [`ReaderError::Rollback`] when the server is behind
    /// `from`.
    pub fn open(serve: &Path, key: &AgentKey, from: Option<Head>) -> Result<Self, ReaderError> {
        let mut conn = UnixStream::connect(serve)?;
        write_msg(&mut conn, &Req::WatchBegin)?;
        let Some(Resp::StreamChallenge(ch)) = read_msg::<Resp>(&mut conn)? else {
            return Err(ReaderError::Stream("no challenge".into()));
        };
        let proof = Box::new(Assertion::sign(key, &ch.id()?));
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
