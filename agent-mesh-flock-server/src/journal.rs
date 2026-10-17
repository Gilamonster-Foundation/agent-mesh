//! The published log: every committed frame, in order, readable without the
//! writer's lock. The writer publishes a frame only after its fsync, so
//! nothing a reader sees can be lost, and replay and live delivery read one
//! sequence: there is no seam to race across.
//!
//! ponytail: the whole log is kept in memory. The ceiling is the log's size;
//! upgrade by keeping `Vec<offset>` and reading frames back from the file.

use crate::frame::{AdmissionRecord, Sealed};
use agent_mesh_protocol::Assertion;
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// A signed head: an admission record and the server's signature over it.
/// The resume token for `watch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// The record (its parents chain to every earlier record).
    pub record: MerkleNode<AdmissionRecord>,
    /// The server's signature over the record's id.
    pub sig: Assertion,
}

impl Head {
    /// The head a sealed event leaves.
    #[must_use]
    pub fn of(s: &Sealed) -> Self {
        Self {
            record: s.record.clone(),
            sig: s.record_sig.clone(),
        }
    }

    /// The admission index.
    #[must_use]
    pub fn index(&self) -> u64 {
        self.record.payload.index
    }

    /// The record id.
    ///
    /// # Errors
    /// Encoding failure.
    pub fn id(&self) -> Result<ContentId, crate::ServerError> {
        self.record
            .content_id()
            .map_err(|e| crate::ServerError::Encoding(e.to_string()))
    }
}

/// Why a resume token cannot be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resume {
    /// The server's history is shorter than the token's index.
    Behind {
        /// How many events the server has.
        have: u64,
    },
    /// The server's record at that index is not the token's.
    Diverged,
    /// The token names an event inside a frame, not the end of one.
    NotABoundary,
}

/// The sessions that were live and belonged to a current member of the
/// roster once a frame had been applied: immutable, published with the
/// frame, so a stream can re-check its own eligibility without the writer's
/// lock.
pub type Eligible = Arc<BTreeSet<String>>;

/// One published frame and who was eligible after it.
pub type Published = (Arc<Vec<Sealed>>, Eligible);

struct Inner {
    frames: Vec<Published>,
    stopped: bool,
}

/// The published frames and the signal that announces new ones.
pub struct Journal {
    inner: Mutex<Inner>,
    more: Condvar,
}

fn last_index(f: &[Sealed]) -> u64 {
    f.last().map_or(0, |s| s.record.payload.index)
}

impl Journal {
    pub(crate) fn new(frames: Vec<(Vec<Sealed>, Eligible)>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                frames: frames.into_iter().map(|(f, e)| (Arc::new(f), e)).collect(),
                stopped: false,
            }),
            more: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Publish a committed frame (after its fsync).
    pub(crate) fn publish(&self, frame: Vec<Sealed>, eligible: Eligible) {
        self.lock().frames.push((Arc::new(frame), eligible));
        self.more.notify_all();
    }

    /// Wake every cursor with "stopped".
    pub fn stop(&self) {
        self.lock().stopped = true;
        self.more.notify_all();
    }

    /// How many events are published.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.lock().frames.last().map_or(0, |(f, _)| last_index(f))
    }

    /// Whether nothing is published yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A cursor positioned after `head` (the start, with none).
    ///
    /// # Errors
    /// [`Resume`] when the server's history cannot be what `head` extends.
    pub fn cursor_from(self: &Arc<Self>, head: Option<&Head>) -> Result<Cursor, Resume> {
        let g = self.lock();
        let next = match head {
            None => 0,
            Some(h) => {
                let at = h.index();
                let have = g.frames.last().map_or(0, |(f, _)| last_index(f));
                if at > have {
                    return Err(Resume::Behind { have });
                }
                let pos = g.frames.partition_point(|(f, _)| last_index(f) < at);
                let frame = &g.frames[pos].0;
                if last_index(frame) != at {
                    return Err(Resume::NotABoundary);
                }
                let mine = frame.last().map(|s| s.record.content_id());
                match (mine, h.id()) {
                    (Some(Ok(a)), Ok(b)) if a == b => pos + 1,
                    _ => return Err(Resume::Diverged),
                }
            }
        };
        drop(g);
        Ok(Cursor {
            journal: self.clone(),
            next,
        })
    }
}

/// A reader's place in the journal.
pub struct Cursor {
    journal: Arc<Journal>,
    next: usize,
}

impl Cursor {
    /// The index of the last event delivered (or the resume point).
    #[must_use]
    pub fn delivered(&self) -> u64 {
        let g = self.journal.lock();
        match self.next {
            0 => 0,
            n => g.frames.get(n - 1).map_or(0, |(f, _)| last_index(f)),
        }
    }

    /// The next frame, blocking until one is published; `None` once the
    /// journal is stopped and drained.
    pub fn next_frame(&mut self) -> Option<Published> {
        let mut g = self.journal.lock();
        loop {
            if let Some(f) = g.frames.get(self.next) {
                self.next += 1;
                return Some(f.clone());
            }
            if g.stopped {
                return None;
            }
            g = self
                .journal
                .more
                .wait(g)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}
