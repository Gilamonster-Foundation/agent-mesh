//! Sender-side envelope sequencing (agent-mesh#100).
//!
//! A receiver admits a sender's envelope only when its sequence exceeds the
//! highest it has seen from that agent key, for as long as the receiver runs
//! ([`crate::replay::SequenceTracker`]). A bus that numbers from 1 is therefore
//! silently dropped by a receiver that outlived its predecessor under the same
//! key, until it has sent more than that predecessor did.
//!
//! [`SequenceReservations`] carries the ordering across that restart without a
//! clock: a bus durably reserves a block of sequences before issuing any of
//! it, and a successor bound to the same reservations starts above the block.
//! A crash mid-block only skips the rest of it. The receiver's replay checks
//! are unchanged — a successor's sequences are simply always higher.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::error::{BusError, Result};

/// How many sequences a bus reserves at a time: one durable write per block.
const RESERVATION_BLOCK: u64 = 1024;

/// Durable storage for the highest envelope sequence an agent key has
/// reserved. One per agent key; two buses bound concurrently under the same
/// key and the same reservations are not supported.
pub trait SequenceReservations: Send + Sync {
    /// The highest sequence reserved so far, or 0 when none has been.
    ///
    /// # Errors
    /// The reservation could not be read. A bus refuses to bind rather than
    /// guess.
    fn reserved(&self) -> Result<u64>;

    /// Durably record that sequences up to `through` are reserved. It must be
    /// stable before it returns: a bus issues sequences from the block only
    /// afterwards.
    ///
    /// # Errors
    /// The reservation could not be written. The bus issues no sequence from
    /// the block, so the send fails.
    fn reserve(&self, through: u64) -> Result<()>;
}

/// [`SequenceReservations`] in a file holding one decimal number, replaced
/// atomically (write, sync, rename) on every reservation.
#[derive(Debug, Clone)]
pub struct FileSequenceReservations {
    path: PathBuf,
}

impl FileSequenceReservations {
    /// Reservations kept at `path`. Its directory must exist.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl SequenceReservations for FileSequenceReservations {
    fn reserved(&self) -> Result<u64> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => text.trim().parse().map_err(|e| {
                BusError::SequenceReservation(format!("{}: {e}", self.path.display()))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(BusError::SequenceReservation(format!(
                "{}: {e}",
                self.path.display()
            ))),
        }
    }

    fn reserve(&self, through: u64) -> Result<()> {
        use std::io::Write as _;
        let failed = |e: std::io::Error| {
            BusError::SequenceReservation(format!("{}: {e}", self.path.display()))
        };
        let staged = self.path.with_extension("reserving");
        let mut file = std::fs::File::create(&staged).map_err(failed)?;
        file.write_all(through.to_string().as_bytes())
            .map_err(failed)?;
        file.sync_all().map_err(failed)?;
        std::fs::rename(&staged, &self.path).map_err(failed)
    }
}

/// A bus's envelope sequence: strictly increasing, and — with reservations —
/// above every sequence a predecessor under the same key could have issued.
pub(crate) struct Sequencer {
    state: Mutex<Issued>,
    reservations: Option<Arc<dyn SequenceReservations>>,
}

struct Issued {
    last: u64,
    reserved: u64,
}

impl Sequencer {
    /// Sequences from 1, held in memory only.
    pub(crate) fn in_memory() -> Self {
        Self::after(0)
    }

    /// Sequences from `last + 1`, held in memory only.
    pub(crate) fn after(last: u64) -> Self {
        Self {
            state: Mutex::new(Issued {
                last,
                reserved: u64::MAX,
            }),
            reservations: None,
        }
    }

    /// Sequences from above everything `reservations` has reserved.
    pub(crate) fn reserving(reservations: Arc<dyn SequenceReservations>) -> Result<Self> {
        let last = reservations.reserved()?;
        Ok(Self {
            state: Mutex::new(Issued {
                last,
                reserved: last,
            }),
            reservations: Some(reservations),
        })
    }

    /// The next sequence. With reservations, a new block is durably reserved
    /// before the first sequence in it is issued.
    pub(crate) fn next(&self) -> Result<u64> {
        let mut issued = self.state.lock().expect("sequencer poisoned");
        let next = issued
            .last
            .checked_add(1)
            .ok_or_else(|| BusError::SequenceReservation("sequences exhausted".into()))?;
        if next > issued.reserved {
            let through = issued.reserved.saturating_add(RESERVATION_BLOCK);
            if let Some(reservations) = &self.reservations {
                reservations.reserve(through)?;
            }
            issued.reserved = through;
        }
        issued.last = next;
        Ok(next)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Reservations in memory, standing in for a file that survives a restart.
    #[derive(Default)]
    pub(crate) struct Kept {
        pub(crate) through: Mutex<u64>,
        pub(crate) failing: std::sync::atomic::AtomicBool,
    }

    impl SequenceReservations for Kept {
        fn reserved(&self) -> Result<u64> {
            Ok(*self.through.lock().unwrap())
        }
        fn reserve(&self, through: u64) -> Result<()> {
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(BusError::SequenceReservation("disk full".into()));
            }
            *self.through.lock().unwrap() = through;
            Ok(())
        }
    }

    /// Every sequence a bus issues is reserved first, so a successor bound to
    /// the same reservations — after a clean close or a crash mid-block —
    /// starts above all of them.
    #[test]
    fn a_successor_starts_above_everything_its_predecessor_could_issue() {
        let kept = Arc::new(Kept::default());
        let first = Sequencer::reserving(kept.clone()).unwrap();
        let issued: Vec<u64> = (0..3).map(|_| first.next().unwrap()).collect();
        assert_eq!(issued, [1, 2, 3]);
        assert_eq!(
            kept.reserved().unwrap(),
            RESERVATION_BLOCK,
            "reserved first"
        );
        drop(first); // a crash: nothing written at close

        let second = Sequencer::reserving(kept.clone()).unwrap();
        assert_eq!(second.next().unwrap(), RESERVATION_BLOCK + 1);
        for _ in 1..RESERVATION_BLOCK {
            second.next().unwrap();
        }
        assert_eq!(
            kept.reserved().unwrap(),
            2 * RESERVATION_BLOCK,
            "one write per block"
        );
        assert_eq!(second.next().unwrap(), 2 * RESERVATION_BLOCK + 1);
        assert_eq!(kept.reserved().unwrap(), 3 * RESERVATION_BLOCK);
    }

    /// A block that cannot be reserved issues nothing from it: the send fails
    /// rather than reuse a sequence a successor might also issue.
    #[test]
    fn an_unreserved_sequence_is_never_issued() {
        let kept = Arc::new(Kept::default());
        kept.failing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let sequencer = Sequencer::reserving(kept.clone()).unwrap();
        assert!(sequencer.next().is_err());
        kept.failing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(sequencer.next().unwrap(), 1, "nothing was consumed");
    }

    #[test]
    fn file_reservations_round_trip_and_read_zero_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let file = FileSequenceReservations::new(dir.path().join("agent.seq"));
        assert_eq!(file.reserved().unwrap(), 0);
        file.reserve(2048).unwrap();
        assert_eq!(file.reserved().unwrap(), 2048);
        assert_eq!(
            FileSequenceReservations::new(dir.path().join("agent.seq"))
                .reserved()
                .unwrap(),
            2048,
            "a successor reads the same reservation"
        );
        std::fs::write(dir.path().join("agent.seq"), "garbage").unwrap();
        assert!(
            file.reserved().is_err(),
            "an unreadable reservation fails closed"
        );
    }
}
