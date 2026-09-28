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

/// The directory-sync step of [`FileSequenceReservations::reserve`],
/// factored out so tests can inject ordering checks and failures without
/// a heavier fault-injection framework. Production code always installs
/// [`sync_parent_dir`].
type DirSync = Arc<dyn Fn(&std::path::Path) -> std::io::Result<()> + Send + Sync>;

/// Durably syncs the directory entry a rename into `path` just created, so
/// the rename itself — not just the file's data — survives a crash.
///
/// Unix only. Opening a directory and `fsync`-ing it is how POSIX commits a
/// rename's directory-entry update; Windows has no equivalent open-a-
/// directory-as-a-file primitive. There, a completed `MoveFileEx` is
/// committed to NTFS's own metadata journal as part of the rename call
/// itself, so no separate directory sync is issued or needed — this
/// function is a no-op off Unix.
#[cfg(unix)]
fn sync_parent_dir(path: &std::path::Path) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// [`SequenceReservations`] in a file holding one decimal number, replaced
/// atomically: written to a uniquely-named, exclusively-created staging
/// file in the same directory (so it can never alias the destination or
/// another store's staging file), synced, renamed over the destination,
/// then the destination's directory is synced so the rename itself is
/// durable before [`reserve`](SequenceReservations::reserve) returns.
#[derive(Clone)]
pub struct FileSequenceReservations {
    path: PathBuf,
    dir_sync: DirSync,
}

impl std::fmt::Debug for FileSequenceReservations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSequenceReservations")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileSequenceReservations {
    /// Reservations kept at `path`. Its directory must exist.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            dir_sync: Arc::new(sync_parent_dir),
        }
    }

    /// Like [`new`](Self::new), but with the directory-sync step replaced —
    /// tests only, to inject ordering checks and failures.
    #[cfg(test)]
    fn with_dir_sync(path: impl Into<PathBuf>, dir_sync: DirSync) -> Self {
        Self {
            path: path.into(),
            dir_sync,
        }
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
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let mut staged = tempfile::NamedTempFile::new_in(dir).map_err(failed)?;
        staged
            .write_all(through.to_string().as_bytes())
            .map_err(failed)?;
        staged.as_file().sync_all().map_err(failed)?;
        staged.persist(&self.path).map_err(|e| failed(e.error))?;
        (self.dir_sync)(&self.path).map_err(failed)
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

    /// Regression for agent-mesh PR #101 review finding P2: the old staging
    /// path was `path.with_extension("reserving")`, so `agent.a` and
    /// `agent.b` both staged through the same `agent.reserving` file. This
    /// fails on that code (both end up reading the same final value) and
    /// passes now that staging uses a unique, exclusively-created file.
    #[test]
    fn distinct_destinations_sharing_a_stem_never_share_a_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = FileSequenceReservations::new(dir.path().join("agent.a"));
        let b = FileSequenceReservations::new(dir.path().join("agent.b"));
        a.reserve(2048).unwrap();
        b.reserve(1024).unwrap();
        assert_eq!(a.reserved().unwrap(), 2048, "a's own value survives b");
        assert_eq!(b.reserved().unwrap(), 1024);
        assert!(
            !dir.path().join("agent.reserving").exists(),
            "no fixed-suffix staging file is left behind"
        );
    }

    /// Regression for P2's second case: a destination that is itself already
    /// named `*.reserving` used to compute a staging path equal to its own
    /// destination (`with_extension` on a `.reserving` file is a no-op), so
    /// `reserve` opened-and-truncated the live destination in place before
    /// the new value was ready. Fails on that code (readers can observe a
    /// truncated file mid-write); passes now that staging is a distinct file.
    #[test]
    fn a_destination_already_named_reserving_is_not_truncated_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.reserving");
        let file = FileSequenceReservations::new(path.clone());
        file.reserve(2048).unwrap();
        assert_eq!(file.reserved().unwrap(), 2048);
        // The destination is untouched except by the final atomic rename —
        // no window where it reads empty or partial.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "2048");
    }

    /// Regression for the interleaving P2 describes: two distinct stores
    /// concurrently reserving through the same directory must never let one
    /// store's staging write clobber the other's — each store's final value
    /// is exactly what it last reserved, never the other's or a partial one.
    #[test]
    fn concurrent_reservations_on_distinct_destinations_never_cross_contaminate() {
        let dir = tempfile::tempdir().unwrap();
        let a = Arc::new(FileSequenceReservations::new(dir.path().join("agent.a")));
        let b = Arc::new(FileSequenceReservations::new(dir.path().join("agent.b")));
        for round in 0..200u64 {
            let (av, bv) = (2000 + round, 1000 + round);
            let (ac, bc) = (a.clone(), b.clone());
            let ta = std::thread::spawn(move || ac.reserve(av).unwrap());
            let tb = std::thread::spawn(move || bc.reserve(bv).unwrap());
            ta.join().unwrap();
            tb.join().unwrap();
            assert_eq!(a.reserved().unwrap(), av);
            assert_eq!(b.reserved().unwrap(), bv);
        }
    }

    /// P1: a directory-sync failure after a successful rename must fail
    /// `reserve` — and therefore `Sequencer::next`, which issues nothing
    /// from an unconfirmed-durable block.
    #[test]
    fn a_directory_sync_failure_fails_reserve_and_next() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FileSequenceReservations::with_dir_sync(
            dir.path().join("agent.seq"),
            Arc::new(|_path| Err(std::io::Error::other("dir sync failed"))),
        ));
        assert!(store.reserve(1024).is_err());

        let sequencer = Sequencer::reserving(store).unwrap();
        assert!(
            sequencer.next().is_err(),
            "next must not issue from a block reserve() couldn't durably confirm"
        );
    }

    /// P1 ordering: the directory must be synced only after the rename is
    /// already visible under the destination path — never before, and never
    /// skipped when the rename itself succeeded.
    #[test]
    fn directory_sync_observes_the_rename_already_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.seq");
        let observed = Arc::new(Mutex::new(None));
        let observed_in_hook = observed.clone();
        let hook_path = path.clone();
        let store = FileSequenceReservations::with_dir_sync(
            path,
            Arc::new(move |_dir_target| {
                *observed_in_hook.lock().unwrap() =
                    Some(std::fs::read_to_string(&hook_path).unwrap());
                Ok(())
            }),
        );
        store.reserve(4096).unwrap();
        assert_eq!(observed.lock().unwrap().as_deref(), Some("4096"));
    }
}
