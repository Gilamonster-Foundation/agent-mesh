//! [`RevocationGuard`] turns the local user's revocation log into the
//! [`RevocationState`] every handshake checks a peer's chain against.
//!
//! Transport-free (std only), so any verifier can use the one implementation.
//!
//! Fail-closed throughout: a log that is missing, unreadable, invalid, owned by
//! another user, or that does not extend the head last persisted in its `Seen`
//! file refuses every peer until it is fixed. See `docs/decisions/revocation.md`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{CertChain, Fingerprint, MeshError, RevocationLog, RevocationState, Seen, UserKey};

/// Why a [`RevocationGuard`] refused.
#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    /// The peer's chain, or a link of it, is revoked (agent fingerprint, hex).
    #[error("peer revoked: agent {0}")]
    Revoked(String),
    /// The chain failed verification for a reason other than revocation.
    #[error("cert chain rejected: {0}")]
    BadCertChain(String),
    /// No usable revocation log (missing, unreadable, invalid, another user's,
    /// or not extending what was last seen). Fail closed.
    #[error("revocation log unavailable: {0}")]
    Unavailable(String),
}

/// Result alias for guard operations.
pub type Result<T> = std::result::Result<T, GuardError>;

/// The user's revocation log, as a verifier of peer chains.
///
/// Cheap to clone; every clone shares one cached view.
#[derive(Clone, Debug)]
pub struct RevocationGuard {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    local_user: Fingerprint,
    file: Option<LogFile>,
    cache: Mutex<Option<Cached>>,
}

#[derive(Debug)]
struct LogFile {
    log: PathBuf,
    seen: PathBuf,
    /// Held exclusively across read, check and write of `seen`.
    lock: PathBuf,
}

#[derive(Debug)]
struct Cached {
    state: Arc<RevocationState>,
    /// The exact bytes `state` was verified from. The file is read on every
    /// call and compared with these: identical bytes are the same log (same
    /// head), anything else is verified afresh. Metadata is never trusted.
    bytes: Vec<u8>,
}

impl RevocationGuard {
    /// A guard over the log file at `log`, for the local user `local_user`.
    ///
    /// Reads, verifies and checks the log against the `Seen` record kept
    /// beside it (`<name>.seen.json`) before returning, so a missing, invalid
    /// or rolled-back log is refused at startup. The first time a log is
    /// opened there is no `Seen` yet; it is written then.
    ///
    /// # Errors
    /// [`GuardError::Unavailable`] if the log is missing,
    /// unreadable, invalid, another user's, or does not extend what was seen.
    pub fn open(log: impl Into<PathBuf>, local_user: Fingerprint) -> Result<Self> {
        let log = log.into();
        let seen = log.with_extension("seen.json");
        let lock = log.with_extension("seen.lock");
        let guard = Self {
            inner: Arc::new(Inner {
                local_user,
                file: Some(LogFile { log, seen, lock }),
                cache: Mutex::new(None),
            }),
        };
        guard.state()?;
        Ok(guard)
    }

    /// A guard over a fresh, empty log owned by `user`: nothing is revoked and
    /// nothing is persisted. For tests and for callers that keep no log;
    /// production code opens the user's `revocation.json` with [`Self::open`].
    #[must_use]
    pub fn in_memory(user: &UserKey) -> Self {
        let log = RevocationLog::genesis(user).expect("genesis encodes");
        let state = log.verify().expect("a fresh genesis verifies");
        Self {
            inner: Arc::new(Inner {
                local_user: user.fingerprint(),
                file: None,
                cache: Mutex::new(Some(Cached {
                    state: Arc::new(state),
                    bytes: Vec::new(),
                })),
            }),
        }
    }

    /// The current verified state, re-reading the log if its file changed.
    ///
    /// # Errors
    /// [`GuardError::Unavailable`] as for [`Self::open`].
    pub fn state(&self) -> Result<Arc<RevocationState>> {
        let mut cache = lock(&self.inner.cache);
        let Some(file) = &self.inner.file else {
            return Ok(cache
                .as_ref()
                .expect("in-memory state is set")
                .state
                .clone());
        };
        match fs::read(&file.log) {
            Ok(now) => {
                // Unchanged bytes are the same log, but not necessarily still
                // acceptable: another guard or process may have advanced the
                // shared `Seen` past it (this file is then a rollback). The
                // cache only stands while `Seen` is exactly what it persisted;
                // anything else goes through `load`, which re-checks it under
                // the lock.
                if let Some(cached) = cache
                    .as_ref()
                    .filter(|c| c.bytes == now && seen_is(&file.seen, &c.state))
                {
                    return Ok(cached.state.clone());
                }
            }
            Err(e) => {
                *cache = None;
                return Err(unavailable("read revocation log", &e));
            }
        }
        // Refused until fixed: forget the old view so a failure is not masked.
        *cache = None;
        let (state, bytes) = self.load(file)?;
        let state = Arc::new(state);
        *cache = Some(Cached {
            state: state.clone(),
            bytes,
        });
        Ok(state)
    }

    /// Check `peer` against the current state: its user is ours, no link in
    /// its chain is revoked, and it is valid at the current generation.
    ///
    /// # Errors
    /// [`GuardError::Revoked`] for a revoked link,
    /// [`GuardError::BadCertChain`] for any other chain failure,
    /// [`GuardError::Unavailable`] if there is no usable log.
    pub fn check(&self, peer: &CertChain) -> Result<()> {
        let state = self.state()?;
        verify_with(peer, &state)
    }

    /// Verify the log and advance `Seen` as one transaction under an
    /// exclusive lock, so independent guards and processes sharing a home
    /// cannot interleave a read of `Seen` with another's write of it. `Seen`
    /// is only ever written with a head that strictly extends the one on disk.
    fn load(&self, file: &LogFile) -> Result<(RevocationState, Vec<u8>)> {
        let _lock = fs::File::options()
            .create(true)
            .append(true)
            .open(&file.lock)
            .and_then(|f| f.lock().map(|()| f))
            .map_err(|e| unavailable("lock seen record", &e))?;
        // read inside the lock: the bytes verified are the bytes cached
        let bytes = fs::read(&file.log).map_err(|e| unavailable("read revocation log", &e))?;
        let log: RevocationLog =
            serde_json::from_slice(&bytes).map_err(|e| unavailable("parse revocation log", &e))?;
        let state = log
            .verify()
            .map_err(|e| unavailable("verify revocation log", &e))?;
        if state.user != self.inner.local_user {
            return Err(unavailable(
                "revocation log",
                &"belongs to a different user than the local identity",
            ));
        }
        let advance = match fs::read(&file.seen) {
            Ok(raw) => {
                let seen: Seen = serde_json::from_slice(&raw)
                    .map_err(|e| unavailable("parse seen record", &e))?;
                log.extends(&seen)
                    .map_err(|e| unavailable("revocation log", &e))?;
                state.len > seen.len
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => return Err(unavailable("read seen record", &e)),
        };
        if advance {
            persist_seen(&file.seen, &state.seen()).map_err(|e| unavailable("persist seen", &e))?;
        }
        Ok((state, bytes))
    }
}

/// Whether the persisted `Seen` is exactly the one `state` produced. The
/// record is replaced by atomic rename, so an unlocked read sees a whole one.
fn seen_is(path: &Path, state: &RevocationState) -> bool {
    fs::read(path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<Seen>(&raw).ok())
        .is_some_and(|seen| seen == state.seen())
}

fn unavailable(what: &str, e: &dyn std::fmt::Display) -> GuardError {
    GuardError::Unavailable(format!("{what}: {e}"))
}

/// Check `peer` against an already-verified `state`.
///
/// # Errors
/// [`GuardError::Revoked`] or [`GuardError::BadCertChain`].
pub fn verify_with(peer: &CertChain, state: &RevocationState) -> Result<()> {
    peer.verify_with(state).map_err(|e| match e {
        MeshError::Revoked { agent } => GuardError::Revoked(agent.hex()),
        other => GuardError::BadCertChain(other.to_string()),
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Publish `seen` beside the log: exclusive temp file, synced, renamed, with
/// the directory synced ([`crate::atomic::atomic_write`]).
fn persist_seen(path: &Path, seen: &Seen) -> io::Result<()> {
    crate::atomic::atomic_write(path, &serde_json::to_vec(seen).map_err(io::Error::other)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentKey, AgentMetadata, Caveats, RevocationEntry};
    use std::time::SystemTime;

    fn agent(user: &UserKey) -> AgentKey {
        AgentKey::issue(
            user,
            AgentMetadata {
                role: "w".into(),
                host: "h".into(),
                capabilities: vec![],
                issued_at: "2026-10-26T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        )
    }

    /// A user with a persisted genesis log in a temp dir.
    struct Fixture {
        user: UserKey,
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let f = Self {
                user: UserKey::generate(),
                dir: tempfile::tempdir().unwrap(),
            };
            f.write(&RevocationLog::genesis(&f.user).unwrap());
            f
        }

        fn path(&self) -> PathBuf {
            self.dir.path().join("revocation.json")
        }

        fn write(&self, log: &RevocationLog) {
            fs::write(self.path(), serde_json::to_vec(log).unwrap()).unwrap();
        }

        fn read(&self) -> RevocationLog {
            serde_json::from_slice(&fs::read(self.path()).unwrap()).unwrap()
        }

        fn revoke(&self, k: &AgentKey) {
            let mut log = self.read();
            let agent = k.fingerprint();
            log.append(&self.user, RevocationEntry::Revoke { agent })
                .unwrap();
            self.write(&log);
        }

        fn open(&self) -> Result<RevocationGuard> {
            RevocationGuard::open(self.path(), self.user.fingerprint())
        }
    }

    fn unavailable<T: std::fmt::Debug>(r: Result<T>) -> bool {
        matches!(r, Err(GuardError::Unavailable(_)))
    }

    #[test]
    fn a_missing_log_refuses() {
        let user = UserKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let r = RevocationGuard::open(dir.path().join("revocation.json"), user.fingerprint());
        assert!(unavailable(r));
    }

    #[test]
    fn a_garbled_log_refuses() {
        let f = Fixture::new();
        fs::write(f.path(), b"{not json").unwrap();
        assert!(unavailable(f.open()));
    }

    #[test]
    fn another_users_log_refuses() {
        let f = Fixture::new();
        let r = RevocationGuard::open(f.path(), UserKey::generate().fingerprint());
        assert!(unavailable(r));
    }

    #[test]
    fn a_valid_log_admits_its_users_agents_and_persists_seen() {
        let f = Fixture::new();
        let guard = f.open().unwrap();
        guard.check(agent(&f.user).cert()).unwrap();
        let seen: Seen =
            serde_json::from_slice(&fs::read(f.path().with_extension("seen.json")).unwrap())
                .unwrap();
        assert_eq!(seen, guard.state().unwrap().seen());
    }

    #[test]
    fn a_revoked_agent_is_refused() {
        let f = Fixture::new();
        let a = agent(&f.user);
        f.revoke(&a);
        let guard = f.open().unwrap();
        assert!(matches!(guard.check(a.cert()), Err(GuardError::Revoked(_))));
    }

    /// Regression for the rollback hole: a log file swapped back to an older
    /// copy must be refused at startup, not silently un-revoke the agent.
    #[test]
    fn a_rolled_back_log_is_refused_at_startup() {
        let f = Fixture::new();
        let old = f.read();
        f.revoke(&agent(&f.user));
        f.open().unwrap();
        f.write(&old);
        assert!(unavailable(f.open()));
    }

    #[test]
    fn a_forked_log_is_refused_at_startup() {
        let f = Fixture::new();
        let genesis = f.read();
        f.revoke(&agent(&f.user));
        f.open().unwrap();
        let mut fork = genesis;
        fork.append(
            &f.user,
            RevocationEntry::Revoke {
                agent: agent(&f.user).fingerprint(),
            },
        )
        .unwrap();
        f.write(&fork);
        assert!(unavailable(f.open()));
    }

    #[test]
    fn a_log_that_changes_to_a_rollback_while_running_refuses_every_peer() {
        let f = Fixture::new();
        let (a, b) = (agent(&f.user), agent(&f.user));
        let old = f.read();
        f.revoke(&a);
        let guard = f.open().unwrap();
        guard.check(b.cert()).unwrap();
        f.write(&old);
        assert!(unavailable(guard.state()));
        assert!(guard.check(b.cert()).is_err());
    }

    #[test]
    fn an_in_memory_guard_admits_its_user_and_refuses_another() {
        let user = UserKey::generate();
        let guard = RevocationGuard::in_memory(&user);
        guard.check(agent(&user).cert()).unwrap();
        assert!(guard.check(agent(&UserKey::generate()).cert()).is_err());
    }

    /// Pad `bytes` (JSON) with trailing spaces to exactly `len`.
    fn padded(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
        assert!(bytes.len() <= len);
        bytes.resize(len, b' ');
        bytes
    }

    fn set_mtime(path: &Path, t: SystemTime) {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    /// Regression (PR 185 review): file metadata is not the log's identity. A
    /// newer, valid log written over the old one with the same length and
    /// mtime must be seen on the next check.
    #[test]
    fn an_equal_length_same_mtime_replacement_is_detected() {
        let f = Fixture::new();
        let (a, b) = (agent(&f.user), agent(&f.user));
        let mut old = f.read();
        old.append(
            &f.user,
            RevocationEntry::Revoke {
                agent: b.fingerprint(),
            },
        )
        .unwrap();
        let mut new = old.clone();
        new.append(
            &f.user,
            RevocationEntry::Revoke {
                agent: a.fingerprint(),
            },
        )
        .unwrap();
        let (old, new) = (
            serde_json::to_vec(&old).unwrap(),
            serde_json::to_vec(&new).unwrap(),
        );
        let len = old.len().max(new.len());
        fs::write(f.path(), padded(old, len)).unwrap();
        let stamp = fs::metadata(f.path()).unwrap().modified().unwrap();
        let guard = f.open().unwrap();
        guard.check(a.cert()).unwrap();

        fs::write(f.path(), padded(new, len)).unwrap();
        set_mtime(&f.path(), stamp);
        assert!(
            matches!(guard.check(a.cert()), Err(GuardError::Revoked(_))),
            "the replacement revokes a, even with identical metadata"
        );
    }

    /// An equal-length corrupt replacement with the old mtime fails closed.
    #[test]
    fn an_equal_length_same_mtime_corrupt_replacement_fails_closed() {
        let f = Fixture::new();
        let guard = f.open().unwrap();
        let stamp = fs::metadata(f.path()).unwrap().modified().unwrap();
        let len = fs::metadata(f.path()).unwrap().len() as usize;
        fs::write(f.path(), vec![b'x'; len]).unwrap();
        set_mtime(&f.path(), stamp);
        assert!(unavailable(guard.state()));
    }

    /// Two guards on one home persist `Seen` under one exclusive lock held
    /// across read, check and write: while another holder has it, opening
    /// waits instead of racing the record.
    #[test]
    fn opening_waits_for_the_seen_lock() {
        let f = Fixture::new();
        f.open().unwrap();
        let lock = fs::File::options()
            .create(true)
            .append(true)
            .open(f.path().with_extension("seen.lock"))
            .unwrap();
        lock.lock().unwrap();
        let (path, fp) = (f.path(), f.user.fingerprint());
        let opened = std::thread::spawn(move || RevocationGuard::open(path, fp).is_ok());
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!opened.is_finished(), "open must wait for the lock");
        drop(lock);
        assert!(opened.join().unwrap());
    }

    /// `Seen` only advances: a guard whose view is older than what another
    /// guard persisted is refused and leaves the record where it was.
    #[test]
    fn seen_never_goes_backwards_across_guards() {
        let f = Fixture::new();
        let l1 = f.read();
        f.revoke(&agent(&f.user));
        let l2 = f.read();
        f.revoke(&agent(&f.user));
        let l3 = f.read();
        f.write(&l1);
        let a = f.open().unwrap();
        f.write(&l3);
        let b = f.open().unwrap();
        let persisted = |f: &Fixture| fs::read(f.path().with_extension("seen.json")).unwrap();
        let at_l3 = persisted(&f);
        f.write(&l2);
        assert!(unavailable(a.state()));
        assert!(unavailable(b.state()));
        assert_eq!(persisted(&f), at_l3, "Seen is still L3");
        f.write(&l3);
        a.state().unwrap();
        assert_eq!(persisted(&f), at_l3);
    }

    /// Regression (PR 185 round 3): a guard that cached L1 must not accept a
    /// peer on L1's bytes once another guard has persisted a `Seen` that L1
    /// does not extend: restoring the old file is a rollback, cache or not.
    #[test]
    fn a_cached_guard_refuses_a_rollback_to_its_cached_log() {
        let f = Fixture::new();
        let (a, victim) = (agent(&f.user), agent(&f.user));
        let l1 = fs::read(f.path()).unwrap();
        let guard_a = f.open().unwrap();
        guard_a.check(victim.cert()).unwrap();

        f.revoke(&victim);
        let _guard_b = f.open().unwrap(); // persists Seen = L2
        fs::write(f.path(), &l1).unwrap(); // the exact L1 bytes come back
        assert!(
            guard_a.check(victim.cert()).is_err(),
            "a rollback to L1 must be refused even though A cached L1"
        );
        let _ = a;
    }

    /// Regression (PR 185 round 3): the `Seen` record is published through a
    /// fresh exclusive temp file; a symlink planted at any guessable temp
    /// name is never followed or truncated.
    #[cfg(unix)]
    #[test]
    fn a_planted_tmp_symlink_is_never_followed_when_seen_is_written() {
        let f = Fixture::new();
        let victim = f.dir.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        let seen = f.path().with_extension("seen.json");
        for name in [
            format!("{}.tmp", std::process::id()),
            "tmp".to_string(),
            "seen.tmp".to_string(),
        ] {
            let planted = seen.with_extension(name);
            let _ = std::os::unix::fs::symlink(&victim, planted);
        }
        f.open().unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert!(fs::metadata(&seen).is_ok(), "Seen was still written");
    }
}
