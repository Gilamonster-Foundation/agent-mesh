//! Revocation enforcement for the transports: [`RevocationGuard`] turns the
//! local user's revocation log into the [`RevocationState`] every handshake
//! checks a peer's chain against, and [`LiveCheck`] / [`Revocable`] re-check
//! an established session when that log changes.
//!
//! Fail-closed throughout: a log that is missing, unreadable, invalid, owned by
//! another user, or that does not extend the head last persisted in its `Seen`
//! file refuses every peer until it is fixed. See `docs/decisions/revocation.md`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::SystemTime;

use agent_mesh_protocol::{
    CertChain, Fingerprint, MeshError, RevocationLog, RevocationState, Seen, UserKey,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Result, TransportError};

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
}

#[derive(Debug)]
struct Cached {
    state: Arc<RevocationState>,
    /// Metadata of the log file when `state` was read: while it is unchanged,
    /// the head cannot have moved, so no re-read is needed.
    // ponytail: mtime+len stamp, not a re-parse per call; a same-size rewrite
    // within one mtime tick is picked up at the next restart, which re-checks.
    stamp: Option<(SystemTime, u64)>,
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
    /// [`TransportError::RevocationUnavailable`] if the log is missing,
    /// unreadable, invalid, another user's, or does not extend what was seen.
    pub fn open(log: impl Into<PathBuf>, local_user: Fingerprint) -> Result<Self> {
        let log = log.into();
        let seen = log.with_extension("seen.json");
        let guard = Self {
            inner: Arc::new(Inner {
                local_user,
                file: Some(LogFile { log, seen }),
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
                    stamp: None,
                })),
            }),
        }
    }

    /// The current verified state, re-reading the log if its file changed.
    ///
    /// # Errors
    /// [`TransportError::RevocationUnavailable`] as for [`Self::open`].
    pub fn state(&self) -> Result<Arc<RevocationState>> {
        let mut cache = lock(&self.inner.cache);
        let Some(file) = &self.inner.file else {
            return Ok(cache
                .as_ref()
                .expect("in-memory state is set")
                .state
                .clone());
        };
        let stamp = stamp(&file.log);
        if let (Some(cached), Some(now)) = (cache.as_ref(), stamp) {
            if cached.stamp == Some(now) {
                return Ok(cached.state.clone());
            }
        }
        // Refused until fixed: forget the old view so a failure is not masked.
        *cache = None;
        let state = Arc::new(self.load(file)?);
        *cache = Some(Cached {
            state: state.clone(),
            stamp,
        });
        Ok(state)
    }

    /// Check `peer` against the current state: its user is ours, no link in
    /// its chain is revoked, and it is valid at the current generation.
    ///
    /// # Errors
    /// [`TransportError::Revoked`] for a revoked link,
    /// [`TransportError::BadCertChain`] for any other chain failure,
    /// [`TransportError::RevocationUnavailable`] if there is no usable log.
    pub fn check(&self, peer: &CertChain) -> Result<()> {
        let state = self.state()?;
        verify_with(peer, &state)
    }

    fn load(&self, file: &LogFile) -> Result<RevocationState> {
        let unavailable = |what: &str, e: &dyn std::fmt::Display| {
            TransportError::RevocationUnavailable(format!("{what}: {e}"))
        };
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
        match fs::read(&file.seen) {
            Ok(bytes) => {
                let seen: Seen = serde_json::from_slice(&bytes)
                    .map_err(|e| unavailable("parse seen record", &e))?;
                log.extends(&seen)
                    .map_err(|e| unavailable("revocation log", &e))?;
                if seen == state.seen() {
                    return Ok(state);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(unavailable("read seen record", &e)),
        }
        persist_seen(&file.seen, &state.seen()).map_err(|e| unavailable("persist seen", &e))?;
        Ok(state)
    }
}

fn verify_with(peer: &CertChain, state: &RevocationState) -> Result<()> {
    peer.verify_with(state).map_err(|e| match e {
        MeshError::Revoked { agent } => TransportError::Revoked(agent.hex()),
        other => TransportError::BadCertChain(other.to_string()),
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let m = fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

/// Write `seen` beside the log by temp file + rename, so a crash leaves the
/// old record or the new one, never half of one.
fn persist_seen(path: &Path, seen: &Seen) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec(seen).map_err(io::Error::other)?)?;
    fs::rename(&tmp, path)
}

/// A peer's chain, re-checked whenever the log's head moves.
///
/// An established session holds one. Calling [`Self::admit`] before dispatching
/// each inbound envelope costs a file stat while the log is unchanged.
pub struct LiveCheck {
    guard: RevocationGuard,
    peer: CertChain,
    state: Arc<RevocationState>,
}

impl LiveCheck {
    /// Check `peer` now and remember the state it passed.
    ///
    /// # Errors
    /// As [`RevocationGuard::check`].
    pub fn new(guard: RevocationGuard, peer: CertChain) -> Result<Self> {
        let state = guard.state()?;
        verify_with(&peer, &state)?;
        Ok(Self { guard, peer, state })
    }

    /// Fail if the peer is no longer acceptable. Re-verifies the chain only
    /// when the log's head differs from the last one this peer passed.
    ///
    /// # Errors
    /// As [`RevocationGuard::check`]; the session must then be torn down.
    pub fn admit(&mut self) -> Result<()> {
        let state = self.guard.state()?;
        if state.head != self.state.head {
            verify_with(&self.peer, &state)?;
            self.state = state;
        }
        Ok(())
    }
}

/// A byte stream that ends with an error the moment its peer is revoked.
///
/// Wraps one half of a session stream; the check runs on every read and write
/// attempt, so no byte from, or to, a revoked peer is handed on after the log
/// learns of the revocation.
pub struct Revocable<T> {
    inner: T,
    live: Arc<Mutex<LiveCheck>>,
}

impl<T> Revocable<T> {
    /// Wrap `inner`, sharing `live` with the stream's other half.
    #[must_use]
    pub fn new(inner: T, live: Arc<Mutex<LiveCheck>>) -> Self {
        Self { inner, live }
    }

    fn admit(&self) -> io::Result<()> {
        lock(&self.live)
            .admit()
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Revocable<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.admit() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Revocable<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.admit() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, RevocationEntry};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        matches!(r, Err(TransportError::RevocationUnavailable(_)))
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
        assert!(matches!(
            guard.check(a.cert()),
            Err(TransportError::Revoked(_))
        ));
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

    #[test]
    fn live_check_admits_until_the_log_revokes_the_peer() {
        let f = Fixture::new();
        let a = agent(&f.user);
        let mut live = LiveCheck::new(f.open().unwrap(), a.cert().clone()).unwrap();
        live.admit().unwrap();
        f.revoke(&a);
        assert!(matches!(live.admit(), Err(TransportError::Revoked(_))));
    }

    #[test]
    fn live_check_ignores_a_head_move_that_leaves_the_peer_standing() {
        let f = Fixture::new();
        let (a, b) = (agent(&f.user), agent(&f.user));
        let mut live = LiveCheck::new(f.open().unwrap(), a.cert().clone()).unwrap();
        f.revoke(&b);
        live.admit().unwrap();
    }

    #[test]
    fn a_revoked_parent_takes_its_delegated_child_with_it() {
        let f = Fixture::new();
        let parent = agent(&f.user);
        let child = parent
            .delegate(AgentMetadata {
                role: "child".into(),
                host: "h".into(),
                capabilities: vec![],
                issued_at: "2026-10-26T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            })
            .unwrap();
        let mut live = LiveCheck::new(f.open().unwrap(), child.cert().clone()).unwrap();
        f.revoke(&parent);
        assert!(matches!(live.admit(), Err(TransportError::Revoked(_))));
    }

    #[tokio::test]
    async fn a_revocable_stream_errors_once_its_peer_is_revoked() {
        let f = Fixture::new();
        let a = agent(&f.user);
        let live = LiveCheck::new(f.open().unwrap(), a.cert().clone()).unwrap();
        let (near, mut far) = tokio::io::duplex(64);
        let mut near = Revocable::new(near, Arc::new(Mutex::new(live)));
        far.write_all(b"one").await.unwrap();
        let mut buf = [0u8; 3];
        near.read_exact(&mut buf).await.unwrap();
        f.revoke(&a);
        far.write_all(b"two").await.unwrap();
        let e = near.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(near.write_all(b"x").await.is_err());
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
        old.append(&f.user, RevocationEntry::Revoke { agent: b.fingerprint() })
            .unwrap();
        let mut new = old.clone();
        new.append(&f.user, RevocationEntry::Revoke { agent: a.fingerprint() })
            .unwrap();
        let (old, new) = (serde_json::to_vec(&old).unwrap(), serde_json::to_vec(&new).unwrap());
        let len = old.len().max(new.len());
        fs::write(f.path(), padded(old, len)).unwrap();
        let stamp = fs::metadata(f.path()).unwrap().modified().unwrap();
        let guard = f.open().unwrap();
        guard.check(a.cert()).unwrap();

        fs::write(f.path(), padded(new, len)).unwrap();
        set_mtime(&f.path(), stamp);
        assert!(
            matches!(guard.check(a.cert()), Err(TransportError::Revoked(_))),
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

    /// Regression (PR 185 review): two envelopes already buffered in the
    /// reader; the peer is revoked between them; the second must be refused,
    /// not handed on from the buffer.
    #[tokio::test]
    async fn a_buffered_second_envelope_is_refused_after_revocation() {
        use crate::stream::EnvelopeReader;
        use agent_mesh_protocol::{Fingerprint, Recipient, SignedEnvelope};
        let f = Fixture::new();
        let a = agent(&f.user);
        let live = LiveCheck::new(f.open().unwrap(), a.cert().clone()).unwrap();
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut reader = EnvelopeReader::new(Revocable::new(near, Arc::new(Mutex::new(live))));
        // A large first frame leaves the reader's buffer large, so its next
        // read takes the two small frames behind it in one go.
        let mut all = Vec::new();
        for (n, size) in [2000usize, 10, 10].into_iter().enumerate() {
            let env = SignedEnvelope::new(
                &a,
                Recipient::Direct { agent_fp: Fingerprint::of_bytes(b"r") },
                n as u64,
                vec![n as u8; size],
            );
            let body = serde_json::to_vec(&env).unwrap();
            all.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
            all.extend_from_slice(&body);
        }
        far.write_all(&all).await.unwrap();
        assert_eq!(reader.next().await.unwrap().unwrap().sequence, 0);
        assert_eq!(reader.next().await.unwrap().unwrap().sequence, 1);
        f.revoke(&a);
        let third = reader.next().await;
        assert!(third.is_err(), "the buffered envelope of a revoked peer is refused");
    }
}
