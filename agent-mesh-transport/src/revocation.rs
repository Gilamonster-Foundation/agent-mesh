//! Session-level revocation enforcement: [`LiveCheck`] / [`Revocable`] re-check
//! an established session when the local user's revocation log changes.
//!
//! The log reader itself, [`RevocationGuard`], lives in `agent-mesh-protocol`
//! (so verifiers that do not want iroh can use it) and is re-exported here.
//! Fail-closed throughout. See `docs/decisions/revocation.md`.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use agent_mesh_protocol::guard::verify_with as verify_guard;
pub use agent_mesh_protocol::RevocationGuard;
use agent_mesh_protocol::{CertChain, RevocationState};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Result, TransportError};

fn verify_with(peer: &CertChain, state: &RevocationState) -> Result<()> {
    Ok(verify_guard(peer, state)?)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A peer's chain, re-checked whenever the log's head moves.
///
/// An established session holds one, and every envelope it delivers passes
/// [`Self::admit`] first (see [`crate::recv_envelope`]). The log file is read
/// and compared on each call, never trusted from a cache. Cheap to clone;
/// clones share one verdict, and once the peer is refused it stays refused.
#[derive(Clone)]
pub struct LiveCheck {
    guard: RevocationGuard,
    peer: Arc<CertChain>,
    state: Arc<Mutex<Option<Arc<RevocationState>>>>,
}

impl LiveCheck {
    /// Check `peer` now and remember the state it passed.
    ///
    /// # Errors
    /// As [`RevocationGuard::check`].
    pub fn new(guard: RevocationGuard, peer: CertChain) -> Result<Self> {
        let state = guard.state()?;
        verify_with(&peer, &state)?;
        Ok(Self {
            guard,
            peer: Arc::new(peer),
            state: Arc::new(Mutex::new(Some(state))),
        })
    }

    /// Fail if the peer is no longer acceptable. Re-verifies the chain only
    /// when the log's head differs from the last one this peer passed.
    ///
    /// # Errors
    /// As [`RevocationGuard::check`]; the session must then be torn down.
    pub fn admit(&self) -> Result<()> {
        let mut passed = lock(&self.state);
        let Some(last) = passed.clone() else {
            return Err(TransportError::Revoked("session already refused".into()));
        };
        let refused = |passed: &mut Option<Arc<RevocationState>>, e| {
            *passed = None;
            Err(e)
        };
        let state = match self.guard.state() {
            Ok(state) => state,
            Err(e) => return refused(&mut passed, e.into()),
        };
        if state.head != last.head {
            if let Err(e) = verify_with(&self.peer, &state) {
                return refused(&mut passed, e);
            }
            *passed = Some(state);
        }
        Ok(())
    }
}

/// A byte stream that ends with an error the moment its peer is revoked.
///
/// Wraps one half of a session stream; the check runs on every read and write
/// attempt, so no byte from, or to, a revoked peer is handed on after the log
/// learns of the revocation. (Envelopes already buffered above this are
/// caught by the envelope reader's own admission check.)
pub struct Revocable<T> {
    inner: T,
    live: LiveCheck,
}

impl<T> Revocable<T> {
    /// Wrap `inner`, sharing `live` with the stream's other half.
    #[must_use]
    pub fn new(inner: T, live: LiveCheck) -> Self {
        Self { inner, live }
    }

    fn admit(&self) -> io::Result<()> {
        self.live
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
    use agent_mesh_protocol::{
        AgentKey, AgentMetadata, Caveats, RevocationEntry, RevocationLog, UserKey,
    };
    use std::fs;
    use std::path::PathBuf;
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
            Ok(RevocationGuard::open(self.path(), self.user.fingerprint())?)
        }
    }

    #[test]
    fn live_check_admits_until_the_log_revokes_the_peer() {
        let f = Fixture::new();
        let a = agent(&f.user);
        let live = LiveCheck::new(f.open().unwrap(), a.cert().clone()).unwrap();
        live.admit().unwrap();
        f.revoke(&a);
        assert!(matches!(live.admit(), Err(TransportError::Revoked(_))));
    }

    #[test]
    fn live_check_ignores_a_head_move_that_leaves_the_peer_standing() {
        let f = Fixture::new();
        let (a, b) = (agent(&f.user), agent(&f.user));
        let live = LiveCheck::new(f.open().unwrap(), a.cert().clone()).unwrap();
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
        let live = LiveCheck::new(f.open().unwrap(), child.cert().clone()).unwrap();
        f.revoke(&parent);
        assert!(matches!(live.admit(), Err(TransportError::Revoked(_))));
    }

    #[tokio::test]
    async fn a_revocable_stream_errors_once_its_peer_is_revoked() {
        let f = Fixture::new();
        let a = agent(&f.user);
        let live = LiveCheck::new(f.open().unwrap(), a.cert().clone()).unwrap();
        let (near, mut far) = tokio::io::duplex(64);
        let mut near = Revocable::new(near, live);
        far.write_all(b"one").await.unwrap();
        let mut buf = [0u8; 3];
        near.read_exact(&mut buf).await.unwrap();
        f.revoke(&a);
        far.write_all(b"two").await.unwrap();
        let e = near.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(near.write_all(b"x").await.is_err());
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
        let mut reader = EnvelopeReader::new(near, live);
        // A large first frame leaves the reader's buffer large, so its next
        // read takes the two small frames behind it in one go.
        let mut all = Vec::new();
        for (n, size) in [2000usize, 10, 10].into_iter().enumerate() {
            let env = SignedEnvelope::new(
                &a,
                Recipient::Direct {
                    agent_fp: Fingerprint::of_bytes(b"r"),
                },
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
        assert!(
            third.is_err(),
            "the buffered envelope of a revoked peer is refused"
        );
    }
}
