//! [`PeerResolver`] — bridges Phase 1 mDNS discovery to Phase 2
//! transport.
//!
//! Given a peer fingerprint, look up the [`PeerInfo`] currently
//! advertised on the LAN (or wait up to a timeout for it to appear).
//! Holds the [`Browser`] alive in a background task and maintains a
//! `RwLock`-protected map keyed by `Fingerprint`.

use crate::error::{Result, TransportError};
use agent_mesh_discovery::{Browser, BrowserEvent, BrowserHandle, PeerInfo};
use agent_mesh_protocol::Fingerprint;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;

/// In-process index of mDNS-discovered peers.
///
/// Created via [`PeerResolver::start`]. Drop the
/// [`ResolverHandle`] returned alongside the resolver to stop
/// browsing and release the daemon thread.
pub struct PeerResolver {
    by_fp: Arc<RwLock<HashMap<Fingerprint, PeerInfo>>>,
    /// Notified every time a new peer is inserted. `resolve` parks
    /// on this with a deadline.
    on_insert: Arc<Notify>,
}

/// Owned handle that keeps the resolver's background browser alive.
/// Drop to stop browsing and reclaim the daemon thread.
pub struct ResolverHandle {
    _browser: BrowserHandle,
    pump: JoinHandle<()>,
}

impl Drop for ResolverHandle {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

impl PeerResolver {
    /// Start the resolver: stand up a [`Browser`], spawn a background
    /// task that copies events into the index, and return both the
    /// resolver and the keep-alive handle.
    pub fn start() -> Result<(Self, ResolverHandle)> {
        let (browser_handle, mut rx) =
            Browser::start().map_err(|e| TransportError::Iroh(format!("browser start: {e}")))?;
        let by_fp: Arc<RwLock<HashMap<Fingerprint, PeerInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let on_insert = Arc::new(Notify::new());

        let by_fp_task = by_fp.clone();
        let notify_task = on_insert.clone();
        let pump = tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                match evt {
                    BrowserEvent::Resolved(peer) => {
                        let fp = peer.agent_fp;
                        by_fp_task.write().await.insert(fp, peer);
                        notify_task.notify_waiters();
                    }
                    BrowserEvent::Removed { instance } => {
                        let mut map = by_fp_task.write().await;
                        map.retain(|_, p| p.instance != instance);
                    }
                }
            }
        });

        Ok((
            Self { by_fp, on_insert },
            ResolverHandle {
                _browser: browser_handle,
                pump,
            },
        ))
    }

    /// Look up `fp`, waiting up to `timeout` for the peer to show up
    /// on mDNS.
    pub async fn resolve(&self, fp: &Fingerprint, timeout: Duration) -> Option<PeerInfo> {
        if let Some(p) = self.by_fp.read().await.get(fp).cloned() {
            return Some(p);
        }
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            let wait = self.on_insert.notified();
            tokio::pin!(wait);
            tokio::select! {
                _ = &mut deadline => return None,
                _ = &mut wait => {
                    if let Some(p) = self.by_fp.read().await.get(fp).cloned() {
                        return Some(p);
                    }
                }
            }
        }
    }

    /// Snapshot the currently-known peers.
    pub async fn known(&self) -> Vec<PeerInfo> {
        self.by_fp.read().await.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_returns_none_on_timeout_when_no_peers() {
        // No announcer running → nothing should resolve. Use a tiny
        // timeout so the test is fast.
        let (resolver, _handle) = PeerResolver::start().expect("start resolver");
        let fp = Fingerprint::of_bytes(b"nobody");
        let out = resolver.resolve(&fp, Duration::from_millis(150)).await;
        assert!(out.is_none(), "expected None, got {out:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn known_starts_empty() {
        let (resolver, _handle) = PeerResolver::start().expect("start resolver");
        assert!(resolver.known().await.is_empty());
    }
}
