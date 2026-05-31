//! [`Endpoint`] — bound iroh QUIC endpoint for the mesh.
//!
//! Wraps `iroh::Endpoint` and pins:
//!
//! * the ALPN to [`crate::alpn::ALPN`] (one protocol, one version),
//! * the agent's ed25519 key as the iroh secret key,
//! * no relay (mesh-native discovery is mDNS, not the iroh relay
//!   network) — peers we can't reach directly we can't reach at all
//!   in this phase.
//!
//! The struct exposes only the minimum surface the rest of the
//! transport layer needs: bind, dial, accept-one, bound sockets,
//! close. No exotic iroh features leak.

use crate::alpn::ALPN;
use crate::error::{Result, TransportError};
use agent_mesh_protocol::AgentKey;
use iroh::endpoint::{presets, Connection, Incoming};
use iroh::{Endpoint as IrohEndpoint, EndpointAddr, PublicKey, SecretKey};
use std::net::SocketAddr;

/// A bound iroh endpoint, ready to dial and accept agent-mesh
/// connections.
///
/// Drop the endpoint to release its UDP port. Use [`Self::close`]
/// for a graceful shutdown that flushes any pending traffic.
pub struct Endpoint {
    inner: IrohEndpoint,
}

impl Endpoint {
    /// Bind a new endpoint backed by `agent`'s ed25519 key.
    ///
    /// `port = 0` lets the OS pick a free UDP port (use this for
    /// tests and CLI ephemeral binds). A non-zero `port` requests a
    /// specific port; the bind fails if it's in use.
    ///
    /// Binds to the unspecified IPv4 address (`0.0.0.0:<port>`) so
    /// the endpoint is reachable on every local interface.
    pub async fn bind(agent: &AgentKey, port: u16) -> Result<Self> {
        let secret: SecretKey = crate::identity::to_iroh_secret(agent);
        let bind_addr: SocketAddr = format!("0.0.0.0:{port}")
            .parse()
            .expect("0.0.0.0:<port> always parses");

        let inner = IrohEndpoint::builder(presets::N0DisableRelay)
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .clear_address_lookup()
            .bind_addr(bind_addr)
            .map_err(|e| TransportError::Iroh(format!("bind_addr: {e}")))?
            .bind()
            .await
            .map_err(|e| TransportError::Iroh(format!("bind: {e}")))?;
        Ok(Self { inner })
    }

    /// Dial the given peer by iroh `PublicKey` and one-or-more socket
    /// addresses. Negotiates ALPN and returns a [`Connection`] ready
    /// for `open_bi`.
    pub async fn dial(
        &self,
        peer_pubkey: PublicKey,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Connection> {
        let peer_addr = addrs
            .into_iter()
            .fold(EndpointAddr::new(peer_pubkey), EndpointAddr::with_ip_addr);
        let conn = self
            .inner
            .connect(peer_addr, ALPN)
            .await
            .map_err(|e| TransportError::Iroh(format!("connect: {e}")))?;
        Ok(conn)
    }

    /// Await the next incoming connection.
    ///
    /// Returns `None` if the endpoint has been closed. The returned
    /// [`Incoming`] still needs to be awaited (or `accept`ed) to
    /// finish the QUIC handshake before bi-streams can be opened.
    pub async fn accept(&self) -> Option<Incoming> {
        self.inner.accept().await
    }

    /// Local socket addresses the iroh endpoint is bound on. mDNS
    /// announcement picks the first one; tests use them directly.
    #[must_use]
    pub fn local_socket_addrs(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    /// First bound UDP port. Convenience for mDNS announcement.
    /// Returns `0` if the endpoint somehow has no bound sockets
    /// (should not happen after `bind` succeeds).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.local_socket_addrs()
            .first()
            .map(SocketAddr::port)
            .unwrap_or(0)
    }

    /// Our own iroh public key — i.e. our agent pubkey.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.inner.secret_key().public()
    }

    /// Borrow the underlying iroh endpoint. Escape hatch for tests
    /// that need to drive iroh APIs not surfaced here. Not part of
    /// the stable public surface.
    #[doc(hidden)]
    #[must_use]
    pub fn raw(&self) -> &IrohEndpoint {
        &self.inner
    }

    /// Graceful shutdown — closes all live connections, flushes
    /// pending packets, and releases the UDP port.
    pub async fn close(self) {
        self.inner.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_protocol::{AgentMetadata, Caveats, UserKey};

    fn fixture_agent(role: &str) -> AgentKey {
        let user = UserKey::generate();
        AgentKey::issue(
            &user,
            AgentMetadata {
                role: role.into(),
                host: "test-host".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-05-28T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bind_to_ephemeral_port() {
        let agent = fixture_agent("worker");
        let ep = Endpoint::bind(&agent, 0).await.expect("bind");
        let port = ep.port();
        assert!(port > 0, "ephemeral bind should yield a real port");
        assert_eq!(ep.public_key().as_bytes(), &agent.public_bytes());
        ep.close().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bound_sockets_lists_at_least_one_addr() {
        let agent = fixture_agent("worker");
        let ep = Endpoint::bind(&agent, 0).await.expect("bind");
        let addrs = ep.local_socket_addrs();
        assert!(!addrs.is_empty(), "expected at least one bound socket");
        ep.close().await;
    }
}
