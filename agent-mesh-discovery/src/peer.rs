//! [`PeerInfo`] — what we know about a peer from mDNS alone.
//!
//! A `PeerInfo` is the *claim* a peer broadcast over mDNS; nothing in
//! it is cryptographically verified yet. The transport handshake in
//! Phase 2 will fetch the peer's actual public key and check the
//! fingerprint against `agent_fp`.

use agent_mesh_core::Fingerprint;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// What we know about a peer from mDNS alone (no handshake yet).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    /// Agent pubkey fingerprint (claimed in TXT record).
    pub agent_fp: Fingerprint,
    /// Raw 32-byte ed25519 pubkey of the agent (claimed in TXT
    /// record). `None` for peers that publish only a fingerprint
    /// (e.g. `amesh announce` in Phase 1; Phase 2's `amesh listen`
    /// publishes both). The Phase 2 transport requires this to dial
    /// the peer — iroh dials by `EndpointId`, which IS the pubkey.
    pub agent_pubkey: Option<[u8; 32]>,
    /// User pubkey fingerprint (claimed in TXT record).
    pub user_fp: Fingerprint,
    /// Capabilities the agent claims (e.g. `["ollama", "vllm"]`).
    pub capabilities: Vec<String>,
    /// Agent role hint (e.g. `"inference-worker"`).
    pub role: String,
    /// Host hint (e.g. `"host-a"`).
    pub host: String,
    /// Resolved IP addresses for the peer.
    pub addrs: Vec<IpAddr>,
    /// Resolved port (`0` means discovery-only — no transport yet).
    pub port: u16,
    /// mDNS service instance fullname (unique on the LAN).
    pub instance: String,
}

impl PeerInfo {
    /// True if this peer shares our user fingerprint.
    #[must_use]
    pub fn is_same_user(&self, our_user_fp: &Fingerprint) -> bool {
        &self.user_fp == our_user_fp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::Fingerprint;

    fn fp_of(seed: u8) -> Fingerprint {
        Fingerprint([seed; 32])
    }

    fn sample_peer(user_fp: Fingerprint) -> PeerInfo {
        PeerInfo {
            agent_fp: fp_of(1),
            agent_pubkey: None,
            user_fp,
            capabilities: vec!["ollama".into()],
            role: "inference-worker".into(),
            host: "test".into(),
            addrs: vec![],
            port: 0,
            instance: "test._agent-mesh._udp.local.".into(),
        }
    }

    #[test]
    fn same_user_detects_matching_fp() {
        let user_fp = fp_of(42);
        let peer = sample_peer(user_fp);
        assert!(peer.is_same_user(&user_fp));
    }

    #[test]
    fn same_user_rejects_different_fp() {
        let peer = sample_peer(fp_of(42));
        assert!(!peer.is_same_user(&fp_of(99)));
    }

    #[test]
    fn peer_info_serde_roundtrip() {
        let peer = PeerInfo {
            agent_fp: fp_of(1),
            agent_pubkey: Some([7u8; 32]),
            user_fp: fp_of(2),
            capabilities: vec!["ollama".into(), "vllm".into()],
            role: "inference-worker".into(),
            host: "host-a".into(),
            addrs: vec!["127.0.0.1".parse().unwrap()],
            port: 11434,
            instance: "test._agent-mesh._udp.local.".into(),
        };
        let json = serde_json::to_string(&peer).unwrap();
        let back: PeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(peer, back);
    }

    #[test]
    fn peer_info_with_no_capabilities() {
        let peer = PeerInfo {
            agent_fp: fp_of(3),
            agent_pubkey: None,
            user_fp: fp_of(4),
            capabilities: vec![],
            role: "scout".into(),
            host: "h".into(),
            addrs: vec![],
            port: 0,
            instance: "i".into(),
        };
        assert!(peer.capabilities.is_empty());
        let json = serde_json::to_string(&peer).unwrap();
        let back: PeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(peer, back);
    }

    #[test]
    fn peer_info_with_ipv6() {
        let peer = PeerInfo {
            agent_fp: fp_of(5),
            agent_pubkey: None,
            user_fp: fp_of(6),
            capabilities: vec!["ipv6".into()],
            role: "r".into(),
            host: "h".into(),
            addrs: vec!["::1".parse().unwrap()],
            port: 0,
            instance: "i".into(),
        };
        let json = serde_json::to_string(&peer).unwrap();
        let back: PeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(peer, back);
    }
}
