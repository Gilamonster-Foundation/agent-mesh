//! [`Browser`] — discovers other agent-mesh peers on the LAN via mDNS.
//!
//! A `Browser` owns a [`ServiceDaemon`] and a background thread that
//! bridges mdns-sd's `flume`-style channel onto a tokio
//! `mpsc::UnboundedReceiver<BrowserEvent>`. The returned
//! [`BrowserHandle`] keeps the daemon alive until dropped; `Drop`
//! stops the browse and shuts the daemon down.

use crate::{PeerInfo, SERVICE_TYPE};
use agent_mesh_protocol::Fingerprint;
use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::str::FromStr;
use tokio::sync::mpsc;

/// Events emitted by the browser.
#[derive(Debug, Clone)]
pub enum BrowserEvent {
    /// A peer was discovered (or refreshed). Always carries a fully
    /// parsed [`PeerInfo`].
    Resolved(PeerInfo),
    /// A peer left the LAN — either through an explicit mDNS goodbye
    /// or because its TTL expired.
    Removed {
        /// Service instance fullname, matching `PeerInfo::instance`.
        instance: String,
    },
}

/// Spawns an mDNS browser. Drop the [`BrowserHandle`] returned by
/// [`start`](Self::start) to stop browsing.
pub struct Browser;

impl Browser {
    /// Start browsing for mesh peers.
    ///
    /// Returns a [`BrowserHandle`] (must be kept alive for as long as
    /// you want to receive events) and a tokio
    /// `mpsc::UnboundedReceiver` of [`BrowserEvent`]s. The receiver
    /// stays open as long as the handle is alive; when the handle is
    /// dropped, the background thread exits and the channel closes.
    pub fn start() -> Result<(BrowserHandle, mpsc::UnboundedReceiver<BrowserEvent>)> {
        let daemon = ServiceDaemon::new().context("create mDNS daemon")?;
        let receiver = daemon.browse(SERVICE_TYPE).context("start browse")?;
        let (tx, rx) = mpsc::unbounded_channel();

        let tx_thread = tx.clone();
        std::thread::Builder::new()
            .name("amesh-discovery-browse".into())
            .spawn(move || {
                while let Ok(event) = receiver.recv() {
                    match event {
                        ServiceEvent::ServiceResolved(info) => {
                            match peer_from_service_info(&info) {
                                Some(peer) => {
                                    if tx_thread.send(BrowserEvent::Resolved(peer)).is_err() {
                                        break;
                                    }
                                }
                                None => {
                                    tracing::debug!(
                                        instance = %info.get_fullname(),
                                        "ignoring resolution with missing or malformed TXT"
                                    );
                                }
                            }
                        }
                        ServiceEvent::ServiceRemoved(_ty, fullname) => {
                            if tx_thread
                                .send(BrowserEvent::Removed { instance: fullname })
                                .is_err()
                            {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            })
            .context("spawn browse bridge thread")?;

        Ok((
            BrowserHandle {
                daemon,
                _tx_keepalive: tx,
            },
            rx,
        ))
    }
}

/// Handle keeping a [`Browser`] alive. Drop to stop the browse and
/// shut down the daemon.
pub struct BrowserHandle {
    daemon: ServiceDaemon,
    /// Holding the original sender open prevents the receiver-side
    /// `mpsc::UnboundedReceiver::recv` from returning `None` while
    /// the handle is alive — even if the bridge thread exits first.
    _tx_keepalive: mpsc::UnboundedSender<BrowserEvent>,
}

impl Drop for BrowserHandle {
    fn drop(&mut self) {
        let _ = self.daemon.stop_browse(SERVICE_TYPE);
        let _ = self.daemon.shutdown();
    }
}

/// Parse a [`ServiceInfo`](mdns_sd::ServiceInfo) into our richer
/// [`PeerInfo`]. Returns `None` if required TXT fields (`agent_fp`,
/// `user_fp`) are missing or malformed.
fn peer_from_service_info(info: &mdns_sd::ServiceInfo) -> Option<PeerInfo> {
    let props = info.get_properties();
    let agent_fp_str = props.get_property_val_str("agent_fp")?;
    let user_fp_str = props.get_property_val_str("user_fp")?;
    let agent_fp = Fingerprint::from_str(agent_fp_str).ok()?;
    let user_fp = Fingerprint::from_str(user_fp_str).ok()?;
    let agent_pubkey = props.get_property_val_str("agent_pub").and_then(|s| {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        } else {
            None
        }
    });
    let caps_str = props.get_property_val_str("caps").unwrap_or("");
    let capabilities: Vec<String> = caps_str
        .split(',')
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
        .collect();
    let role = props.get_property_val_str("role").unwrap_or("").to_string();
    let host = props.get_property_val_str("host").unwrap_or("").to_string();

    let addrs: Vec<std::net::IpAddr> = info.get_addresses().iter().copied().collect();
    let port = info.get_port();
    let instance = info.get_fullname().to_string();

    Some(PeerInfo {
        agent_fp,
        agent_pubkey,
        user_fp,
        capabilities,
        role,
        host,
        addrs,
        port,
        instance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_from_service_info_rejects_missing_agent_fp() {
        // Build a ServiceInfo with only `user_fp` set — should be
        // rejected because `agent_fp` is required.
        let user_hex = "a".repeat(64);
        let props: Vec<(&str, &str)> = vec![("user_fp", user_hex.as_str())];
        let info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            "missing-agent",
            "host.local.",
            "",
            0,
            &props[..],
        )
        .expect("build info");
        assert!(peer_from_service_info(&info).is_none());
    }

    #[test]
    fn peer_from_service_info_rejects_malformed_fp() {
        let props: Vec<(&str, &str)> = vec![("agent_fp", "not-hex"), ("user_fp", "also-not-hex")];
        let info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            "malformed-fp",
            "host.local.",
            "",
            0,
            &props[..],
        )
        .expect("build info");
        assert!(peer_from_service_info(&info).is_none());
    }

    #[test]
    fn peer_from_service_info_parses_full_record() {
        let agent_hex = "11".repeat(32);
        let user_hex = "22".repeat(32);
        let props: Vec<(&str, &str)> = vec![
            ("agent_fp", agent_hex.as_str()),
            ("user_fp", user_hex.as_str()),
            ("caps", "ollama,vllm"),
            ("role", "inference-worker"),
            ("host", "host-a"),
        ];
        let info =
            mdns_sd::ServiceInfo::new(SERVICE_TYPE, "am-test", "host-a.local.", "", 42, &props[..])
                .expect("build info");
        let peer = peer_from_service_info(&info).expect("parse peer");
        assert_eq!(peer.role, "inference-worker");
        assert_eq!(peer.host, "host-a");
        assert_eq!(peer.port, 42);
        assert_eq!(
            peer.capabilities,
            vec!["ollama".to_string(), "vllm".to_string()]
        );
        assert_eq!(peer.agent_fp.hex(), agent_hex);
        assert_eq!(peer.user_fp.hex(), user_hex);
    }

    #[test]
    fn peer_from_service_info_extracts_agent_pubkey_when_present() {
        let agent_hex = "11".repeat(32);
        let user_hex = "22".repeat(32);
        let pub_hex = "ab".repeat(32);
        let props: Vec<(&str, &str)> = vec![
            ("agent_fp", agent_hex.as_str()),
            ("user_fp", user_hex.as_str()),
            ("agent_pub", pub_hex.as_str()),
            ("caps", "ollama"),
            ("role", "inference-worker"),
            ("host", "h"),
        ];
        let info =
            mdns_sd::ServiceInfo::new(SERVICE_TYPE, "am-pubkey", "h.local.", "", 4242, &props[..])
                .expect("build info");
        let peer = peer_from_service_info(&info).expect("parse peer");
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hex::decode(&pub_hex).unwrap());
        assert_eq!(peer.agent_pubkey, Some(expected));
    }

    #[test]
    fn peer_from_service_info_drops_invalid_pubkey() {
        // An `agent_pub` TXT entry that isn't valid hex / wrong
        // length is silently ignored — the peer is still returned,
        // just with `agent_pubkey: None`. Phase 2 callers will fail
        // closed at dial time.
        let agent_hex = "11".repeat(32);
        let user_hex = "22".repeat(32);
        let props: Vec<(&str, &str)> = vec![
            ("agent_fp", agent_hex.as_str()),
            ("user_fp", user_hex.as_str()),
            ("agent_pub", "not-hex"),
            ("role", "r"),
            ("host", "h"),
        ];
        let info =
            mdns_sd::ServiceInfo::new(SERVICE_TYPE, "am-badpub", "h.local.", "", 0, &props[..])
                .expect("build info");
        let peer = peer_from_service_info(&info).expect("parse peer");
        assert!(peer.agent_pubkey.is_none());
    }

    #[test]
    fn peer_from_service_info_handles_empty_caps() {
        let agent_hex = "33".repeat(32);
        let user_hex = "44".repeat(32);
        let props: Vec<(&str, &str)> = vec![
            ("agent_fp", agent_hex.as_str()),
            ("user_fp", user_hex.as_str()),
            ("caps", ""),
            ("role", "scout"),
            ("host", "h"),
        ];
        let info =
            mdns_sd::ServiceInfo::new(SERVICE_TYPE, "am-empty-caps", "h.local.", "", 0, &props[..])
                .expect("build info");
        let peer = peer_from_service_info(&info).expect("parse peer");
        assert!(peer.capabilities.is_empty());
    }
}
