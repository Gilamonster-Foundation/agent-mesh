//! [`Announcer`] — registers this agent on the LAN via mDNS.
//!
//! An `Announcer` owns a [`ServiceDaemon`] that broadcasts the agent's
//! presence on `_agent-mesh._udp.local.` with a TXT record carrying
//! the agent + user fingerprints, role, host, and capabilities. The
//! returned [`AnnouncerHandle`] keeps the daemon alive until dropped;
//! `Drop` sends an mDNS "goodbye" before shutting the daemon down.

use crate::{DEFAULT_PORT, SERVICE_TYPE};
use agent_mesh_core::Fingerprint;
use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};

/// Configuration for announcing this agent on the LAN.
#[derive(Debug, Clone)]
pub struct AnnounceConfig {
    /// Agent's own fingerprint.
    pub agent_fp: Fingerprint,
    /// Agent's full 32-byte ed25519 pubkey. `None` for
    /// discovery-only nodes (`amesh announce` without a transport
    /// bound); `Some(..)` for any node that wants peers to be able
    /// to dial it via the QUIC transport. The pubkey is BLAKE3-
    /// hashed to derive `agent_fp`, so peers can cross-check.
    pub agent_pubkey: Option<[u8; 32]>,
    /// User fingerprint (the trust root we belong to).
    pub user_fp: Fingerprint,
    /// Capabilities to advertise (e.g. `["ollama", "vllm"]`).
    pub capabilities: Vec<String>,
    /// Role (e.g. `"inference-worker"`, `"orchestrator"`).
    pub role: String,
    /// Host hint (typically the system hostname).
    pub host: String,
    /// Port to advertise. Use `0` for discovery-only; Phase 2's
    /// `amesh listen` sets this to the bound iroh port.
    pub port: u16,
}

/// Runs the mDNS announcer for an agent. Drop the [`AnnouncerHandle`]
/// returned by [`start`](Self::start) to stop announcing.
pub struct Announcer;

impl Announcer {
    /// Start the mDNS announcer.
    ///
    /// The returned handle owns the daemon and the registered
    /// instance fullname. Dropping the handle unregisters the
    /// service (sending an mDNS "goodbye") and shuts the daemon
    /// down.
    pub fn start(config: AnnounceConfig) -> Result<AnnouncerHandle> {
        let daemon = ServiceDaemon::new().context("create mDNS daemon")?;
        let instance = format!("am-{}", config.agent_fp.short());
        let port = if config.port == 0 {
            DEFAULT_PORT
        } else {
            config.port
        };

        // mdns-sd's `ServiceInfo::new` takes properties as a slice of
        // `(K, V)` pairs where `K: AsRef<str>` and `V: AsRef<str>`.
        // Ordering doesn't matter for TXT records.
        let agent_hex = config.agent_fp.hex();
        let user_hex = config.user_fp.hex();
        let caps_csv = config.capabilities.join(",");
        let agent_pub_hex = config.agent_pubkey.map(hex::encode);
        let mut props: Vec<(&str, &str)> = vec![
            ("agent_fp", agent_hex.as_str()),
            ("user_fp", user_hex.as_str()),
            ("caps", caps_csv.as_str()),
            ("role", config.role.as_str()),
            ("host", config.host.as_str()),
        ];
        if let Some(p) = agent_pub_hex.as_deref() {
            props.push(("agent_pub", p));
        }

        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{}.local.", config.host),
            "",
            port,
            &props[..],
        )
        .context("build ServiceInfo")?
        .enable_addr_auto();

        let fullname = format!("{instance}.{SERVICE_TYPE}");
        daemon.register(service).context("register mDNS service")?;
        tracing::info!(instance = %fullname, "mDNS service registered");

        Ok(AnnouncerHandle { daemon, fullname })
    }
}

/// Handle keeping an [`Announcer`] alive. Drop to unregister and
/// shut down the daemon.
pub struct AnnouncerHandle {
    daemon: ServiceDaemon,
    fullname: String,
}

impl AnnouncerHandle {
    /// The fully-qualified mDNS instance name we registered as,
    /// e.g. `am-abcd12345678._agent-mesh._udp.local.`.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.fullname
    }
}

impl Drop for AnnouncerHandle {
    fn drop(&mut self) {
        if let Ok(receiver) = self.daemon.unregister(&self.fullname) {
            // Drain briefly so mdns-sd has a chance to flush the
            // goodbye packet onto the wire.
            let _ = receiver.recv_timeout(std::time::Duration::from_millis(100));
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::Fingerprint;

    fn fp_of(seed: u8) -> Fingerprint {
        Fingerprint([seed; 32])
    }

    fn sample_config() -> AnnounceConfig {
        AnnounceConfig {
            agent_fp: fp_of(1),
            agent_pubkey: None,
            user_fp: fp_of(2),
            capabilities: vec!["ollama".into()],
            role: "test-worker".into(),
            host: "test-host".into(),
            port: 0,
        }
    }

    #[test]
    fn announce_config_clones() {
        let c = sample_config();
        let c2 = c.clone();
        assert_eq!(c2.agent_fp, c.agent_fp);
        assert_eq!(c2.role, c.role);
    }

    #[test]
    fn announcer_start_and_drop_is_clean() {
        // Stand the announcer up, then immediately drop the handle.
        // Drop should not panic, and the daemon shutdown path should
        // run cleanly.
        let handle = Announcer::start(sample_config()).expect("start announcer");
        let instance = handle.instance().to_string();
        assert!(
            instance.ends_with("._agent-mesh._udp.local."),
            "instance should end with service type, got {instance}"
        );
        assert!(
            instance.starts_with("am-"),
            "instance should start with am-, got {instance}"
        );
        drop(handle);
    }

    #[test]
    fn announcer_start_with_pubkey_is_clean() {
        // Same as above, but the TXT record carries the optional
        // `agent_pub` field that Phase 2's transport requires.
        let mut config = sample_config();
        config.agent_pubkey = Some([0x42u8; 32]);
        config.port = 42_000;
        let handle = Announcer::start(config).expect("start with pubkey");
        assert!(handle.instance().ends_with("._agent-mesh._udp.local."));
        drop(handle);
    }
}
