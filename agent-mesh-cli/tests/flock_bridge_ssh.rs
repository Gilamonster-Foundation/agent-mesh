//! The flock attach suite over the SSH carrier: the same scenarios as
//! `flock_bridge`, with both buses on `agent-mesh-transport-ssh` and a real
//! loopback `sshd` (throwaway keys, host key pinned) between them. The remote
//! reaches the home as a known peer, through the ssh target, not by endpoint.
//!
//! Needs OpenSSH; see `support/sshd.rs` for what happens where it is absent.
#![cfg(unix)]

#[path = "support/sshd.rs"]
mod sshd;
mod support;

use agent_mesh_bus::{Bus, Transport};
use agent_mesh_cli::flock_bridge::Peer;
use agent_mesh_protocol::UserKey;
use agent_mesh_transport::RevocationGuard;
use agent_mesh_transport_ssh::{OpenSshClient, SshTransport, SshTransportOptions};
use std::sync::Arc;
use support::{agent, blocking, World};

/// Both ends over ssh. The sshd comes back too: it must outlive the world.
async fn ssh_world() -> Option<(World, sshd::Sshd)> {
    let user = Arc::new(UserKey::generate());
    let opts = {
        let user = user.clone();
        move || SshTransportOptions::new(RevocationGuard::in_memory(&user))
    };
    let home_key = Arc::new(agent(&user, "home"));
    let home_fp = home_key.fingerprint();
    let home_transport =
        SshTransport::bind(home_key.clone(), "127.0.0.1:0".parse().unwrap(), opts())
            .await
            .unwrap();
    let mesh_port = home_transport.local_addr().port();
    let home_bus =
        Bus::bind_with_transport(home_key, Arc::new(home_transport) as Arc<dyn Transport>).unwrap();

    let sshd = blocking(move || sshd::Sshd::start(mesh_port)).await?;
    let remote_key = Arc::new(agent(&user, "remote"));
    let remote_transport = SshTransport::bind_with_client(
        remote_key.clone(),
        "127.0.0.1:0".parse().unwrap(),
        opts(),
        OpenSshClient::new(&sshd.ssh).unwrap(),
    )
    .await
    .unwrap();
    remote_transport.add_target(home_fp, sshd.target(mesh_port));
    let remote_bus =
        Bus::bind_with_transport(remote_key, Arc::new(remote_transport) as Arc<dyn Transport>)
            .unwrap();
    let world = World {
        user,
        home_bus: Arc::new(home_bus),
        remote_bus: Arc::new(remote_bus),
        peer: Peer::Known(home_fp),
    };
    Some((world, sshd))
}

macro_rules! over_ssh {
    ($name:ident, $scenario:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            let Some((world, sshd)) = ssh_world().await else {
                return;
            };
            // a failure should say what sshd saw
            let ran = tokio::spawn(support::$scenario(world)).await;
            if ran.is_err() {
                eprintln!("--- sshd log ---\n{}", sshd.log());
            }
            ran.unwrap();
            // and it really went through the sshd, as the key it was given
            assert!(
                sshd.log().contains("Accepted publickey"),
                "the scenario passed without an ssh login"
            );
        }
    };
}

over_ssh!(a_remote_session_enrols_and_emits_over_ssh, enrol_and_emit);
over_ssh!(
    a_reader_replays_then_follows_live_over_ssh,
    replay_then_live
);
over_ssh!(
    a_session_offline_across_missed_epochs_renews_over_ssh,
    renew_after_missed_epochs
);
over_ssh!(the_refusals_hold_over_ssh, refusals_hold);
over_ssh!(a_cited_file_is_read_over_ssh, cited_file);
