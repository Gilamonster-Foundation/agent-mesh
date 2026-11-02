//! Test homes need the revocation log every handshake is checked against.
//! `amesh keygen` writes one itself from #181 on; until then, and after, this
//! gives a home a genesis log only if it has none.

#![allow(dead_code)] // each test binary uses only what it needs

use agent_mesh_protocol::{RevocationLog, UserKey};
use std::path::Path;

/// Write `<home>/revocation.json` (a genesis log for the home's `user.key`)
/// unless the home already has one.
pub fn ensure_log(home: &Path) {
    let path = home.join("revocation.json");
    if path.exists() {
        return;
    }
    let user = UserKey::load(&home.join("user.key")).expect("home has a user.key");
    let log = RevocationLog::genesis(&user).expect("genesis");
    std::fs::write(path, serde_json::to_vec(&log).expect("encode")).expect("write log");
}

/// Give `far` the same log as `home`, as two hosts of one user share it.
pub fn copy_log(home: &Path, far: &Path) {
    ensure_log(home);
    std::fs::copy(home.join("revocation.json"), far.join("revocation.json")).expect("copy log");
}
