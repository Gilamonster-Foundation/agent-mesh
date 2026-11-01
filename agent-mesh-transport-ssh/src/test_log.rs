//! A persisted revocation log in a temp dir, for tests that revoke mid-run.

use agent_mesh_protocol::{AgentKey, UserKey};
use agent_mesh_transport::RevocationGuard;

/// A user with a persisted revocation log in a temp dir.
pub(crate) struct LogFixture {
    pub(crate) user: UserKey,
    dir: tempfile::TempDir,
}

impl LogFixture {
    pub(crate) fn new() -> Self {
        let f = Self {
            user: UserKey::generate(),
            dir: tempfile::tempdir().unwrap(),
        };
        let log = agent_mesh_protocol::RevocationLog::genesis(&f.user).unwrap();
        f.write(&log);
        f
    }

    pub(crate) fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("revocation.json")
    }

    pub(crate) fn write(&self, log: &agent_mesh_protocol::RevocationLog) {
        std::fs::write(self.path(), serde_json::to_vec(log).unwrap()).unwrap();
    }

    pub(crate) fn guard(&self) -> RevocationGuard {
        RevocationGuard::open(self.path(), self.user.fingerprint()).unwrap()
    }

    pub(crate) fn bump(&self, current: u64) {
        let mut log: agent_mesh_protocol::RevocationLog =
            serde_json::from_slice(&std::fs::read(self.path()).unwrap()).unwrap();
        log.append(
            &self.user,
            agent_mesh_protocol::RevocationEntry::Generation { current },
        )
        .unwrap();
        self.write(&log);
    }

    pub(crate) fn revoke(&self, agent: &AgentKey) {
        let mut log: agent_mesh_protocol::RevocationLog =
            serde_json::from_slice(&std::fs::read(self.path()).unwrap()).unwrap();
        let agent = agent.fingerprint();
        log.append(
            &self.user,
            agent_mesh_protocol::RevocationEntry::Revoke { agent },
        )
        .unwrap();
        self.write(&log);
    }
}
