//! Shared test helpers for the agent-mesh workspace.
//!
//! Anything that more than one crate's tests would reproduce lives
//! here. Today that's a temp-dir factory and a deterministic
//! `AgentMetadata` fixture.

use agent_mesh_core::{AgentKey, AgentMetadata, UserKey};

/// Spawn a temporary directory bounded to the caller's scope.
///
/// Panics on failure — tests don't want to thread a Result through
/// every helper call.
#[must_use]
pub fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create tempdir")
}

/// Issue a test agent key with deterministic metadata for a given
/// user. `role` is the only varying field; `issued_at` is fixed so
/// tests don't tickle wall-clock dependencies.
#[must_use]
pub fn issue_test_agent(user: &UserKey, role: &str) -> AgentKey {
    AgentKey::issue(
        user,
        AgentMetadata {
            role: role.to_string(),
            host: "test-host".to_string(),
            capabilities: vec!["test".to_string()],
            issued_at: "2026-05-28T00:00:00Z".to_string(),
            expires_at: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tempdir_creates_dir() {
        let dir = tempdir();
        assert!(dir.path().is_dir());
    }

    #[test]
    fn issue_test_agent_verifies() {
        let user = UserKey::generate();
        let agent = issue_test_agent(&user, "worker");
        agent.cert().verify().expect("cert verifies");
        assert_eq!(agent.cert().metadata.role, "worker");
    }
}
