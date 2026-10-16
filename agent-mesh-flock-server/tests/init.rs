//! `init`, the key file, and a restart.
#![cfg(unix)]
mod support;

use agent_mesh_flock_server::{
    init, load_genesis, load_server_key, store_server_key, ServerError, GENESIS_FILE, KEY_FILE,
};
use agent_mesh_protocol::{Assertion, UserKey};
use content_addressable::ContentId;
use std::os::unix::fs::PermissionsExt;
use support::Env;

#[test]
fn init_writes_a_0600_key_and_a_genesis_whose_cid_is_the_flock_id() {
    let env = Env::new();
    let mode = std::fs::metadata(env.dir().join(KEY_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let genesis = load_genesis(&env.dir()).unwrap();
    use content_addressable::ContentAddressable;
    assert_eq!(genesis.node.content_id().unwrap(), env.flock);
}

#[test]
fn init_is_once_only() {
    let env = Env::new();
    let again = init(&env.dir(), &UserKey::generate(), support::spec());
    assert!(matches!(again, Err(ServerError::AlreadyInitialised(_))));
}

#[test]
fn a_tampered_genesis_does_not_load() {
    let env = Env::new();
    let path = env.dir().join(GENESIS_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(load_genesis(&env.dir()).is_err());
}

#[test]
fn the_key_file_refuses_wider_modes_and_a_mismatched_pair() {
    let env = Env::new();
    let path = env.dir().join(KEY_FILE);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        load_server_key(&path),
        Err(ServerError::KeyFileMode)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other = tempfile::tempdir().unwrap();
    let theirs = Env::new();
    // splice their cert onto this seed
    let mine: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let theirs_v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(theirs.dir().join(KEY_FILE)).unwrap()).unwrap();
    let mut spliced = mine.clone();
    spliced["cert"] = theirs_v["cert"].clone();
    let p = other.path().join("k");
    std::fs::write(&p, spliced.to_string()).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_server_key(&p).is_err());
    // and a stored key refuses to be overwritten
    let key = load_server_key(&path).unwrap();
    assert!(store_server_key(&path, &key).is_err());
}

#[test]
fn after_a_restart_the_server_has_the_same_identity_and_still_signs() {
    let mut env = Env::new();
    let fp_before = env.server_key().fingerprint();
    let mut server = env.open();
    let (n, s) = env.server_event("before");
    server.admit(n, s).unwrap();
    drop(server);

    let mut server = env.open();
    assert_eq!(server.admitted(), 1);
    let key = env.server_key();
    assert_eq!(key.fingerprint(), fp_before);
    let (n, s) = env.server_event("after");
    assert_eq!(server.admit(n, s).unwrap().index, 2);

    // it can still certify a session key: a chain rooted at the same server
    let session = key.delegate(support::meta("h1")).unwrap();
    let cid = ContentId::from_canonical_bytes(b"x");
    Assertion::sign(&session, &cid)
        .verify(&cid, &server.server_pub(), 0)
        .unwrap();
}
