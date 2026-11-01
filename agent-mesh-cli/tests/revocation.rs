//! `amesh revocation` / `revoke` against a temp home: every write verifies the
//! log first, extends it, and never rewrites history (#181).

use agent_mesh_protocol::RevocationLog;
use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

const AGENT: &str = "ab00000000000000000000000000000000000000000000000000000000000001";
const OTHER: &str = "cd00000000000000000000000000000000000000000000000000000000000002";

fn amesh(home: &TempDir, args: &[&str]) -> Command {
    let mut c = Command::cargo_bin("amesh").unwrap();
    c.args(["--home", home.path().to_str().unwrap()]).args(args);
    c
}

fn keygen() -> TempDir {
    let home = TempDir::new().unwrap();
    amesh(&home, &["keygen"]).assert().success();
    home
}

fn log_of(home: &TempDir) -> RevocationLog {
    let json = std::fs::read_to_string(home.path().join("revocation.json")).unwrap();
    serde_json::from_str(&json).unwrap()
}

#[test]
fn keygen_writes_a_genesis_log() {
    let home = keygen();
    let st = log_of(&home).verify().unwrap();
    assert_eq!((st.len, st.generation), (1, 0));
    assert!(st.revoked.is_empty());
    amesh(&home, &["revocation", "show"])
        .assert()
        .success()
        .stdout(contains("length:     1"))
        .stdout(contains("generation: 0"));
}

#[test]
fn init_backfills_an_existing_user_and_refuses_twice() {
    let home = keygen();
    std::fs::remove_file(home.path().join("revocation.json")).unwrap();
    amesh(&home, &["revocation", "init"]).assert().success();
    assert_eq!(log_of(&home).verify().unwrap().len, 1);
    amesh(&home, &["revocation", "init"])
        .assert()
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn revoke_appends_and_extends_the_previous_log() {
    let home = keygen();
    let before = log_of(&home).verify().unwrap();
    amesh(&home, &["revoke", AGENT])
        .assert()
        .success()
        .stdout(contains("revoked"));
    let after = log_of(&home);
    after.extends(&before.seen()).unwrap();
    let st = after.verify().unwrap();
    assert_eq!(st.len, 2);
    assert!(st.revoked.contains(&AGENT.parse().unwrap()));
    amesh(&home, &["revocation", "show"])
        .assert()
        .stdout(contains(AGENT));
}

#[test]
fn revoking_twice_is_a_noop_with_a_message() {
    let home = keygen();
    amesh(&home, &["revoke", AGENT]).assert().success();
    amesh(&home, &["revoke", AGENT])
        .assert()
        .success()
        .stdout(contains("already revoked"));
    assert_eq!(log_of(&home).verify().unwrap().len, 2);
}

#[test]
fn revoke_rejects_a_malformed_fingerprint() {
    let home = keygen();
    amesh(&home, &["revoke", "nothex"]).assert().failure();
    assert_eq!(log_of(&home).verify().unwrap().len, 1);
}

#[test]
fn bump_raises_the_generation_each_time() {
    let home = keygen();
    amesh(&home, &["revocation", "bump"])
        .assert()
        .success()
        .stdout(contains("generation 1"));
    amesh(&home, &["revocation", "bump"])
        .assert()
        .success()
        .stdout(contains("generation 2"));
    let st = log_of(&home).verify().unwrap();
    assert_eq!((st.len, st.generation), (3, 2));
}

#[test]
fn corrupted_log_blocks_every_command() {
    let home = keygen();
    amesh(&home, &["revoke", AGENT]).assert().success();
    let path = home.path().join("revocation.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    // Flip the revoked agent's last byte: the node's id no longer matches its signature.
    v["entries"][1]["node"]["payload"]["Revoke"]["agent"][31] = 9.into();
    let tampered = serde_json::to_string(&v).unwrap();
    assert_ne!(tampered, std::fs::read_to_string(&path).unwrap());
    std::fs::write(&path, &tampered).unwrap();
    let out = home.path().join("out.json");
    for args in [
        vec!["revoke", OTHER],
        vec!["revocation", "bump"],
        vec!["revocation", "show"],
        vec!["revocation", "export", out.to_str().unwrap()],
    ] {
        amesh(&home, &args).assert().failure();
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), tampered);
    assert!(!out.exists());
}

#[test]
fn export_writes_a_verifying_copy_and_refuses_a_log_that_does_not_extend() {
    let home = keygen();
    amesh(&home, &["revoke", AGENT]).assert().success();
    let out = home.path().join("export.json");
    amesh(&home, &["revocation", "export", out.to_str().unwrap()])
        .assert()
        .success();
    let exported: RevocationLog =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(exported, log_of(&home));

    // The destination already holds this user's log: re-exporting a longer one
    // extends it, but another user's log does not and is refused.
    amesh(&home, &["revocation", "bump"]).assert().success();
    amesh(&home, &["revocation", "export", out.to_str().unwrap()])
        .assert()
        .success();
    let other = keygen();
    amesh(&other, &["revocation", "export", out.to_str().unwrap()])
        .assert()
        .failure();
    assert_eq!(
        serde_json::from_str::<RevocationLog>(&std::fs::read_to_string(&out).unwrap())
            .unwrap()
            .verify()
            .unwrap()
            .len,
        3
    );
}

#[test]
fn a_writer_waits_for_the_lock_and_then_builds_on_the_new_head() {
    let home = keygen();
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(home.path().join("revocation.json.lock"))
        .unwrap();
    lock.lock().unwrap();
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("amesh"))
        .args(["--home", home.path().to_str().unwrap(), "revoke", AGENT])
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(child.try_wait().unwrap().is_none(), "ran without the lock");
    assert_eq!(log_of(&home).verify().unwrap().len, 1);
    lock.unlock().unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(log_of(&home).verify().unwrap().len, 2);
}

#[test]
fn concurrent_revokes_never_drop_an_acknowledged_entry() {
    let home = keygen();
    let agents: Vec<String> = (0..8)
        .map(|i| format!("{i:02x}{}", "11".repeat(31)))
        .collect();
    let kids: Vec<_> = agents
        .iter()
        .map(|a| {
            std::process::Command::new(assert_cmd::cargo::cargo_bin("amesh"))
                .args(["--home", home.path().to_str().unwrap(), "revoke", a])
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for mut k in kids {
        assert!(k.wait().unwrap().success());
    }
    let st = log_of(&home).verify().unwrap();
    assert_eq!(st.len, 9);
    for a in &agents {
        assert!(st.revoked.contains(&a.parse().unwrap()), "lost {a}");
    }
}

#[test]
fn keygen_beside_an_existing_log_creates_no_key() {
    let home = TempDir::new().unwrap();
    std::fs::write(home.path().join("revocation.json"), "not a log").unwrap();
    amesh(&home, &["keygen"])
        .assert()
        .failure()
        .stderr(contains("revocation log already exists"));
    assert!(!home.path().join("user.key").exists());

    // Another user's valid log is just as incompatible with a fresh key.
    let other = keygen();
    std::fs::copy(
        other.path().join("revocation.json"),
        home.path().join("revocation.json"),
    )
    .unwrap();
    amesh(&home, &["keygen"]).assert().failure();
    assert!(!home.path().join("user.key").exists());
}
