//! [`UserKey`] — the per-user root of trust.
//!
//! Every agent-mesh participant has exactly one `UserKey` (an ed25519
//! keypair). All other identities — agent keys, GitHub bindings —
//! derive their authority from this one signature. The private half
//! lives on disk in PKCS#8 PEM with `0600` permissions; the public
//! half is what peers compare against [`Fingerprint`]s.

use crate::fingerprint::Fingerprint;
use crate::{MeshError, Result};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

/// A user-level ed25519 keypair. Root of trust for an agent mesh.
///
/// The private half is held in memory by this struct and zeroized on
/// drop. Use [`save`](Self::save) to persist to disk (refuses to
/// overwrite existing files) and [`load`](Self::load) to rehydrate.
pub struct UserKey {
    signing: SigningKey,
}

impl UserKey {
    /// Generate a fresh user key from the operating system RNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        Self { signing }
    }

    /// Public verifying half of the key — safe to share with peers.
    #[must_use]
    pub fn public(&self) -> UserPublic {
        UserPublic {
            verifying: self.signing.verifying_key(),
        }
    }

    /// BLAKE3 fingerprint of the public key bytes.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.public().fingerprint()
    }

    /// Sign an arbitrary message with the user's root key.
    ///
    /// In practice this is called sparingly — typically just to
    /// issue agent certificates and the one-time GitHub binding.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Save the private key to disk in PKCS#8 PEM format.
    ///
    /// Refuses to overwrite an existing file (returns
    /// [`MeshError::Io`] with `AlreadyExists`). On Unix systems the
    /// file is created `0600` *atomically* — the key is never
    /// group/world-readable for any window, not even between create
    /// and the first byte written. The parent directory is created if
    /// it doesn't exist.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let pem = self
            .signing
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| MeshError::InvalidKey(e.to_string()))?;

        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut opts = std::fs::OpenOptions::new();
        // `create_new(true)` folds in the old `path.exists()` guard:
        // it returns `AlreadyExists` rather than truncating an
        // existing key, preserving the refuse-to-overwrite contract.
        opts.write(true).create_new(true);
        // On Unix the file is born at 0600 — there is no umask-default
        // (e.g. 0644) window where the key bytes are readable by
        // group/world. Non-unix has no mode support, so it falls back
        // to a plain create, unchanged from before.
        #[cfg(unix)]
        opts.mode(0o600);

        let mut f = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                MeshError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("refusing to overwrite existing key at {}", path.display()),
                ))
            } else {
                MeshError::Io(e)
            }
        })?;
        f.write_all(pem.as_bytes())?;
        Ok(())
    }

    /// Load a private key previously written by [`save`](Self::save).
    pub fn load(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        let signing =
            SigningKey::from_pkcs8_pem(&pem).map_err(|e| MeshError::InvalidKey(e.to_string()))?;
        Ok(Self { signing })
    }
}

impl std::fmt::Debug for UserKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately do not print the private key bytes.
        f.debug_struct("UserKey")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Drop for UserKey {
    fn drop(&mut self) {
        // Best-effort zeroize of the in-memory keypair. The dalek
        // type itself zeroizes on drop too, but we explicitly scrub
        // the byte copy we hand back to ourselves.
        let mut bytes = self.signing.to_bytes();
        bytes.zeroize();
    }
}

/// Public verifying half of a [`UserKey`]. Cheap to clone, safe to
/// share, and the thing peers actually exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublic {
    #[serde(with = "verifying_key_serde")]
    pub verifying: VerifyingKey,
}

impl UserPublic {
    /// BLAKE3 fingerprint of the underlying 32-byte ed25519 public
    /// key.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_bytes(self.verifying.as_bytes())
    }

    /// Verify a signature was produced by this user's private key
    /// over `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verifying
            .verify(message, signature)
            .map_err(|_| MeshError::BadSignature)
    }

    /// Raw 32-byte ed25519 public key.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; 32] {
        *self.verifying.as_bytes()
    }
}

mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(key: &VerifyingKey, ser: S) -> Result<S::Ok, S::Error> {
        let bytes: &[u8] = key.as_bytes();
        bytes.serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<VerifyingKey, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(de)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_different_keys() {
        let a = UserKey::generate();
        let b = UserKey::generate();
        assert_ne!(
            a.fingerprint(),
            b.fingerprint(),
            "two fresh keys must not collide"
        );
    }

    #[test]
    fn roundtrip_save_load_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        let key = UserKey::generate();
        let fp = key.fingerprint();
        key.save(&path).expect("save");
        let loaded = UserKey::load(&path).expect("load");
        assert_eq!(loaded.fingerprint(), fp);
    }

    #[test]
    fn save_refuses_overwrite() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        let key = UserKey::generate();
        key.save(&path).expect("first save");
        let key2 = UserKey::generate();
        let err = key2.save(&path).expect_err("must refuse");
        match err {
            MeshError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
    }

    #[test]
    fn save_creates_parent_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("dir").join("user.key");
        UserKey::generate().save(&path).expect("save with mkdir -p");
        assert!(path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn save_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        // The key is created 0600 *atomically* (see `save`): the file
        // is born with these bits via `OpenOptions::mode`, never at a
        // umask default and narrowed afterward. There is therefore no
        // window — not even between `create` and the first byte — in
        // which the private key is group/world-readable. This test
        // asserts the final mode is *exactly* 0600 (no wider bits set,
        // hence no wider window the create could have transiently left
        // behind).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        UserKey::generate().save(&path).expect("save");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected exactly 0600, got {mode:o}");
        // No group/world bits at all — the atomic create never widened
        // the file even transiently.
        assert_eq!(mode & 0o077, 0, "no group/world bits, got {mode:o}");
    }

    #[test]
    fn sign_verify() {
        let key = UserKey::generate();
        let pubk = key.public();
        let msg = b"hello agent-mesh";
        let sig = key.sign(msg);
        pubk.verify(msg, &sig).expect("verify own signature");
    }

    #[test]
    fn wrong_message_fails_verify() {
        let key = UserKey::generate();
        let pubk = key.public();
        let sig = key.sign(b"original");
        let err = pubk.verify(b"tampered", &sig).expect_err("must fail");
        assert!(matches!(err, MeshError::BadSignature));
    }

    #[test]
    fn fingerprint_stable_across_loads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        let key = UserKey::generate();
        let fp1 = key.fingerprint();
        key.save(&path).unwrap();
        drop(key);
        let loaded = UserKey::load(&path).unwrap();
        let fp2 = loaded.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn serde_roundtrip_public() {
        let key = UserKey::generate();
        let pubk = key.public();
        let json = serde_json::to_string(&pubk).unwrap();
        let parsed: UserPublic = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pubk);
        assert_eq!(parsed.fingerprint(), pubk.fingerprint());
    }

    #[test]
    fn public_as_bytes_is_32() {
        let key = UserKey::generate();
        let bytes = key.public().as_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn load_fails_on_missing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.key");
        let err = UserKey::load(&path).expect_err("must fail");
        assert!(matches!(err, MeshError::Io(_)));
    }

    #[test]
    fn load_fails_on_garbage_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("garbage");
        std::fs::write(&path, b"not a pem").unwrap();
        let err = UserKey::load(&path).expect_err("must fail");
        assert!(matches!(err, MeshError::InvalidKey(_)));
    }

    // ------------------------------------------------------------------
    // Regression tests for issue #17: `save` must create the key file
    // atomically (O_CREAT|O_EXCL, mode 0600 at open) instead of the old
    // exists()-check → fs::write → chmod sequence. Each test below
    // documents whether it fails on the pre-fix implementation.
    // ------------------------------------------------------------------

    /// Regression test for issue #17 (symlink redirect, deterministic).
    ///
    /// The pre-fix code checked `path.exists()` — which follows
    /// symlinks and returns `false` for a dangling one — and then
    /// `fs::write(path, ..)`, which also follows symlinks. An attacker
    /// who pre-planted a dangling symlink at the expected key path
    /// could therefore redirect where the root key file was created
    /// (and the trailing chmod was applied to the attacker-chosen
    /// target). `create_new(true)` (O_CREAT|O_EXCL) refuses to traverse
    /// any symlink: the open fails with EEXIST and nothing is created.
    ///
    /// FAILS on the pre-fix implementation: old `save` returns Ok and
    /// creates the key at the symlink target.
    #[test]
    #[cfg(unix)]
    fn save_refuses_dangling_symlink_and_creates_nothing() {
        let dir = TempDir::new().unwrap();
        let target_dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        let target = target_dir.path().join("redirected.key");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let err = UserKey::generate()
            .save(&path)
            .expect_err("must refuse to save through a dangling symlink");
        match err {
            MeshError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
        assert!(
            !target.exists(),
            "key must not be created at the symlink target"
        );
        let meta = std::fs::symlink_metadata(&path).expect("symlink still present");
        assert!(
            meta.file_type().is_symlink(),
            "the planted symlink must be left untouched"
        );
    }

    /// Regression test for issue #17 (symlink chain, deterministic).
    ///
    /// Same attack as the dangling-symlink case but through a chain
    /// (`a -> b -> <missing>`): the old `fs::write` resolves the whole
    /// chain and creates the final target; O_EXCL fails on the first
    /// link without resolving anything.
    ///
    /// FAILS on the pre-fix implementation.
    #[test]
    #[cfg(unix)]
    fn save_refuses_symlink_chain_and_creates_nothing() {
        let dir = TempDir::new().unwrap();
        let target_dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        let mid = dir.path().join("mid.link");
        let target = target_dir.path().join("end.key");
        std::os::unix::fs::symlink(&target, &mid).unwrap();
        std::os::unix::fs::symlink(&mid, &path).unwrap();

        let err = UserKey::generate()
            .save(&path)
            .expect_err("must refuse to save through a symlink chain");
        assert!(matches!(err, MeshError::Io(_)));
        assert!(
            !target.exists(),
            "key must not be created at the end of the chain"
        );
    }

    /// Contract pin (passes on both implementations): a symlink to an
    /// EXISTING file is refused, and the target's content and mode are
    /// left untouched. The old code happened to refuse too (via the
    /// followed `exists()` check), but only the new O_EXCL semantics
    /// guarantee the target is never opened at all.
    #[test]
    #[cfg(unix)]
    fn save_refuses_symlink_to_existing_file_without_touching_target() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let target_dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        let target = target_dir.path().join("victim.txt");
        std::fs::write(&target, b"victim content").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let err = UserKey::generate()
            .save(&path)
            .expect_err("must refuse symlink to existing file");
        assert!(matches!(err, MeshError::Io(_)));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"victim content",
            "target content must be untouched"
        );
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "target mode must be untouched");
    }

    /// Regression test for issue #17 (exists-then-write race).
    ///
    /// N threads barrier-race `save` to one fresh path. O_CREAT|O_EXCL
    /// guarantees that exactly one open can ever succeed per path, so
    /// on the fixed code `exactly one Ok` holds unconditionally — this
    /// test cannot flake. The pre-fix code window (all threads pass the
    /// `exists()` check before any file appears, then `fs::write`
    /// truncate-overwrite each other) makes multiple Oks — and torn
    /// key files — overwhelmingly likely across the iterations.
    ///
    /// FAILS on the pre-fix implementation (probabilistically per
    /// iteration, near-certainly across 50).
    #[test]
    fn save_concurrent_racers_exactly_one_wins() {
        use std::sync::{Arc, Barrier};
        const THREADS: usize = 8;
        const ITERS: usize = 50;

        for i in 0..ITERS {
            let dir = TempDir::new().unwrap();
            let path = Arc::new(dir.path().join(format!("user-{i}.key")));
            let barrier = Arc::new(Barrier::new(THREADS));

            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let path = Arc::clone(&path);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        // Generate before the barrier so every thread
                        // hits open() at the same instant.
                        let key = UserKey::generate();
                        barrier.wait();
                        key.save(&path)
                    })
                })
                .collect();

            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let oks = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(
                oks, 1,
                "exactly one concurrent save must win (iteration {i}), got {oks}"
            );
            for r in &results {
                if let Err(MeshError::Io(e)) = r {
                    assert_eq!(
                        e.kind(),
                        std::io::ErrorKind::AlreadyExists,
                        "losers must see AlreadyExists"
                    );
                }
            }
            // The winner's file must be a complete, loadable key —
            // never a torn/truncated PEM.
            UserKey::load(&path).expect("winner must have written a complete valid key");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&*path).unwrap().permissions().mode();
                assert_eq!(mode & 0o077, 0, "winner file must have no group/world bits");
            }
        }
    }

    /// Regression test for issue #17 (the 0600 window itself).
    ///
    /// An observer thread spin-stats the path while `save` runs; every
    /// observation of the file must already be free of group/world
    /// bits. With mode applied at open time this can never fail on the
    /// fixed code (umask can only narrow 0600, never widen it). The
    /// pre-fix code created the file at the umask default (typically
    /// 0644) and only chmod'd it after the PEM bytes were written, so
    /// the observer catches the wide window with high probability
    /// across iterations.
    ///
    /// FAILS on the pre-fix implementation (probabilistically per
    /// iteration, near-certainly across 200).
    #[test]
    #[cfg(unix)]
    fn save_never_exposes_group_world_readable_window() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        const ITERS: usize = 200;

        let dir = TempDir::new().unwrap();
        for i in 0..ITERS {
            let path = Arc::new(dir.path().join(format!("probe-{i}.key")));
            let stop = Arc::new(AtomicBool::new(false));
            let saw_wide = Arc::new(AtomicBool::new(false));

            let observer = {
                let path = Arc::clone(&path);
                let stop = Arc::clone(&stop);
                let saw_wide = Arc::clone(&saw_wide);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        if let Ok(meta) = std::fs::symlink_metadata(&*path) {
                            if meta.permissions().mode() & 0o077 != 0 {
                                saw_wide.store(true, Ordering::Relaxed);
                            }
                        }
                        std::hint::spin_loop();
                    }
                })
            };

            UserKey::generate().save(&path).expect("save");
            stop.store(true, Ordering::Relaxed);
            observer.join().unwrap();

            assert!(
                !saw_wide.load(Ordering::Relaxed),
                "key file was observable with group/world bits (iteration {i})"
            );
        }
    }

    /// Contract pin: the refuse-to-overwrite error message format is
    /// part of the API surface (callers and ops scripts match on it)
    /// and must survive the create_new refactor byte-for-byte.
    #[test]
    fn save_refuse_overwrite_message_pins_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        UserKey::generate().save(&path).expect("first save");
        let err = UserKey::generate().save(&path).expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains(&format!(
                "refusing to overwrite existing key at {}",
                path.display()
            )),
            "unexpected error message: {msg}"
        );
    }

    /// Contract pin: a refused save must leave the existing file's
    /// content and mode untouched (no O_TRUNC side effects). The
    /// concurrent-racers test covers the racing variant of this; this
    /// is the deterministic single-threaded pin.
    #[test]
    fn save_refuse_overwrite_leaves_existing_content_untouched() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        std::fs::write(&path, b"pre-existing bytes, not even a key").unwrap();

        let err = UserKey::generate().save(&path).expect_err("must refuse");
        assert!(matches!(err, MeshError::Io(_)));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"pre-existing bytes, not even a key",
            "existing file must not be truncated or rewritten"
        );
    }

    /// Contract pin: a directory squatting at the key path is refused
    /// (O_EXCL reports EEXIST, surfaced through the same
    /// refuse-to-overwrite mapping) and the directory survives intact.
    #[test]
    fn save_refuses_directory_at_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("inner.txt"), b"keep me").unwrap();

        let err = UserKey::generate()
            .save(&path)
            .expect_err("must refuse dir");
        assert!(matches!(err, MeshError::Io(_)));
        assert!(path.is_dir(), "directory must survive");
        assert_eq!(std::fs::read(path.join("inner.txt")).unwrap(), b"keep me");
    }

    /// Contract pin: a regular file squatting on a parent component
    /// makes save fail cleanly (create_dir_all errors) without
    /// touching the squatting file.
    #[test]
    fn save_errors_when_parent_component_is_a_file() {
        let dir = TempDir::new().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"i am a file").unwrap();
        let path = blocker.join("sub").join("user.key");

        let err = UserKey::generate().save(&path).expect_err("must fail");
        assert!(matches!(err, MeshError::Io(_)));
        assert_eq!(
            std::fs::read(&blocker).unwrap(),
            b"i am a file",
            "blocking file must be untouched"
        );
    }

    /// Contract pin: an unwritable parent directory surfaces a clean
    /// PermissionDenied Io error (no panic, no partial file). Skipped
    /// when running privileged (e.g. root in a CI container), where
    /// permission bits don't bind.
    #[test]
    #[cfg(unix)]
    fn save_errors_on_readonly_parent_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("locked");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();

        // Privilege probe: root (or CAP_DAC_OVERRIDE) ignores mode
        // bits entirely; the scenario is untestable there.
        if std::fs::File::create(parent.join(".probe")).is_ok() {
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipping: running privileged, mode bits don't bind");
            return;
        }

        let path = parent.join("user.key");
        let err = UserKey::generate().save(&path).expect_err("must fail");
        match &err {
            MeshError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
            other => panic!("expected Io(PermissionDenied), got {other:?}"),
        }
        assert!(!path.exists(), "no partial file may appear");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Contract pin: non-UTF-8 filenames round-trip through save/load
    /// and the refuse-to-overwrite path (the error message formats the
    /// path lossily via `display()` without panicking). This workspace
    /// has been bitten by encoding assumptions before; the key store
    /// must not be.
    #[test]
    #[cfg(unix)]
    fn save_load_roundtrip_non_utf8_filename() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(OsStr::from_bytes(b"user-\xff\xfe.key"));

        let key = UserKey::generate();
        let fp = key.fingerprint();
        key.save(&path).expect("save with non-UTF-8 filename");
        let loaded = UserKey::load(&path).expect("load with non-UTF-8 filename");
        assert_eq!(loaded.fingerprint(), fp);

        let err = UserKey::generate().save(&path).expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("refusing to overwrite existing key at "),
            "lossy display must still produce the refuse message: {msg}"
        );
    }

    /// Regression test for issue #17 (live TOCTOU race, the literal
    /// attack in the issue title).
    ///
    /// A planter thread races `save` to materialize the path first
    /// with a dangling symlink. On the fixed code only two syscalls
    /// can create the path — our open(O_CREAT|O_EXCL) and the
    /// planter's symlink(2) — and each fails EEXIST if the other won,
    /// so exactly one wins under every interleaving and the key can
    /// NEVER appear at the symlink target. The pre-fix code had a
    /// check-to-use gap: a symlink planted between `exists()` and
    /// `fs::write` redirected the key to the target and both sides
    /// "succeeded".
    ///
    /// FAILS on the pre-fix implementation (probabilistically per
    /// iteration, near-certainly across 400).
    #[test]
    #[cfg(unix)]
    fn save_racing_symlink_plant_never_redirects_key() {
        use std::sync::{Arc, Barrier};
        const ITERS: usize = 400;

        let dir = TempDir::new().unwrap();
        for i in 0..ITERS {
            let path = Arc::new(dir.path().join(format!("race-{i}.key")));
            let target = Arc::new(dir.path().join(format!("target-{i}.key")));
            let barrier = Arc::new(Barrier::new(2));

            let saver = {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let key = UserKey::generate();
                    barrier.wait();
                    key.save(&path)
                })
            };
            let planter = {
                let path = Arc::clone(&path);
                let target = Arc::clone(&target);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    std::os::unix::fs::symlink(&*target, &*path)
                })
            };

            let save_res = saver.join().unwrap();
            let plant_res = planter.join().unwrap();

            assert!(
                !target.exists(),
                "key must never be written through a planted symlink (iteration {i})"
            );
            assert!(
                save_res.is_ok() != plant_res.is_ok(),
                "exactly one of save/plant must win (iteration {i}): \
                 save={save_res:?} plant_ok={}",
                plant_res.is_ok()
            );
            let meta = std::fs::symlink_metadata(&*path).unwrap();
            if save_res.is_ok() {
                assert!(
                    meta.file_type().is_file(),
                    "winner save must leave a regular file"
                );
                UserKey::load(&path).expect("saved key must be complete and loadable");
            } else {
                assert!(
                    meta.file_type().is_symlink(),
                    "winner plant must leave the symlink"
                );
                if let Err(MeshError::Io(e)) = &save_res {
                    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
                } else {
                    panic!("losing save must be Io(AlreadyExists), got {save_res:?}");
                }
            }
        }
    }

    /// Regression test for issue #17 (self-referential symlink,
    /// deterministic).
    ///
    /// O_CREAT|O_EXCL fails EEXIST when the path names a symlink even
    /// if resolving it would loop, so the fixed code refuses with the
    /// standard overwrite message. The pre-fix `exists()` followed the
    /// link, hit ELOOP, returned `false`, and `fs::write` then failed
    /// with a raw filesystem-loop error — wrong kind, wrong message.
    ///
    /// FAILS on the pre-fix implementation.
    #[test]
    #[cfg(unix)]
    fn save_refuses_self_loop_symlink_with_already_exists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("loop.key");
        std::os::unix::fs::symlink(&path, &path).unwrap();

        let err = UserKey::generate().save(&path).expect_err("must refuse");
        match &err {
            MeshError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
        assert!(
            err.to_string()
                .contains("refusing to overwrite existing key at "),
            "self-loop must surface the standard refusal, got: {err}"
        );
    }

    /// Contract pin: concurrent saves to DISTINCT paths under one
    /// not-yet-existing parent all succeed — `create_dir_all` is
    /// concurrency-safe (treats EEXIST as success). Guards a future
    /// refactor to bare `create_dir`, which would race-fail here.
    #[test]
    fn save_concurrent_distinct_paths_shared_new_parent_all_win() {
        use std::sync::{Arc, Barrier};
        const THREADS: usize = 8;

        let dir = TempDir::new().unwrap();
        let parent = Arc::new(dir.path().join("deep").join("nest"));
        let barrier = Arc::new(Barrier::new(THREADS));

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let parent = Arc::clone(&parent);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let key = UserKey::generate();
                    let fp = key.fingerprint();
                    let path = parent.join(format!("k{t}.key"));
                    barrier.wait();
                    key.save(&path).expect("distinct-path save must succeed");
                    (path, fp)
                })
            })
            .collect();

        for h in handles {
            let (path, fp) = h.join().unwrap();
            let loaded = UserKey::load(&path).expect("each saved key must load");
            assert_eq!(loaded.fingerprint(), fp);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "expected 0600, got {mode:o}");
            }
        }
    }

    /// Contract pin: a name longer than NAME_MAX must surface as a
    /// plain Io error — the AlreadyExists-only `map_err` arm must not
    /// swallow ENAMETOOLONG into the "refusing to overwrite" message.
    /// (Deliberately does not assert the specific kind; its mapping is
    /// Rust-version-dependent.)
    #[test]
    #[cfg(unix)]
    fn save_name_too_long_is_plain_io_error_not_refusal() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("k".repeat(300));

        let err = UserKey::generate().save(&path).expect_err("must fail");
        match &err {
            MeshError::Io(e) => {
                assert_ne!(e.kind(), std::io::ErrorKind::AlreadyExists);
            }
            other => panic!("expected Io, got {other:?}"),
        }
        assert!(
            !err.to_string().contains("refusing to overwrite"),
            "ENAMETOOLONG must not masquerade as the overwrite refusal: {err}"
        );
    }

    /// Contract pin: the on-disk format is strict PKCS#8 PEM with LF
    /// line endings, written exactly once. Guards against a future
    /// "native line endings" change and against the open-then-write
    /// sequence double-writing under refactor. Complements
    /// `roundtrip_save_load_disk`, which only proves loadability.
    #[test]
    fn saved_pem_is_strict_pkcs8_with_lf_endings() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        let key = UserKey::generate();
        let fp = key.fingerprint();
        key.save(&path).expect("save");

        let bytes = std::fs::read(&path).unwrap();
        assert!(
            bytes.starts_with(b"-----BEGIN PRIVATE KEY-----\n"),
            "PEM header missing or not LF-terminated"
        );
        assert!(
            bytes.ends_with(b"-----END PRIVATE KEY-----\n"),
            "PEM trailer missing or not LF-terminated"
        );
        assert!(!bytes.contains(&b'\r'), "PEM must use LF only, found CR");
        assert!(
            bytes.len() < 512,
            "one ed25519 PKCS#8 PEM expected, got {} bytes (double write?)",
            bytes.len()
        );
        let pem = String::from_utf8(bytes).expect("PEM is ASCII");
        let signing = SigningKey::from_pkcs8_pem(&pem).expect("strict PKCS#8 parse");
        assert_eq!(
            Fingerprint::of_bytes(signing.verifying_key().as_bytes()),
            fp,
            "parsed key must match the saved key"
        );
    }

    /// Contract pin: unicode (multibyte UTF-8) filenames round-trip.
    /// Portable companion to the unix-only non-UTF-8 test.
    #[test]
    fn save_load_roundtrip_unicode_filename() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("clé-ключ-鍵-🔑.key");
        let key = UserKey::generate();
        let fp = key.fingerprint();
        key.save(&path).expect("save with unicode filename");
        assert_eq!(UserKey::load(&path).expect("load").fingerprint(), fp);
    }

    /// Contract pin: an existing but EMPTY file is still refused and
    /// left untouched — emptiness must not be mistaken for absence.
    #[test]
    fn save_refuses_existing_empty_file_untouched() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        std::fs::write(&path, b"").unwrap();

        let err = UserKey::generate().save(&path).expect_err("must refuse");
        assert!(matches!(err, MeshError::Io(_)));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            0,
            "empty file must remain exactly as it was"
        );
    }
}
