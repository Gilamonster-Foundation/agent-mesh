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
    /// resulting file is `chmod 0600`. The parent directory is
    /// created if it doesn't exist.
    pub fn save(&self, path: &Path) -> Result<()> {
        if path.exists() {
            return Err(MeshError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("refusing to overwrite existing key at {}", path.display()),
            )));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let pem = self
            .signing
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| MeshError::InvalidKey(e.to_string()))?;
        std::fs::write(path, pem.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
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
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("user.key");
        UserKey::generate().save(&path).expect("save");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {mode:o}");
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
}
