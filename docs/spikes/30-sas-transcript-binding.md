# Spike 30 — Does the handshake expose a transcript hash for SAS binding?

Issue: Gilamonster-Foundation/agent-mesh#30
Consumes: Gilamonster-Foundation/newt-agent#202 (merged) §4.5 (numeric-comparison
pairing) + §12.7. Gates the `newt mesh enroll` work on the newt-agent side.

Status: **resolved — YES.** A sound channel-binding value is reachable at the
iroh/QUIC layer today. §4.5 numeric-comparison SAS can proceed without reworking
the app-level handshake. The app-level cert-chain handshake is *not* a sound
binding source on its own and must **not** be used for the SAS.

Versions analysed (from `Cargo.lock` on `origin/main` @ `6937e3b`):
`iroh 0.98.2` (workspace pin `iroh = "0.98"`, `default-features = false`,
`features = ["tls-ring"]`) → `noq 0.18.0` / `noq-proto 0.17.0` (n0's quinn fork) →
`rustls 0.23.40` (ring backend). `blake3 1` is already a workspace dependency.

---

## TL;DR — the recommended SAS-bound value

Both peers, **after the QUIC handshake completes and after the app-level
cert-chain handshake succeeds**, derive a 32-byte channel-binding secret from the
TLS session via RFC 5705 keying-material export, then hash it to the SAS digits:

```
cb = Connection::export_keying_material(
        &mut [0u8; 32],
        b"agent-mesh/sas/v1",          // label  — domain separation
        enrollment_context,            // context — see below
)                                       // RFC 5705 TLS exporter (iroh 0.98 API)

sas_seed = BLAKE3(
        b"agent-mesh sas v1\0"
        || cb                          // the 32-byte exported secret
        || dialer_agent_pubkey (32)    // lower fingerprint, canonical order
        || acceptor_agent_pubkey (32)  // higher fingerprint
)

SAS digits = base-10 truncation of sas_seed (e.g. first ~20 bits → 6 digits)
```

The load-bearing value is `cb` = the **RFC 5705 exporter output of the actual
dial-time QUIC/TLS session**. Everything else (the BLAKE3 wrap, the pubkey
mix-in) is hardening, not the root of trust.

`enrollment_context` should be the bytes that scope this specific pairing
attempt — concretely the concatenation of both agents' ed25519 pubkeys (so the
context is identical on both ends) and optionally a per-enrollment nonce both
sides have already agreed on. The exporter already binds the session secrets;
the context just adds explicit pairing scoping and is not strictly required for
MITM resistance.

---

## Layer 1 verdict — iroh QUIC/TLS: **YES, exposed.**

`iroh::endpoint::Connection` exposes a public RFC 5705 keying-material exporter:

```rust
// iroh-0.98.2/src/endpoint/connection.rs:1029, in `impl<T: ConnectionState> Connection<T>`
pub fn export_keying_material(
    &self,
    output: &mut [u8],
    label: &[u8],
    context: &[u8],
) -> Result<(), ExportKeyingMaterialError>
```

- It is on `impl<T: ConnectionState> Connection<T>` (connection.rs:812), so it is
  callable on the connected `Connection` agent-mesh already holds.
- `Connection` **and** `ExportKeyingMaterialError` are publicly re-exported from
  `iroh::endpoint` (endpoint.rs:78–99). `agent-mesh-transport` already
  re-exports `Connection` via `iroh_reexports` (lib.rs:47), so the value is
  reachable from the transport crate **today with no new dependency**.
- The call delegates to `noq::Connection::export_keying_material`
  (noq-0.18.0/src/connection.rs:862) → `crypto_session().export_keying_material`
  → the rustls session's RFC 5705 exporter
  (noq-proto-0.17.0/src/crypto/rustls.rs:200, calling
  `rustls ...export_keying_material(output, label, Some(context))`). It binds to
  the **TLS session secrets** of the actual handshake. Not feature-gated; the
  `tls-ring` path the workspace selects enables exactly this code.
- Upstream test `noq-0.18.0/src/tests.rs:177` asserts both peers derive identical
  bytes from the same `(label, context)` — `assert_eq!(&i_buf[..], &o_buf[..])`.

**Why this is MITM-sound here specifically.** iroh uses raw-public-key TLS 1.3
(tls/verifier.rs): the peer's TLS certificate SPKI must equal the `EndpointId`
the dialer addressed, and the `EndpointId` *is* the agent's ed25519 pubkey
(identity.rs makes the agent signing key double as the iroh secret key). agent-mesh
dials a specific `peer_pubkey` (endpoint.rs `dial`). A relay/MITM cannot terminate
the TLS session in the middle without either (a) presenting its own pubkey — which
fails iroh's raw-key cert check against the addressed EndpointId — or (b) lacking
the victim's ed25519 private key, so it cannot complete the TLS 1.3 handshake as
that identity. Either way the man-in-the-middle ends up in a *different* TLS
session than at least one honest endpoint, so its exporter output differs and the
SAS digits will not match. The exporter is the genuine channel-binding value.

Confidence: **high.** Verdict is read directly from the pinned crate sources
(iroh 0.98.2, noq 0.18.0/0.17.0, rustls 0.23.40), the public re-exports, and an
upstream equality test — not from memory or docs.rs.

---

## Layer 2 verdict — app-level cert-chain handshake: **NO bindable transcript today.**

`agent-mesh-transport/src/handshake.rs` (`do_handshake`) is a length-prefixed
JSON exchange of `HelloMsg { cert_chain }` in each direction (plus a `RejectMsg`
path). It verifies each cert chains to the same `user_pubkey` (the auto-team
rule). It contributes **nothing** to a channel binding:

- **No nonce exchange, no challenge/response, no signature over a transcript.**
  identity.rs:34–35 says so outright: "the app-level handshake itself signs
  nothing — it only exchanges and verifies cert chains."
- The cert chains are **static, long-lived, public** credentials. They do not
  tie the two peers' *session* views together. A relay that forwards both
  Hello frames byte-for-byte sees both sides accept (the certs are valid and
  same-user) without ever being in the key-exchange path.
- Therefore a SAS hashed over the cert-chain bytes would be identical on a relay
  and on the honest endpoints → **no MITM protection**. Do not bind the SAS to
  this transcript as it stands.

The app handshake's authentication comes from the QUIC/TLS layer beneath it (the
raw-key cert check), not from the JSON itself. That's exactly why the *exporter*,
not the JSON, is the right binding source.

### If we ever wanted the app layer to be self-binding (optional, not needed)

If the iroh exporter were ever unavailable (e.g. a future transport swap), the
minimal addition that would make the app handshake bindable is a **mutual
transcript signature**: each side computes `t = BLAKE3(dialer_hello_bytes ||
acceptor_hello_bytes)` over the exact frame bytes, signs `t` with its **mesh
signing key** via `agent_mesh_protocol::MeshSigner`, and exchanges + verifies the
signatures before the handshake is declared open. The SAS would then bind to `t`.
This is a real protocol change (new frame, signature verification, fail-closed
path) and is **not required** given Layer 1 succeeds — recorded only as the
fallback.

---

## Recommendation for newt-agent #202 §4.5

**Proceed with the numeric-comparison SAS.** Bind it to the iroh RFC 5705
exporter as in the TL;DR. Concretely, on the newt-agent enrollment path:

1. Complete the normal dial + `do_handshake` (so identity + auto-team are
   already verified — the SAS is a *human-presence* confirmation on top, not a
   replacement for cert verification).
2. Call `connection.export_keying_material(&mut buf32, b"agent-mesh/sas/v1",
   context)` on **both** ends with identical `(label, context)`.
3. `sas_seed = BLAKE3(domain || cb || dialer_pubkey || acceptor_pubkey)` in
   canonical pubkey order; render the low bits as the comparison digits.
4. Human compares digits on phone + worker console; mismatch → abort enrollment.

A thin wrapper in `agent-mesh-transport` is the clean home for step 2–3, e.g.
`Connection`-taking `pub fn sas_channel_binding(conn: &Connection, ctx: &[u8])
-> Result<[u8; 32]>`, so newt-agent never reaches into `iroh::*`. Keeping it in
the transport crate matches the existing `iroh_reexports` "don't leak iroh"
convention (lib.rs:42–49). That wrapper is the only production code this spike
implies, and it is left to the enrollment PR, not this spike.

**Do not** bind the SAS to the cert-chain handshake bytes. **Do** require the
QUIC handshake to have completed before exporting (it always has by the time
agent-mesh holds a `Connection`).
