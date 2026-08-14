# agent-mesh-transport-ssh

An SSH-backed transport and authenticated session protocol for carrying
`agent_mesh_protocol::SignedEnvelope` records between mesh agents.

The production Option A topology is:

```text
spoke -> system ssh -W -> hub sshd -> loopback TCP listener -> mesh Bus
```

See [`docs/decisions/ssh_transport.md`](../docs/decisions/ssh_transport.md) for
the normative security design and its recorded limitations.

## Security boundary

> [!IMPORTANT]
> A valid `SignedEnvelope` authenticates its contents and signer. It does not
> authenticate the peer that delivered it. Never construct
> `AuthenticatedPeer` from envelope fields.

A conforming SSH transport constructs typed bus provenance only after a fresh,
mutual AgentKey proof-of-possession handshake has established the session. It
then signs each directional record over the session transcript id, counter,
direction, length, and hash of the exact envelope bytes. Raw stream halves are
crate-private: only `AuthenticatedMeshSession` and its authenticated split
halves expose envelope record I/O.

## Three separate authentication results

1. **SSH host authentication:** the spoke verifies the hub's SSH host key.
   Production requires `StrictHostKeyChecking=yes` and a dedicated, pinned
   `UserKnownHostsFile`.
2. **SSH access authentication:** hub `sshd` accepts an authorized SSH client
   key for a restricted account and forward.
3. **Mesh session authentication:** both endpoints prove possession of their
   certified AgentKeys in a fresh, role-separated inner handshake. The dialer
   pins the exact expected mesh agent fingerprint.

`StrictHostKeyChecking=accept-new` is available only as an explicit TOFU
bootstrap policy. It accepts an unknown first-contact host and is not the
production fail-closed default.

With system `ssh -W`, the mesh listener does not receive the SSH username,
accepted client key, or SSH session id. The inner AgentKey identity is
therefore not cryptographically bound to those SSH identities.

## Bus integration

#81 and #82 divide responsibility as follows:

- The SSH session supplies
  `DeliveryProvenance::Direct { carrier: AuthenticatedPeer }`, derived only
  from the verified session handshake.
- The #81 inbox boundary independently verifies every envelope and requires
  its signer, carrier, user root, and recipient to agree before replay state or
  dispatch.
- #82 binds each request correlation to the exact expected responder. The SSH
  backend routes only to sessions authenticated as that fingerprint and does
  not manipulate reply waiters itself.

An unestablished or failed session must never emit `Inbound`; there is no
fallback to envelope-only authentication or unbound provenance.

## Production requirements

- Pin SSH host keys in a dedicated `known_hosts` file. Unknown or changed keys
  fail unless the operator explicitly selected TOFU bootstrap.
- Restrict the SSH account to the intended `direct-tcpip` destination: no
  shell, PTY, agent forwarding, or unrelated forwarding.
- Bind the hub mesh listener to loopback only. `SshTarget` accepts only a
  numeric loopback forwarding address, avoiding a DNS or off-host plaintext
  hop. Treat every accepted socket as unauthenticated until the inner
  handshake succeeds.
- Pipe and drain SSH stderr, inspect child exit status, and retain bounded
  diagnostics for host-key/authentication failures.
- Bound process startup, handshake, prefix/body reads, idle time, queues,
  concurrent sessions, and shutdown. A length cap without a body-read timeout
  is not sufficient.
- Reap SSH children and cancel session tasks on close.
- Use generation-aware cert verification when current generation state is
  available. Generation policy is fixed when the transport binds, so callers
  must close and rebind it on a generation bump. The current bus envelope
  verifier is still context-free and therefore rejects generation-scoped
  envelope certs even if the session handshake succeeds.
- Reuse one authenticated, counter-continuous session per outbound peer until
  it closes or reaches its idle/read deadline; concurrent writes are
  serialized and cancellation poisons the session.

`AgentMetadata::expires_at` is not currently enforced by `CertChain::verify()`;
do not rely on it as an automatic wall-clock expiry control.

## Recorded limitations

- System `ssh -W` does not bind the inner AgentKey to the SSH username, client
  key, or session id.
- A process on the hub can connect directly to the loopback listener and
  attempt inner authentication without traversing `sshd`.
- A transparent live relay can forward the real handshake and records
  byte-for-byte. Transcript-bound records prevent session cutover,
  cross-session replay, and captured-record injection; they do not detect that
  live relay.
- SSH encryption ends at `sshd`; the loopback hop is plaintext.
- Generation revocation requires current policy state and live-session
  teardown.

An in-process SSH server or authenticated proxy metadata channel is required
if a future deployment must bind the accepted SSH identity directly to the
mesh AgentKey.

## License

Apache-2.0.
