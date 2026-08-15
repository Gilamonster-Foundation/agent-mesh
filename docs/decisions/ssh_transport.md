# Design note: SSH carriage with an inner AgentKey-bound session

**Status:** Option A implemented; bus ingress is available only through
authenticated session typestate

**Date:** 2026-08-14

**Origin:** SSH-carried docking for the hub-and-spoke topology

## Decision summary

Option A uses the system OpenSSH client and the host's `sshd` as the encrypted
carriage:

```text
spoke process -> system ssh -W -> sshd -> hub loopback TCP listener
```

Inside that byte stream, the mesh transport performs a fresh, mutual
AgentKey proof-of-possession handshake. Only an established inner session may
produce bus deliveries. Every established-session record is cryptographically
bound to its transcript id, direction, counter, and exact envelope bytes.

This design has three distinct authentication results. They must not be
collapsed into one claim:

1. The SSH client authenticates the hub's **SSH host key**.
2. `sshd` authenticates and authorizes the connecting **SSH client key**.
3. The inner session authenticates possession of a certified **mesh
   AgentKey**.

The system `ssh -W` architecture does not cryptographically bind those three
identities together. In particular, the Rust loopback listener does not learn
the SSH username, accepted client key, or SSH session identifier.

> [!IMPORTANT]
> A valid `SignedEnvelope` proves only that its signer authorized those
> envelope bytes. It does **not** prove which peer delivered them or establish
> transport provenance. An SSH transport may construct
> `AuthenticatedPeer` only from its completed, verified per-session protocol.
> It must never infer the carrier from `SignedEnvelope::cert_chain`,
> `sender_agent_fp()`, or any other message field.

## Context

The native mesh carriage uses iroh/QUIC and mDNS. The agent's ed25519 key is
also the QUIC endpoint identity, so the QUIC handshake can bind possession of
the transport key to the mesh agent. System OpenSSH uses separate SSH keys and
hides the accepted client identity from a process reached through `ssh -W`.

Envelope verification cannot fill that gap. A captured, previously unseen
envelope can be relayed unchanged; its signature still verifies. The SSH
backend therefore needs an authenticated inner session before it can satisfy
the bus provenance contract introduced by #81.

## The three authentication layers

### 1. SSH host authentication

The spoke must authenticate the SSH server before offering credentials or mesh
traffic.

The production default is strict pinning:

```text
ssh -F none                                           \
    -T                                                \
    -W <mesh-host>:<mesh-port>                        \
    -o BatchMode=yes                                  \
    -o StrictHostKeyChecking=yes                      \
    -o UserKnownHostsFile=<dedicated-known-hosts>     \
    -o GlobalKnownHostsFile=none                      \
    -o UpdateHostKeys=no                              \
    -o IdentitiesOnly=yes                             \
    -o IdentityFile=<identity-file>                   \
    -o ForwardAgent=no -o IdentityAgent=none          \
    -o ControlMaster=no -o ControlPath=none           \
    -o EscapeChar=none                                \
    -o ExitOnForwardFailure=yes                       \
    -p <ssh-port> <user>@<hub>
```

The dedicated pin must be provisioned out of band as a raw host key or an
`@cert-authority` host-CA entry. The existing dock fingerprint words identify
a mesh AgentKey, not an SSH host key, and are not a substitute for this pin. A
changed or unknown SSH host key fails before the channel is usable.

`StrictHostKeyChecking=accept-new` is an explicit bootstrap mode only. It is
trust on first use: it accepts an unknown first-contact key and rejects later
changes. It is not fail-closed authentication of an already-known hub, must
never be the production default, and must be surfaced to the operator as a
TOFU decision.

SSH host authentication identifies `sshd`; it does not identify the mesh
AgentKey served behind the forward. The inner handshake separately pins the
expected mesh target.

### 2. SSH client authentication and access authorization

On the hub, `sshd` checks the spoke's SSH key against the dedicated account's
policy. The account should be non-interactive and restricted to the one
loopback destination, with no PTY, shell, agent forwarding, or unrelated port
forwarding. `SshTarget` requires that forwarding destination to be a numeric
loopback IP, so configuration cannot silently extend the plaintext hop through
DNS or to another host. Removing an authorized key prevents new SSH
connections.

This is a gate on remote access to the forwarded port. With system `ssh -W`,
the accepted username/key/session id terminates at `sshd`; the loopback TCP
connection presented to the mesh process carries none of them. The mesh
process must not claim that an `AuthenticatedPeer` is bound to the SSH client
key.

### 3. Inner AgentKey mesh authentication

The inner protocol proves that each endpoint currently possesses the private
AgentKey corresponding to a verified `CertChain`. It also enforces the
same-user policy and, on the dialer, an exact expected responder fingerprint.

This result is the sole source of `AuthenticatedPeer` for Option A. It says
"this byte-stream session completed mutual proof as mesh agent X under user
root Y." It does not say which SSH username or key opened the outer channel.

## Inner session protocol

### Fresh, mutual, role-separated handshake

Each connection performs two symmetric flights before accepting an envelope:

1. Both endpoints concurrently exchange a bounded `Hello`. Each Hello carries
   the protocol and wire versions, transport label, ordered role, a fresh
   32-byte OS-random nonce, the exact cert chain, fixed record parameters, and
   the initiator's exact expected responder fingerprint.
2. After validating the peer Hello, both endpoints concurrently exchange a
   role-separated proof over the same transcript id. Each endpoint becomes
   established only after its peer's proof verifies under the leaf key in the
   validated peer cert.

The transcript commits to the exact encoded Hello payloads, length-delimited
and ordered by role:

```text
transcript_id = BLAKE3(
    "agent-mesh/ssh-session/v1/transcript\0" ||
    u32be(len(initiator_hello)) || exact_initiator_hello ||
    u32be(len(responder_hello)) || exact_responder_hello
)

proof = Sign(agent_key,
    "agent-mesh/ssh-session/v1/proof\0" || role_byte || transcript_id
)
```

Exact raw payload hashing avoids relying on JSON map canonicalization. The
distinct role labels prevent reflection. Either fresh nonce changes the
transcript, so a captured proof cannot authenticate a second connection.
Stream ordering places each proof before that endpoint's first record, and the
peer never releases a record before it has verified the proof.

Cert verification alone is not proof of possession. The implementation must
verify each proof under the leaf key in the corresponding verified cert before
recording that peer's user and agent fingerprints.

### Exact target pinning

Same-user membership is not enough for outbound routing. Before sending any
application bytes, the dialer must compare the authenticated responder's leaf
fingerprint with the exact fingerprint configured for that SSH target. A
different sibling agent under the same user root is the wrong target and must
close the connection.

The hub may additionally require an allowlist of permitted initiating agent
fingerprints. Without one, its inner admission policy is "any currently valid
agent under this user root."

### Transcript-bound session records

After the handshake, the raw envelope frame is carried inside a signed session
record. For each direction, counters start at 1 and the receiver requires the
exact next value:

```text
record_proof = Sign(sender_agent_key,
    "agent-mesh/ssh-session/v1/record\0" ||
    transcript_id || direction || counter_be || envelope_len_be ||
    BLAKE3(exact_envelope_frame_bytes)
)
```

The receiver verifies the record proof under the authenticated session peer,
checks the session id, direction, and counter, and only then releases the
envelope to the bus. Counters are per session and per direction; they do not
replace the envelope's mesh-wide sequence number.

This binding prevents a captured record from being injected after a connection
cutover or replayed into a separately handshaken session. It also prevents a
different authenticated sibling from hiding who wrapped another agent's
envelope: the record remains attributable to that sibling, and the #81 boundary
then rejects carrier/signer mismatch. The bus still independently verifies the
inner envelope.

It does **not** prevent a transparent relay that forwards the live handshake
and every subsequent byte unchanged between the real endpoints. The system
OpenSSH subprocess exposes no channel-binding value with which the inner
transcript could distinguish that path.

## Typestate and lifecycle

The implementation must make the security boundary visible in its state
machine:

```text
Connecting -> MeshAuthenticating -> Established -> Closing -> Closed
                    |                    |
                    +------ failure -----+
```

- `Connecting` owns an SSH child or accepted loopback socket but no peer.
- `MeshAuthenticating` is represented by `UnauthenticatedMeshSession` and may
  exchange only bounded handshake frames.
- `Established` is represented by `AuthenticatedMeshSession` and owns the
  immutable `AuthenticatedPeer`, `transcript_id`,
  per-direction counters, writer lock, and reply-route identity. Only this
  state may create `Inbound` or send envelope records.
- Any malformed proof, root/target mismatch, counter error, timeout, EOF, or
  child failure transitions directly to closing. There is no fallback to
  envelope-only authentication or `DeliveryProvenance::Unbound`.
- `close` stops ingress and receivers, cancels reader tasks, closes sockets,
  removes cached session routes, and starts bounded termination/reaping for
  child processes. Concurrent transport calls observe the persistent closed
  state and cannot register a new established session.

An opaque SSH reply route must name the exact established session and its
authenticated peer. `Transport::reply(fp, route, env)` rechecks that the
route's peer is `fp`. A live matching route is used once. A route already known
stale, foreign, or from another backend is never trusted or reused; when an
exact target is configured, the transport falls back to a fresh authenticated
session. It does not retry after an ambiguous partial write.

## Responsibility split with the bus

### #81 — transport provenance and common admission

The SSH transport contributes:

```text
Inbound {
    envelope,
    provenance: DeliveryProvenance::Direct {
        carrier: AuthenticatedPeer::new(session_user_fp, session_agent_fp),
    },
    reply_route,
}
```

Those fingerprints come only from the established session protocol above.
The #81 common inbox boundary then independently:

- verifies the cert chain, payload CID, and envelope signature;
- requires the direct carrier agent and user to match the envelope signer;
- enforces the local same-user policy and direct recipient;
- performs all of those checks before nonce or sequence mutation.

The transport must not pre-decide that a valid envelope makes an unbound
delivery safe. The bus deliberately rejects unbound provenance.

### #82 — expected responder binding

For a request, the bus stores the expected responder fingerprint with the
correlation id. An inbound reply completes the waiter only when its verified
signer is that expected peer; a sibling agent cannot win the correlation race.

The SSH transport does not manipulate reply waiters. Its responsibilities are
to route `send_to(fp, ...)` only to a session authenticated as `fp`, report
correct provenance on receive, and return replies over an opaque route bound to
the same peer. #82 does not repair missing transport provenance; it relies on
#81 and the inner session.

## Loopback listener and confidentiality boundary

The hub mesh listener binds only to explicitly configured loopback addresses,
never a wildcard interface. `sshd` forwards the `direct-tcpip` channel to that
TCP port. The listener accepts a socket as unauthenticated and runs the inner
handshake before it can create a bus delivery.

Traffic is encrypted between the spoke and `sshd`, but is plaintext on the
hub's loopback hop. Session-record and envelope signatures protect integrity
and identity there; they do not encrypt that hop.

A process on the hub can connect directly to the listener and attempt the
inner handshake without passing SSH access control. It still needs an AgentKey
accepted by the inner mesh policy, but Option A cannot prove that such a
connection traversed `sshd`. Bind permissions, host isolation, firewall rules,
and an agent allowlist reduce this exposure; an in-process SSH server or an
authenticated proxy metadata channel is required to remove it.

## Process supervision, diagnostics, and resource bounds

Security failures must be observable and bounded:

- Pipe and continuously drain SSH stderr into a bounded diagnostic buffer;
  never discard host-key or authentication alarms, and never let stderr fill
  and deadlock the child.
- Inspect and report the child exit status. Preserve useful stderr context
  without logging private key material or arbitrary unbounded peer output.
- Bound process startup, SSH establishment, inner handshake, frame-prefix,
  frame-body, idle, and shutdown waits.
- Enforce small handshake-frame limits and the documented envelope-frame cap
  before allocation. A maximum length alone is insufficient: a peer can send a
  maximum prefix and stall, so body reads also require deadlines.
- Bound concurrent handshakes/sessions, inbound queue capacity, and diagnostic
  buffers. These are count bounds; because one envelope may be up to 16 MiB,
  operators should keep configured session and queue counts proportional to
  their memory budget.
- Serialize writes per session so records cannot interleave, and abort the
  session on a partial record.

## Certificate time and generation policy

`CertChain::verify()` checks signatures, delegation structure, attenuation,
and its context-free generation rules. It does **not** enforce
`AgentMetadata::expires_at`; that field is currently an audit claim, not a
wall-clock admission control. Option A must not document or rely on automatic
expiry until a clock policy is implemented and tested.

Generation-scoped session identities require an explicit current generation
and `verify_at(current_generation)`. In context-free mode, a bounded generation
is rejected rather than ignored. A production transport that receives
generation state binds the accepted generation into session policy and must
close or reauthenticate affected live sessions when the generation advances.
The current transport takes generation policy at bind time; callers must close
and rebind it when that policy advances.

The current common bus envelope verifier remains context-free. It therefore
rejects generation-scoped envelope certs even when the SSH session handshake
was admitted with an explicit generation. End-to-end generation-aware envelope
admission is separate bus work; this transport does not weaken or bypass that
fail-closed behavior.

## Known limitations

Option A deliberately records these residuals:

- The inner AgentKey is not bound to the SSH username, accepted client key, or
  SSH session id. The listener cannot observe those values through `ssh -W`.
- A direct local client can bypass `sshd` and attempt inner authentication.
- A transparent, byte-for-byte live relay remains possible. The fresh
  transcript and signed records block capture/replay, session cutover, and
  cross-session injection, but not a relay that keeps both real endpoints live.
- SSH confidentiality ends at `sshd`; the loopback hop is plaintext.
- `expires_at` is not currently enforced.
- Generation revocation needs supplied generation state plus live-session
  teardown; static cert verification alone is insufficient.
- `request_direct(PeerEndpoint)` is shaped around the iroh endpoint model. An
  SSH backend must use a preconfigured fingerprint-to-SSH-target registry or
  reject that route rather than interpreting its socket address as SSH.
- The generic bus backend error retains an actionable rendering of structured
  SSH process/session errors but does not expose every SSH variant for typed
  matching through the bus API.

## Test evidence

A non-vacuous test must exercise the actual SSH adapter and the common bus
boundary, not feed an envelope directly into `Inbox` and not substitute
`InMemoryTransport` for session authentication.

The implementation exercises:

- a two-Bus request/reply round trip over established SSH session code, with
  repeated requests and burst publishes reusing the sole permitted session,
  with the handler observing the spoke's verified `RequestContext`;
- a sibling-authenticated session carrying another agent's exact envelope is
  rejected, followed by acceptance of the same nonce and sequence on the
  signer's own session;
- wrong-root, wrong-target, reflected, stale-transcript, bad-proof,
  cross-session-record, repeated-counter, and responder mismatch rejection;
- tampered signature and CID rejection at the common boundary;
- strict pinned-host success plus unknown/changed-host refusal, with TOFU
  exercised only under explicit bootstrap configuration;
- unauthorized SSH client refusal and useful stderr/exit reporting;
- oversized and truncated frames fail within bounded time;
- bounded child/socket/task shutdown, close/send/receive races, cancelled
  partial-write poisoning, stale-route fallback, and request-waiter timeout
  cleanup.

The byte-stream session can be tested deterministically over an injected duplex
stream. The macOS CI gate generates temporary keys and pinned `known_hosts`,
launches a loopback `sshd`, uses the real `ssh -W`, and completes the same Bus
request/reply. Missing system OpenSSH tools fail that gate actionably rather
than silently skipping it.

## Alternatives and future strengthening

An in-process SSH server, or a trusted proxy protocol carrying authenticated
SSH session metadata, could bind the accepted SSH key/session to the mesh
handshake and remove the loopback attribution gap. That is a stronger design,
not a property Option A claims today.

Additional encryption inside the forwarded stream may extend confidentiality
past `sshd`, but it does not by itself bind the SSH identity to the AgentKey or
stop transparent live relay. Those are separate requirements.

## Implementation boundary

Raw stream halves remain crate-private. `OpenSshClient` returns an
unauthenticated carrier, and only consuming `UnauthenticatedMeshSession` into
`AuthenticatedMeshSession` unlocks record I/O. The `SshTransport` loopback
listener and outbound dial path create `Inbound` only from that established
typestate. Argument/framing tests supplement, but do not replace, the Bus and
real OpenSSH request/reply tests.
