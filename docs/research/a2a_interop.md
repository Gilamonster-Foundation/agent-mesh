# Agent Mesh × A2A — interoperability research

**Status:** research / gap analysis. No implementation commitment.
**Date:** 2026-08-18
**Baseline:** agent-mesh `main` `d3b2263` (v0.6.4) · A2A spec **v1.0.1** (2026-05-28) ·
`a2a-rs` `main` `9d70cfd` (`a2a-lf` 0.3.0 on crates.io)

---

## 1. Executive summary

**Agent Mesh does not substantially duplicate A2A.** The two systems barely
touch, and where they do it is at exactly two places: *capability
advertisement* and *streaming/session shape*. Everything Agent Mesh actually
implements — cert chains, envelope signatures, replay defence, expected-responder
binding, the attenuation algebra, the authority CID DAG — lives strictly below
the layer A2A specifies. A2A, in turn, specifies a whole application layer
(task lifecycle, artifacts, skills, agent cards, three protocol bindings) that
Agent Mesh has never built and, per its own charter, should not build.

The reason is stated in the spec itself. A2A §7 opens:

> "A2A treats agents as standard enterprise applications, relying on
> established web security practices. **Identity information is handled at the
> protocol layer, not within A2A semantics.**"
> — [specification.md §7](https://github.com/a2aproject/A2A/blob/main/docs/specification.md#7-authentication-and-authorization)

That is a deliberate, documented deferral, not an oversight. A2A's identity
story ends at "TLS proves you reached the domain named in the Agent Card, and
your bearer token proves something to that domain." There is no per-message
signature, no principal on the wire, no delegation chain, no artifact integrity,
and — remarkably — [no unique identifier for an agent in the Agent Card at
all](https://github.com/a2aproject/A2A/issues/1014) (open since v0.2).

So the operator's hypothesis survives falsification, but it needs one sharpening
and one warning.

**Sharpening.** The boundary is not "A2A does communication, Mesh does
security." A2A already defines authn/authz *policy hooks* (§7.4, §7.5, §13.1)
and even an in-task authorization state machine (§7.6). What A2A deliberately
leaves undefined is **evidence**: §7.6.4 says in as many words that the protocol
"does not define the scope, representation, validity, or revocation semantics
of the authorization decision," and that `TASK_STATE_AUTH_REQUIRED` "MUST NOT"
be treated as authorization for anything. A2A tells agents how to *ask* and how
to *react*; it defines nothing anyone can later *verify*. That is the seam.

**Warning.** This gap is not our private discovery. The `a2aproject/A2A` issue
tracker currently carries **~20 open proposals** for exactly this territory —
[#1829](https://github.com/a2aproject/A2A/issues/1829) (Ed25519 + RFC 9421
message signing, 143 comments), [#2028](https://github.com/a2aproject/A2A/issues/2028)
(actor-chain / on-behalf-of delegation),
[#1497](https://github.com/a2aproject/A2A/issues/1497) (identity & trust
framework), [#1140](https://github.com/a2aproject/A2A/issues/1140) (content
integrity for artifacts), [#2079](https://github.com/a2aproject/A2A/issues/2079)
(confidential delegation with attenuated authority — conceptually our design),
[#1937](https://github.com/a2aproject/A2A/issues/1937) (context-binding for
delegated authority). None has graduated. The `a2aproject` org today contains
exactly **one** experimental extension repo
([`experimental-ext-oid4vp-auth`](https://github.com/a2aproject/experimental-ext-oid4vp-auth))
and **one** experimental custom protocol binding
([`experimental-cpb-slimrpc`](https://github.com/a2aproject/experimental-cpb-slimrpc)).
Agent Mesh's differentiator is therefore **not** noticing the gap. It is being
the only candidate with a *working, tested, fail-closed* implementation of the
attenuation algebra and the authority DAG — and with an enforcement witness
(agent-bridle) on the other end of it.

**Recommendation: architecture E (hybrid), realised as C + D.** Publish a plain
A2A HTTPS surface any third party can use with zero knowledge of the mesh; carry
Mesh guarantees as three opt-in A2A **extensions**; and offer the mesh bus as an
optional **custom protocol binding** for peers that want transport-level
authentication, replay defence and expected-responder binding for free. Adopt
A2A's `Task`/`Message`/`Artifact`/`AgentCard` as the canonical application
vocabulary, and stop growing ad-hoc per-topic payload schemas.

---

## 2. Current A2A ecosystem and spec status

| Fact | Value | Source |
|---|---|---|
| Latest released spec | **1.0.1** (2026-05-28) | [releases](https://github.com/a2aproject/A2A/releases) |
| Previous majors | 1.0.0 (2026-03-12, breaking), 0.3.0 (2025-07-30), 0.2.x | ibid. |
| Governance | Linux Foundation; TSC with quorum/majority voting | [ext-and-binding-governance](https://github.com/a2aproject/A2A/blob/main/docs/topics/extension-and-binding-governance.md) |
| Normative artefact | **`specification/a2a.proto`** — not the markdown, not the JSON | [spec §1.4](https://github.com/a2aproject/A2A/blob/main/docs/specification.md#14-normative-content) |
| Version negotiation | `A2A-Version` service parameter, `Major.Minor` only; empty ⇒ `0.3` | spec §3.6 |
| Bindings | JSON-RPC 2.0 (§9), gRPC (§10), HTTP+JSON/REST (§11), custom (§12) | spec §5 |
| SDKs | Python, Go, JS, Java, .NET, **Rust** | [A2A README](https://github.com/a2aproject/A2A) |
| Extension namespace | `https://a2a-protocol.org/extensions/{name}/v1` (official only) | governance doc |
| Binding namespace | `https://a2a-protocol.org/bindings/{name}/v1` (official only) | governance doc |

Two structural facts matter for us:

1. **The proto is normative.** Any Mesh work that generates or validates A2A
   objects must regenerate from `specification/a2a.proto`, not from prose. The
   spec explicitly forbids hand-edited derived schemas.
2. **Breaking changes have already happened once** (1.0.0 removed the `kind`
   discriminator and relocated the extended-card field — spec Appendix A.2).
   The deprecation policy is "not removed earlier than the next major," which is
   workable but means pinning `A2A-Version` explicitly rather than relying on
   the empty-header `0.3` default.

### 2.1 The MCP boundary — verified, not assumed

The operator's framing (MCP = agent↔tools, A2A = agent↔agent) is the framing the
spec itself uses, near-verbatim (Appendix B). But the clean split does **not**
survive contact with the details:

- **A2A does tool-shaped things.** `AgentSkill` (proto:436) is a
  named, tagged, typed-in/out capability with its own `security_requirements` —
  structurally a tool declaration. An agent exposing one skill is
  indistinguishable in shape from an MCP server exposing one tool.
- **A2A does not do context/resources.** There is no MCP-`resources` analogue,
  no sampling, no roots. Content only moves as `Part`s inside `Message`s and
  `Artifact`s.
- **MCP does not do task lifecycle.** Nothing in MCP corresponds to
  `TaskState`, `contextId`, push notifications, or `TASK_STATE_AUTH_REQUIRED`.

The honest boundary is **statefulness and opacity**, not "tools vs agents": A2A
governs *long-running, stateful, opaque-execution* delegation between parties
that do not share memory; MCP governs *stateless-ish, transparent* capability
invocation by a party that owns the loop. For Agent Mesh this matters because
`amesh mcp` (`agent-mesh-cli/src/mcp.rs`) already exposes mesh operations as MCP
tools — that is the *right* place for it, and it should not migrate to A2A.

---

## 3. Agent Mesh as implemented today

Status key: **I** = implemented and tested · **P** = partially implemented ·
**S** = specified (ADR/issue) not implemented · **A** = aspirational/mentioned.

| Concept | Status | Where |
|---|---|---|
| Operator root identity (ed25519 `UserKey`) | **I** | `agent-mesh-protocol/src/user_key.rs` |
| External anchor (GitHub SSH cross-signature) | **I** | `agent-mesh-protocol/src/github_binding.rs`; verified against `github.com/<user>.keys` |
| Per-process agent identity (`AgentKey`) | **I** | `agent_key.rs:59`, `issue()` at `:71` |
| Delegated agent identity (agent issues agent) | **I** | `agent_key.rs:97` `delegate()`; `Issuer::Agent` at `:296` |
| External/platform-key delegation (no seed) | **I** | `agent_key.rs:146` `delegate_external`; `signer.rs` `MeshSigner` seam |
| Proof-of-possession challenge | **I** | `agent_key.rs:29` `PossessionChallenge` |
| Cert-chain verification incl. per-link attenuation | **I** | `agent_key.rs:335` `verify()`, `:345` `verify_at()` |
| Fingerprint = BLAKE3(pubkey); doubles as iroh endpoint id | **I** | `fingerprint.rs`; `agent-mesh-transport/src/identity.rs` |
| Addressing: `Direct` / `Topic` / `Anycast{capability}` | **I** | `envelope.rs:22-31` |
| Peer discovery (mDNS `_agent-mesh._udp.local.`) | **I** | `agent-mesh-discovery/`; `peer.rs:14` `PeerInfo` |
| Capability advertisement (TXT: role, host, capabilities) | **I** | `peer.rs:26-30` — *claims, unverified until handshake* |
| Signed envelope (sig over `tag‖recipient‖nonce‖seq‖payload_cid`) | **I** | `envelope.rs:45-53`, `:110` `verify()` |
| Payload content-binding (BLAKE3 `payload_cid`, under signature) | **I** | `envelope.rs:97`, checked at `:117` |
| Transport auth: QUIC + ALPN `agent-mesh/v1` + cert exchange | **I** | `agent-mesh-transport/src/handshake.rs:69` |
| Auto-team rule (same `user_pubkey` else refuse, fail-closed) | **I** | `handshake.rs` `ensure_trustable` |
| Cert bound to the QUIC session identity | **I** (bus layer) | `agent-mesh-bus/src/bus.rs:614` `authenticated_iroh_peer` |
| Intended-peer check on dial | **I** | `bus.rs:635` `ensure_intended_iroh_peer` |
| Authenticated delivery provenance, fail-closed on `Unbound` | **I** | `agent-mesh-bus/src/transport.rs:73` `DeliveryProvenance` (#81) |
| Verified-caller `RequestContext` for handlers | **I** | `agent-mesh-bus/src/inbox.rs:94`; `bus.rs:354` (#75) |
| Expected-responder binding on replies | **I** | `agent-mesh-bus/src/reply.rs:41` `ReplyDelivery::PeerMismatch` (#82) |
| Request/response correlation (128-bit `CorrelationId`) | **I** | `reply.rs:22` |
| Replay defence (nonce cache + per-peer sequence tracker) | **I** | `agent-mesh-bus/src/replay.rs` |
| Attenuation lattice `(L, ⊑, ⊓, ⊤)` — property-tested | **I** | `caveats.rs:148`; `leq` `:183`, `meet` `:195` |
| Caveats carried in the *signed* cert payload | **I** | `agent_key.rs:266` `AgentMetadata.caveats` |
| Content-addressed `Authority` / `Grant` (typed CIDs) | **I** | `authority.rs:135`, `:202` |
| Attenuation algebra over the DAG (`check_derivation`) | **I** | `authority.rs:406` |
| Chain verification to an operator-pinned trusted root | **I** | `authority.rs:530` `verify_chain` |
| L3 BOUND admission vs an OS fence witness (`admit`) | **I** | `authority.rs:811`; consumed by agent-bridle |
| SSH-carried authenticated sessions | **I** | `agent-mesh-transport-ssh/` (#77) |
| Double Ratchet 1:1 message-layer FS/PCS | **I** | `agent-mesh-ratchet/` (vodozemac) |
| Python bindings | **I** | `agent-mesh-py/`, PyPI `newt-agent-mesh` |
| MCP surface (`mesh_whoami/peers/request/publish`) | **I** | `agent-mesh-cli/src/mcp.rs` |
| **Signatures over `Authority`/`Grant`** | **S** | `authority.rs` header table: "Assertion \| signature (**deferred**)"; `DenyAllElevations` at `:350` fail-closes every elevation |
| **Grant/Authority CIDs carried on the wire** | **not present** | `SignedEnvelope` has no authority field (`envelope.rs:45`) |
| Session streams (long-lived bidi conversations) | **S** | `docs/decisions/session_streams.md`; issue #84 |
| Durable store / offline delivery / merkle logs | **S** | `docs/decisions/agent_mesh_store.md`; issues #42, #46 |
| Conversation Graph (causal transcript DAG) | **S** | issue #67 |
| Encrypt-to-recipient envelopes | **S** | issue #43 (today: sign-only) |
| SAS pairing / chain-to-principal pinning | **S** | issue #66; transcript-hash spike #30 |
| SPIFFE/SPIRE integration | **A** | issue #71 |
| Receipts / audit evidence records | **A** | no type exists; implied by agent-bridle's chain-store |
| Signed artifacts | **A** | `payload_cid` binds a payload to *one envelope*; there is no standalone artifact object |

### 3.1 The two honest weak points

1. **The authority DAG is not bound to messages.** `Authority`/`Grant` and
   `SignedEnvelope` are separate universes today. A receiver can verify *who*
   signed an envelope (cert chain) and *what caveats that agent was minted with*
   (`AgentMetadata.caveats`), but the envelope carries no `GrantId`, so it cannot
   verify *under which grant this specific request was made*. The chain exists;
   it just is not cited on the wire. **This is the single highest-value gap in
   the whole provenance story**, and it is independent of A2A.
2. **Elevation is unusable and assertions are unsigned.** `check_derivation`
   fail-closes every `Derivation::Elevation` because no `AttestationVerifier`
   ships (`DenyAllElevations`, `authority.rs:350`). Attenuation-only chains work
   fully; anything requiring an operator to widen authority does not.

### 3.2 The residual the field guide already flags

`do_handshake` (`agent-mesh-transport/src/handshake.rs:69`) verifies the peer's
cert chain and the same-user rule, but does **not** bind the cert to
`conn.remote_id()`. That binding is done one layer up, in the bus
(`bus.rs:614`). Consumers that use the raw transport rather than the bus
therefore get a filter, not a proof — exactly as `docs/field_guide.md` §2 warns.

---

## 4. A2A architecture and normative semantics

Classification: **N** = normative protocol requirement · **O** = optional /
capability-gated · **X** = extension territory · **U** = deliberately
unspecified policy · **S** = SDK implementation detail.

| Feature | Class | Notes / source |
|---|---|---|
| Agent Card exists and is published | **N** | §8.1 "MUST make an Agent Card available" |
| Well-known URI `/.well-known/agent-card.json` | **O** | §8.2 — one of three mechanisms; registries and direct config equally valid |
| `AgentCard.supportedInterfaces[]` (url + binding + version) | **N** | proto:362, `REQUIRED`; first entry preferred |
| **Agent Card signing (JWS over RFC 8785 JCS)** | **O** | §8.4 "**MAY** be digitally signed"; clients "**SHOULD** verify at least one" |
| Key discovery for card verification | **U/broken** | §8.4.3 step 2 permits retrieval "using the `kid` and `jku`" — signer-controlled trust root. Open spec issue [#2096](https://github.com/a2aproject/A2A/issues/2096) |
| `AgentSkill` (id/name/desc/tags/modes/security) | **N** | proto:436 |
| `AgentCapabilities.{streaming,pushNotifications,extendedAgentCard}` | **O** | proto:412; misuse ⇒ `UnsupportedOperationError` (§3.3.4) |
| `Message` (messageId, contextId, taskId, role, parts, metadata, extensions, referenceTaskIds) | **N** | proto:260 |
| `Part` (oneof text/raw/url/data + media_type, filename, metadata) | **N** | proto:224 |
| `Task` (id, contextId, status, artifacts, history, metadata) | **N** | proto:167 |
| `TaskState` — 8 states, terminal/interrupted distinction | **N** | proto:187 |
| `Artifact` (artifactId, name, parts, metadata, extensions) | **N** | proto:280 |
| **Artifact integrity (hash/signature)** | **absent** | no hash, no signature field; open proposal [#1140](https://github.com/a2aproject/A2A/issues/1140) |
| Streaming (`SendStreamingMessage`, `SubscribeToTask`) | **O** | §3.5.2: order MUST be preserved; multiple concurrent streams per task MUST be broadcast identically |
| Push notifications (webhooks) | **O** | §3.5.3, §4.3, §13.2 |
| `Cancel Task` | **N** | §3.1.5; idempotent (§3.3.1) |
| Blocking vs non-blocking (`return_immediately`) | **N** | §3.2.2 — **blocking is the default** |
| Correlation ids: `messageId` client-gen, `taskId` **server-gen** | **N** | §3.4.2 — "Client-provided `taskId` for creating new tasks is **NOT** supported" |
| `contextId` grouping | **N** | §3.4.1; server-generated values opaque to clients |
| Idempotency | **U** | §3.3.1 — Send Message "**MAY** be idempotent"; agents "may" use messageId |
| **Replay protection** | **absent** | no nonce, no sequence, no timestamp binding at protocol level |
| Error model (9 A2A errors + categories + `google.rpc` details) | **N** | §3.3.2 |
| Transport security (TLS) | **N** | §7.1 "**MUST** use encrypted communication" |
| Client auth (`securitySchemes`: apiKey/http/oauth2/oidc/mTLS) | **N** shape, **U** choice | §4.5, §7.3; credential acquisition explicitly out-of-band |
| Server authorization | **U** | §7.5 "Authorization logic is implementation-specific"; §13.1 "Authorization models are agent-defined, not prescribed by the protocol" |
| **In-task authorization** (`TASK_STATE_AUTH_REQUIRED`) | **N** state, **U** meaning | §7.6; §7.6.4: protocol "does not define the scope, representation, validity, or revocation semantics"; state "MUST NOT" be treated as authorization |
| Credential binding to the originating agent | **guidance only** | §7.6.3 "Credentials **SHOULD** be bound to the agent which originated the request" — no mechanism defined |
| Extensions: declaration, activation, `required:true` | **N** | §4.6; `A2A-Extensions` header; agent MUST error if a required ext is not activated |
| Extension capabilities | **X** | data-only, **profile**, **new RPC methods**, **state-machine** extensions all permitted (`topics/extensions.md`) |
| Extension limits | **N** | cannot add fields to core structs or enum values — must use `metadata` maps |
| Custom protocol bindings | **N** process | §12; must preserve functional equivalence (§5.1) and document security (§12.6) |
| `AgentInterface.tenant` | **U** | proto:336 — "opaque"; "the protocol does not define its format or semantics" |
| **Unique agent identifier in the card** | **absent** | open issue [#1014](https://github.com/a2aproject/A2A/issues/1014) |
| Audit trails | **guidance** | §13.4 "Agents **SHOULD** provide audit trails" — no format |

---

## 5. Overlap / gap matrix

| Concern | Agent Mesh | A2A | Overlap? | Semantic mismatch? | Recommended owner |
|---|---|---|---|---|---|
| **Agent identity (cryptographic)** | ed25519 `AgentKey`, BLAKE3 fp, cert chain to `UserKey` (**I**) | none — card has no agent id (#1014); TLS proves *domain* | no | Mesh: identity is a key. A2A: identity is a URL. | **Mesh** |
| **Operator/root identity** | `UserKey` cross-signed by GitHub SSH key (**I**) | none; `AgentProvider` is self-asserted prose | no | — | **Mesh** |
| **Authenticated identity of a request** | envelope sig + transport-bound `RequestContext` (**I**) | bearer/OAuth/mTLS to the server only; opaque to third parties | no | non-transferable (A2A) vs transferable (Mesh) | **Mesh** |
| **Peer discovery** | mDNS LAN, TXT claims (**I**) | well-known URI, registries, direct config (**N/O**) | **yes** | LAN-local + identity-keyed vs web-scale + URL-keyed. Complementary, not competing. | **both** — mDNS finds the card; the card describes the agent |
| **Addressing** | fingerprint (floating identity doctrine) | absolute HTTPS URL / gRPC host:port | **yes** | **Sharp.** Mesh law: "the routing key is the identity, never a location" (`docs/decisions/floating_identity.md`). A2A's routing key *is* a location. | **Mesh** for reachability; A2A URL as one candidate |
| **Capability advertisement** | `Vec<String>` capability tags in mDNS TXT + cert (**I**) | `AgentSkill` — id, name, description, tags, in/out modes, per-skill security (**N**) | **yes — real duplication** | A2A's is strictly richer and standard | **A2A** |
| **Capability *delegation*** | `Caveats` lattice, attenuation-only, enforced at mint *and* verify (**I**) | none | no | — | **Mesh** |
| **Authorization** | attenuation algebra + `admit()` L3 BOUND vs OS fence (**I**) | explicitly agent-defined policy (§7.5, §13.1) | no | A2A leaves the hole Mesh fills | **Mesh** |
| **Authentication (scheme plumbing)** | auto-team rule; no OAuth/OIDC | 5 standard schemes, well-specified | little | Mesh has no enterprise IdP story | **A2A** |
| **Message delivery** | signed envelope over QUIC/iroh or SSH (**I**) | JSON-RPC/gRPC/REST over TLS (**N**) | **yes** | Mesh envelope ≈ transport frame; A2A `Message` ≈ application turn. *Different layers, easily confused.* | **A2A** for the object, **Mesh** for the frame |
| **Request/response correlation** | 128-bit `CorrelationId` (**I**) | `messageId` + server-gen `taskId` + `contextId` (**N**) | **yes** | Mesh's is transport-scoped; A2A's is application-scoped and durable | **A2A** at app layer; keep Mesh's for the bus |
| **Expected-responder binding** | `ReplyDelivery::PeerMismatch` — reply must be signed by the dialed peer (**I**) | none. TLS proves the domain; nothing binds a response to an agent | no | **This is the strongest single Mesh property A2A cannot express.** | **Mesh** |
| **Provenance (who caused this)** | cert chain + `payload_cid` + authority DAG (**I/P**) | none on the wire (#2028 open) | no | — | **Mesh** |
| **Attribution** | `sender_agent_fp` / `sender_user_fp` (**I**) | `Role{USER,AGENT}` — a direction flag, not a principal | no | A2A's `role` is *not* attribution | **Mesh** |
| **Signatures** | per-envelope ed25519 (**I**) | Agent Card only, optional, verifier-trust-root broken (#2096) | trivial | Mesh signs traffic; A2A signs a manifest | **Mesh** |
| **Delegation chains** | `Issuer::Agent` recursive certs + `Grant`/`Derivation` DAG (**I**) | none (#2028 open) | no | — | **Mesh** |
| **Trust anchors** | operator-pinned `trusted_root: GrantId`; GitHub SSH anchor (**I**) | web PKI + optional trusted key store | little | Mesh: explicit pin. A2A: CA + signer-nominated `jku` | **Mesh** |
| **Task lifecycle** | **none** | 8-state machine, terminal/interrupted, cancel, multi-turn (**N**) | **no overlap — Mesh has nothing** | — | **A2A** |
| **Conversation/session identity** | `Topic` + proposed session streams (**S**) | `contextId` + `taskId` + `history` (**N**) | **yes (against our ADR)** | our #58 ADR and #67 Conversation Graph would reinvent this | **A2A** for identity; **Mesh** for the causal DAG |
| **Replay protection** | nonce cache + per-peer sequence (**I**) | none | no | — | **Mesh** |
| **Auditing** | none as a type | "SHOULD provide audit trails", no format | no | both weak | **Mesh** (evidence records) |
| **Receipts / evidence** | none (agent-bridle chain-store adjacent) | none | no | — | **Mesh** |
| **Failure semantics** | `MeshError` / transport errors | 9 named errors + 5 categories + binding maps (**N**) | little | A2A's is far more complete at app layer | **A2A** |
| **Transport abstraction** | `Transport` trait; QUIC + SSH impls (**I**) | 3 bindings + custom-binding process (§12) | **yes** | both have one; A2A's is standardised | **A2A** shape, **Mesh** implementations |
| **OCAP / capability security** | full lattice + admission + bridle witness (**I**) | nothing (#1716 open) | no | — | **Mesh** |
| **Artifacts** | none | `Artifact` + `Part` + streaming chunks (**N**) | no | — | **A2A** |
| **Artifact integrity** | `payload_cid` binds bytes to an envelope | none (#1140 open) | no | Mesh's is envelope-scoped, not artifact-scoped | **Mesh**, but needs a real artifact CID |
| **Confidentiality** | ratchet (**I**), encrypt-to-recipient (**S** #43) | TLS only, hop-by-hop | no | Mesh can do E2E across relays; A2A cannot | **Mesh** |
| **Streaming conventions** | raw envelopes over a bidi stream | `StreamResponse` union, ordering MUST, multi-stream broadcast (**N**) | **yes** | A2A's is specified; ours is not | **A2A** |
| **Bridle / Newt integration** | `Caveats` *is* bridle's leash; `admit()` is the L3 seam (**I**) | n/a | no | — | **Mesh** |

### 5.1 Falsification attempt — where A2A already does what we built

Three honest hits, and only three:

1. **Capability advertisement.** Our `capabilities: Vec<String>` (mDNS TXT +
   `AgentMetadata`) is a strictly poorer `AgentSkill`. We should stop growing a
   capability vocabulary.
2. **Session/conversation identity.** ADR `session_streams.md` (#58/#84) and
   issue #67's `ConversationRecord.conversation_id` would reinvent
   `contextId`/`taskId` and the `RecordKind` enum would reinvent
   `Message`/`Part`/`Artifact`/`TaskState`.
3. **Streaming semantics.** A2A §3.5.2 already specifies ordering guarantees and
   multi-subscriber broadcast per task — precisely the questions our session ADR
   defers.

And three near-misses that turn out **not** to be duplication:

- *Push notifications vs our store ADR.* Superficially both are "delivery to an
  agent that was not connected." A2A's webhooks require the client to be
  HTTP-reachable and carry no durability guarantee; the store ADR is about
  offline-tolerant, tamper-evident replicated logs. Different properties.
- *`TASK_STATE_AUTH_REQUIRED` vs our grants.* A2A's state is a *signal*; §7.6.4
  explicitly refuses to define what the resulting authorization means. Our
  `Grant` is the missing definition, not a competitor.
- *mTLS vs our handshake.* `MutualTlsSecurityScheme` (proto:562) authenticates a
  *client certificate to a server*. It does not bind the *response* to an agent
  identity, does not survive a proxy, and has no attenuation semantics.

---

## 6. Security / trust / provenance gap analysis

What A2A does **not** guarantee, that Agent Mesh does or could:

| Property | A2A status | Mesh status |
|---|---|---|
| Per-message authenticity, verifiable by a third party | none | **I** (`SignedEnvelope`) |
| Message integrity independent of transport | none (TLS is hop-scoped) | **I** (sig over `payload_cid`) |
| Replay rejection | none | **I** (`replay.rs`) |
| The responder is the agent I intended | none | **I** (`reply.rs` `PeerMismatch`, `bus.rs` `ensure_intended_iroh_peer`) |
| Caller identity available to the handler as *verified*, not claimed | out-of-band credential only | **I** (`RequestContext`, fail-closed on `DeliveryProvenance::Unbound`) |
| Authority attenuation cannot be widened by a compromised hop | none | **I** (`Caveats::leq` enforced at mint **and** verify) |
| A chain terminates at an *operator-pinned* root, not a structurally valid one | none | **I** (`verify_chain` rejects `UntrustedRoot`) |
| Authorization decisions have a stable content identity | none | **I** (`AuthorityId`/`GrantId`) |
| An OS-level enforcement witness can be checked against the granted authority | none | **I** (`admit()` L3 BOUND → agent-bridle) |
| Artifact bytes carry their own integrity proof | none (#1140) | **P** — `payload_cid` is envelope-scoped |
| End-to-end confidentiality across relays | none | **P** (`ratchet` **I**, envelope encryption **S** #43) |
| Non-repudiable evidence of *what was authorized* | none (§7.6.4 disclaims it) | **P** — DAG exists, signatures deferred, not wire-bound |

And the reverse — what A2A gives that Mesh cannot:

- **Reach.** Any A2A agent on the public internet, in any of six SDK languages,
  behind any enterprise IdP. Mesh reaches same-`UserKey` peers on a LAN or an
  explicitly configured link.
- **A complete, versioned application vocabulary** with a deprecation policy and
  a TSC.
- **Enterprise auth integration** (OAuth2 flows incl. device code, OIDC) we would
  otherwise have to build for #71/SPIFFE.
- **A specified error model** with binding-specific mappings.

---

## 7. Identity analysis

Answering §5 of the brief directly.

**What binds an Agent Card to the entity serving it?**
Nothing normative and cryptographic. Three weak bindings exist, in decreasing
order of strength:
1. TLS + the well-known URI: fetching `https://d/.well-known/agent-card.json`
   over a validated TLS session binds the card to **control of domain `d`** —
   not to any agent.
2. Optional JWS (§8.4): binds the card to *a key*. But §8.4.3 step 2 lets the
   verifier resolve that key from the signer-supplied `jku` in the protected
   header, so an attacker can nominate their own trust root
   ([#2096](https://github.com/a2aproject/A2A/issues/2096), open;
   `a2a-go` already fixed it SDK-side with a `KeyResolver` constraint,
   `a2a-rs` has **no** verification at all).
3. Registry/catalog trust: entirely out of scope of the spec.

**What establishes that the responder is the agent I intended to contact?**
Nothing beyond the TLS certificate for the host in `AgentInterface.url`. There
is no response signature, no agent key, and `tenant` is explicitly "opaque…the
protocol does not define its format or semantics" (proto:336). If ten agents sit
behind one endpoint, A2A cannot tell you which one answered.
Contrast `agent-mesh-bus/src/reply.rs:41`: a reply signed by anyone other than
the dialed agent fingerprint is returned as `PeerMismatch` and never delivered
to the waiter.

**What does transport authentication prove?**
Client→server: that the caller holds a credential the server accepts. That
proof is **non-transferable** — agent C cannot show anyone that agent B
authenticated to it. Server→client: control of a domain name. Neither is agent
identity, and neither survives a hop.

**Are agent identity and server/service identity distinct?**
No. In A2A today they are the same thing, and the agent-level identity is the
weaker of the two (there is no agent id field at all — [#1014](https://github.com/a2aproject/A2A/issues/1014)).
In Mesh they are rigorously distinct: `user_fp` (operator) ≠ `agent_fp`
(process) ≠ socket address (a mere candidate).

**Can identity survive changing transports or endpoints?**
A2A: no — identity *is* the endpoint. Change the URL and you are a different
agent as far as any client is concerned.
Mesh: yes, by doctrine. `docs/decisions/floating_identity.md` law 1: "the
routing key is the identity (fingerprint), never a location"; law 4:
"conversations outlive locations." This is the sharpest *philosophical*
mismatch between the two systems, and it is the one that must be handled
carefully in any binding design.

**How are delegated agents represented?** They are not. There is no principal in
any A2A payload ([#2028](https://github.com/a2aproject/A2A/issues/2028)).

**Can an agent prove which upstream agent authorized a task?** No.
`referenceTaskIds` (proto:260 field 8) is an unauthenticated hint; `contextId`
is a server-chosen opaque string.

**Can a response be cryptographically bound to the original task/requester?** No.

**Does A2A define durable identity?** No — §7 states plainly that identity is
handled "at the protocol layer, not within A2A semantics." This is deliberate
and, from A2A's goals (enterprise interop over existing web security), defensible.

---

## 8. Delegation and provenance traces

### 8.1 The chain

```text
Operator ──▶ Newt ──▶ Agent A ──A2A──▶ Agent B ──MCP──▶ Tool ──▶ Artifact
```

**What A2A alone proves.** Per hop, and only to the two parties of that hop:

| Link | A2A evidence | Transferable? |
|---|---|---|
| Operator → Newt | nothing (outside A2A) | — |
| Newt → A | nothing (outside A2A) | — |
| A → B | B knows *a caller* presented an accepted credential; A knows it reached domain(B) over TLS | **no** |
| B → Tool | nothing in A2A (MCP hop) | — |
| Tool → Artifact | `artifactId`, unique within the task; no hash, no signature | **no** |

Net: A2A can prove **nothing at all** about the chain as a whole. B cannot
demonstrate to anyone that the operator authorized this work; a later auditor
must join logs across four trust domains and take each one's word for it. The
`confused deputy` is fully available: A's credential to B is all B sees, so B
cannot distinguish "A acting for the operator within scope" from "A acting for
itself, or for someone else, out of scope."

Deepen it:

```text
Operator ──▶ Agent A ──▶ Agent B ──▶ Agent C ──▶ Tool
```

A2A adds nothing per extra hop. C sees B's credential; the operator has
vanished. The spec's own in-task-authorization security note (§7.6.3) concedes
the shape of the problem — "credentials propagating through a chain of A2A
requests" are "exposed to each agent participating in the chain" — and offers
only a `SHOULD`: bind the credential to the originating agent. No mechanism is
defined for doing so.

### 8.2 What Agent Mesh can add — today, with no A2A change

Using only shipped code:

| Claim | Mesh mechanism | File |
|---|---|---|
| "Agent A is a process minted by operator U" | `CertChain::verify` chains `AgentKey` → `UserKey` | `agent_key.rs:335` |
| "Operator U is `github.com/hartsock`" | `GitHubBinding::verify` against published SSH keys | `github_binding.rs` |
| "A held at most caveats *c*" | `AgentMetadata.caveats` inside the signed cert | `agent_key.rs:266` |
| "B is a delegate of A, and B's authority ⊑ A's" | `Issuer::Agent` recursive cert + per-link `leq` re-check | `agent_key.rs:296,335` |
| "this exact request body was sent by A" | envelope sig over `payload_cid` | `envelope.rs:110` |
| "this reply came from the B I dialed" | `ReplyWaiter` peer binding | `reply.rs:41` |
| "this request is not a replay" | nonce cache + sequence tracker | `replay.rs` |
| "this derivation is legal and roots at the pinned root" | `verify_chain` | `authority.rs:530` |
| "the OS fence B ran under was within the granted authority" | `admit()` → agent-bridle | `authority.rs:811` |

### 8.3 What is still missing for the full chain

The target chain —

```text
operator → requesting agent → delegated agent → sub-agent → tool invocation → artifact
```

— is achievable **without modifying A2A**, but needs three Mesh-side pieces that
do not exist yet:

1. **Cite the grant on the wire.** A `GrantId` (and the resolvable
   `Authority`) must travel with each request so the receiver can bind *this
   request* to *that authority*, rather than only to the caller's minted
   caveats. (§3.1 gap.)
2. **Sign assertions.** `Derivation::Elevation` needs a real
   `AttestationVerifier`; without it every operator-widening step fail-closes and
   the chain can only ever narrow. (`authority.rs:350`.)
3. **Artifact-scoped content identity.** `payload_cid` binds bytes to one
   envelope. An artifact that outlives the exchange needs its own CID and a
   signature over it — which is also exactly what A2A
   [#1140](https://github.com/a2aproject/A2A/issues/1140) is asking for.

The MCP hop is not a hole: `amesh mcp` already surfaces mesh identity to the
tool layer, and agent-bridle already witnesses what the OS permitted. The link
that needs designing is *recording* the tool invocation into the same evidence
DAG — issue #67's `RecordKind::{ToolInvocation, ToolResult}`.

---

## 9. Integration architectures evaluated

Scoring: ●●● good · ●● acceptable · ● poor.

### A. A2A transport/adaptor inside Agent Mesh
*Mesh stays the internal abstraction; an A2A "backend" lets it dial out.*

| Criterion | |
|---|---|
| Interoperability | ●● outbound only — third parties still cannot call us |
| Conceptual cleanliness | ● Mesh keeps owning an application vocabulary it never designed |
| Bespoke protocol retained | ● all of it, plus a translation layer |
| Backward compatibility | ●●● nothing changes |
| Security / provenance | ●● Mesh guarantees stop at the adaptor boundary |
| Implementation complexity | ●● small |
| Unmodified 3rd-party A2A peers | ●● as *servers* only |
| Two Mesh-aware peers get more | ●●● they just use the mesh |
| Upgrade story | ● two vocabularies to version forever |

**Verdict: insufficient alone.** Useful as a *component* of E (the outbound
client), fatal as the whole answer because it never makes us callable.

### B. Mesh security envelope *around* A2A
*A2A objects are canonical; Mesh wraps them with identity/provenance.*

| Criterion | |
|---|---|
| Interoperability | ● if the wrapper is mandatory, no vanilla peer can talk to us |
| Conceptual cleanliness | ●●● very clean layering |
| Bespoke protocol retained | ●●● only the envelope |
| Backward compatibility | ●● |
| Security / provenance | ●●● strongest — signature covers the whole A2A object |
| Implementation complexity | ●●● small |
| Unmodified 3rd-party peers | ● **no** |
| Two Mesh-aware peers | ●●● |
| Upgrade story | ●● |

**Verdict: right idea, wrong placement.** Wrapping is correct *inside* the mesh
and *as an evidence record*; making it the wire format destroys the property we
most want (§9 of the brief: "a normal third-party A2A implementation should be
able to communicate with us without knowing Agent Mesh exists").

### C. Mesh as A2A extension(s)
*Spec-compliant `AgentExtension` entries; evidence rides in `metadata` maps.*

The mechanism is real and adequate (`docs/topics/extensions.md`): extensions may
be **data-only**, **profile** (narrowing allowed values, adding task substates),
**method** (new RPC methods), or **state-machine**. They are declared in
`AgentCard.capabilities.extensions[]`, activated per-request via the
`A2A-Extensions` header, **inactive by default**, and may be `required: true` to
fail-close. The one hard limit: extensions "should place custom attributes in
the `metadata` map" and may not add fields to core structs or values to enums.

`Message` (proto:260), `Artifact` (proto:280), `Task`, `TaskStatus`,
`TaskStatusUpdateEvent`, `TaskArtifactUpdateEvent` and `Part` all carry a
`metadata` Struct, and `Message`/`Artifact` additionally carry `extensions[]`
URI lists. That is enough room for a signature, a cert chain, a `GrantId`, and a
receipt.

A spec-compliant sketch (contrast with the brief's illustrative syntax, which is
**not** valid — extensions are objects under `capabilities.extensions`, not a
top-level `extensions` map):

```jsonc
{
  "name": "Newt Coder",
  "description": "Autonomous coding agent",
  "version": "0.1.0",
  "supportedInterfaces": [
    { "url": "https://newt.example/a2a/v1",
      "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }
  ],
  "capabilities": {
    "streaming": true,
    "extensions": [
      { "uri": "https://gilamonster.foundation/a2a/ext/mesh-identity/v1",
        "description": "ed25519 agent identity, cert chain to an operator root",
        "required": false,
        "params": { "userFingerprint": "…", "agentFingerprint": "…",
                    "anchor": "github:hartsock" } },
      { "uri": "https://gilamonster.foundation/a2a/ext/mesh-authority/v1",
        "description": "Content-addressed authority provenance (Authority/Grant DAG)",
        "required": false },
      { "uri": "https://gilamonster.foundation/a2a/ext/mesh-receipt/v1",
        "description": "Signed evidence records for completed exchanges",
        "required": false }
    ]
  },
  "defaultInputModes": ["text/plain", "application/json"],
  "defaultOutputModes": ["text/plain", "application/json"],
  "skills": [ /* … */ ]
}
```

with per-message evidence:

```jsonc
{
  "role": "ROLE_USER",
  "messageId": "…",
  "parts": [{ "text": "rebase issue-333 onto main" }],
  "extensions": ["https://gilamonster.foundation/a2a/ext/mesh-identity/v1"],
  "metadata": {
    "https://gilamonster.foundation/a2a/ext/mesh-identity/v1": {
      "certChain": "…base64 dag-cbor…",
      "sig": "…base64 ed25519 over JCS(message minus this metadata key)…"
    },
    "https://gilamonster.foundation/a2a/ext/mesh-authority/v1": {
      "grantId": "bafy…", "authorityId": "bafy…", "chain": ["bafy…", "bafy…"]
    }
  }
}
```

| Criterion | |
|---|---|
| Interoperability | ●●● best possible — inactive by default |
| Conceptual cleanliness | ●● evidence-in-metadata is a bit of a squeeze |
| Bespoke protocol retained | ●●● almost none |
| Backward compatibility | ●●● |
| Security / provenance | ●● **cannot** bind to the transport session, cannot do expected-responder binding, needs its own canonicalisation rule |
| Implementation complexity | ●● JCS canonicalisation over a `metadata`-excluded subtree is fiddly and easy to get wrong |
| Unmodified 3rd-party peers | ●●● |
| Two Mesh-aware peers | ●● stronger, but weaker than the mesh bus |
| Upgrade story | ●●● URI-versioned, breaking change ⇒ new URI |

**Verdict: necessary, not sufficient.** This is how we stay reachable *and*
carry evidence to peers that care. But it cannot deliver expected-responder
binding or replay defence, because those are transport properties.

### D. Agent Mesh below A2A (A2A over the mesh bus)
*A custom protocol binding, per spec §12 and the `cpb-*` governance track.*

Precedent exists and is fresh: `experimental-cpb-slimrpc` implements A2A over
AGNTCY SLIM, and `a2a-rs` ships it as a first-class `TransportFactory`
(`a2a-slimrpc/src/client.rs:400`). Our equivalent would register a
`MeshTransportFactory` with `protocol() == "AGENT-MESH"`, carrying
`SendMessageRequest`/`StreamResponse` as `SignedEnvelope` payloads over the
existing bus.

Everything Mesh already enforces then applies to A2A traffic **for free**:
cert-chain handshake, auto-team rule, `DeliveryProvenance`, verified-caller
`RequestContext`, nonce/sequence replay defence, expected-responder binding.

| Criterion | |
|---|---|
| Interoperability | ● vanilla peers cannot speak it |
| Conceptual cleanliness | ●●● textbook layering; A2A explicitly anticipates this (§12) |
| Bespoke protocol retained | ●●● we keep only the transport, which is our actual product |
| Backward compatibility | ●●● additive |
| Security / provenance | ●●● strongest available |
| Implementation complexity | ●● must satisfy §5.1 functional equivalence for *all* operations, incl. push notifications ("regardless of binding, WebHook calls use plain HTTP") |
| Unmodified 3rd-party peers | ● no |
| Two Mesh-aware peers | ●●● maximal |
| Upgrade story | ●● tied to A2A binding governance |

**Verdict: the strong path, and the one with the clearest upstream story** —
but useless on its own for third-party reach.

### E. Hybrid — thin A2A surface + negotiated Mesh strength
**= standard HTTPS/JSON-RPC binding (reach) + C (evidence) + D (strength).**

| Criterion | |
|---|---|
| Interoperability | ●●● |
| Conceptual cleanliness | ●● three surfaces to keep coherent |
| Bespoke protocol retained | ●●● only the transport and the evidence types |
| Backward compatibility | ●●● |
| Security / provenance | ●●● graduated: none → extension-level → transport-level |
| Implementation complexity | ● highest |
| Unmodified 3rd-party peers | ●●● |
| Two Mesh-aware peers | ●●● |
| Upgrade story | ●●● each layer versions independently |

### Recommendation: **E**

Sequenced so that the expensive parts are deferred and each stage is
independently valuable:

```text
  ┌───────────────────────────────────────────────────────────┐
  │  application vocabulary: A2A Task / Message / Artifact    │  ← adopt wholesale
  ├──────────────────────────┬────────────────────────────────┤
  │  evidence: 3 A2A         │  strength: cpb-agent-mesh      │  ← C (stage 2)   / D (stage 3)
  │  extensions in metadata  │  binding over the mesh bus     │
  ├──────────────────────────┴────────────────────────────────┤
  │  reach: standard JSON-RPC/HTTPS A2A binding (a2a-rs)      │  ← stage 1
  ├───────────────────────────────────────────────────────────┤
  │  agent-mesh: identity · authority DAG · replay · OCAP     │  ← unchanged, now cited
  └───────────────────────────────────────────────────────────┘
```

Architecture **B is rejected as a wire format** but **retained internally**: the
Mesh *evidence record* — the thing written into the authority DAG / conversation
graph — is exactly "a signed envelope wrapping a CID of the canonical A2A
object." That gives B's provenance strength without B's interop cost.

---

## 10. What Agent Mesh can delete or simplify

Approached as "what can we stop owning?" — with the honest answer that **the
list is short, because Mesh never built an application layer.**

**Stop building (highest value — these are unbuilt, so deletion is free):**

1. **Session-stream conversation semantics** (#58 ADR, #84). Do not define a
   bespoke session/turn model. Implement `open_session` as the *carrier* for
   A2A `StreamResponse`, and take `contextId`/`taskId`, the ordering guarantee
   and multi-subscriber broadcast rules from A2A §3.5.2.
2. **Issue #67's `RecordKind` vocabulary.** `UserMessage`/`AgentMessage`/
   `ToolInvocation`/`ToolResult`/`Patch` re-invents `Message`/`Part`/`Artifact`
   plus MCP. Redefine `ConversationRecord.payload` as *a CID over a canonical
   A2A object* (or MCP call), keeping only the genuinely-Mesh record kinds:
   `Attestation`, `Checkpoint`, `Decision`, `Retraction`, `Supersession`.
   This is a large simplification of an unbuilt design.
3. **A capability vocabulary.** Keep `Anycast{capability}` and the mDNS TXT tag
   as a *routing hint* (cheap, LAN-local, pre-connection). Stop there: the
   descriptive layer is `AgentSkill`. Do not add modes, schemas, or examples to
   the TXT record.
4. **Per-topic payload schemas in consumers.** `newt-mesh`'s `InferenceRequest`
   and the dock's `SessionInput` are private application protocols. They are
   `Message` + `Part` + `Task`. New consumers should not invent a third.
5. **Issue #38 ("Agent Mesh should be data agnostic").** A2A's `Part` oneof
   (`text` / `raw` bytes / `url` / structured `data`, each with `media_type`)
   *is* the data-agnostic answer, already standardised and already
   multi-modal. Close #38 by adopting `Part` rather than designing a format
   negotiation layer.

**Simplify (built, but should shrink):**

6. `CorrelationId` (`reply.rs:22`) stays as a bus-internal transport concern,
   but must not grow into an application-visible request id — `messageId` and
   `taskId` own that.
7. Error taxonomy: for A2A-carried traffic, map to A2A's nine named errors
   (§3.3.2) rather than growing `MeshError`.

**Explicitly do NOT delete** — these have no A2A equivalent and are the product:
`SignedEnvelope`, `CertChain`/`Issuer`, `Caveats`, `Authority`/`Grant`/
`verify_chain`/`admit`, `replay.rs`, `ReplyWaiter`'s peer binding,
`DeliveryProvenance`, the mDNS+fingerprint reachability model, and the ratchet.

---

## 11. Agent Mesh's role, earned from the evidence

The operator's candidate sentence survives, with one substitution — *"under
whose authority"* is right, but the load-bearing word is **evidence**, because
A2A §7.6.4 disclaims exactly that and nothing else:

> **A2A specifies how autonomous agents ask each other to do work.
> Agent Mesh makes the answer to "who asked, under whose authority, within
> which capabilities, and what was actually enforced" into evidence a third
> party can verify later — without either agent having to trust the other's
> logs.**

Ranking the candidate differentiators by *how much of the property is already
built* and *how badly A2A lacks it*:

| Contribution | Built? | A2A gap | Strength |
|---|---|---|---|
| **Delegated authority (attenuation-only, verified both ends)** | **I** | total | **strongest** — nothing comparable exists or is proposed with a working algebra |
| **OCAP integration with an enforcement witness** (`admit` → bridle) | **I** | total | **strongest** — this is the property no competing A2A proposal has |
| **Expected-responder binding** | **I** | total | very strong, and startlingly cheap |
| **Cryptographic agent identity** | **I** | total, but **crowded** (#1497, #1786, #2043, #1672…) | strong, poorly differentiated |
| **Authenticated delivery** | **I** | total | strong |
| **Provenance chains** | **P** (DAG built, not wire-bound) | total (#2028 proposed) | strong once §8.3 lands |
| Receipts / audit evidence | **A** | total | high potential, unbuilt |
| Signed artifacts | **A** | total (#1140 proposed) | medium — better contributed upstream |
| Cross-agent policy enforcement | **P** | total (#1716 proposed) | medium |

The two-line version for a README: **delegated authority with an enforcement
witness**. Cryptographic identity is table stakes that a dozen other proposals
also claim; *an attenuation lattice whose grants can be checked against what the
operating system actually permitted* is ours alone.

---

## 12. Rust integration seam (`a2a-rs`)

| Aspect | Finding |
|---|---|
| Crates | `a2a-lf` (types), `a2a-client-lf`, `a2a-server-lf`, `a2a-pb`, `a2a-grpc`, `a2a-slimrpc`, `a2acli` |
| License | **Apache-2.0** — matches agent-mesh |
| MSRV / edition | **1.85 / edition 2024** vs agent-mesh's **1.75 / 2021** ⚠ |
| Maturity | `a2a-lf` **0.3.0** on crates.io, 2 published versions. Pre-1.0 → expect breakage |
| Protocol version | `a2a::VERSION = "1.0"` (`a2a/src/lib.rs:20`) — current |
| Types crate weight | **very light**: serde, serde_json, chrono, base64, thiserror, uuid |
| Client weight | + reqwest, tokio, futures, rustls, semver, pin-project-lite |
| Server weight | + axum, tower, hyper (not needed for a client-only spike) |
| Transport abstraction | `Transport` trait (`a2a-client/src/transport.rs:20`) + `TransportFactory` (`:96`), registerable via `A2AClientFactory::builder().register(...)` (`factory.rs:145`) |
| Custom-binding precedent | `a2a-slimrpc/src/client.rs:400` implements `TransportFactory` for a non-HTTP transport |
| Client interceptors | `CallInterceptor::before(&self, method, params: &mut ServiceParams)` — **headers only, no body access** (`a2a-client/src/middleware.rs:12`) |
| Server interceptors | `CallInterceptor::before(&self, ctx: &mut CallContext, request: &Value)` — **sees the full request** and can set `ctx.user` (`a2a-server/src/middleware.rs:68`) |
| Server handler seam | `RequestHandler` (`a2a-server/src/handler.rs:353`) — public trait taking `&ServiceParams` + typed request; decoratable |
| Executor seam | `ExecutorContext` carries `user`, `service_params`, `metadata`, `tenant` (`a2a-server/src/executor.rs:11`) |
| **Agent Card signing/verification** | **absent.** `AgentCardSignature` is a data type only (`a2a/src/agent_card.rs:519`); no JCS, no JWS, no key resolver anywhere in the repo |
| **Extension negotiation** | **absent.** `SVC_PARAM_EXTENSIONS` is defined (`a2a/src/lib.rs:26`) but never read or written by client or server |
| Task persistence | `TaskStore` trait + in-memory impl (`a2a-server/src/task_store/`) — swappable |
| Streaming / cancellation / errors | complete (`StreamResponse`, `CancelTask`, `A2AError` + `errordetails`) |

### 12.1 The narrowest useful seam

**Depend on `a2a-lf` only** for stage 1. It is a types crate with six trivial
dependencies, which means the entire A2A data model becomes available to
agent-mesh for a near-zero dependency cost, with no HTTP stack and no runtime
opinions. Everything in §10's "stop building" list can be actioned against
`a2a-lf` types alone.

Add `a2a-client-lf` for the outbound spike, and `a2a-server-lf` only when we
publish an endpoint.

**Do not fork.** Every capability we need at the client is reachable through
public traits: `Transport`/`TransportFactory` for the mesh binding,
`RequestHandler` decoration for server-side verification, `CallInterceptor` for
header work.

### 12.2 The one real friction: MSRV

`a2a-rs` requires **Rust 1.85 / edition 2024**; agent-mesh declares
`rust-version = "1.75"`. Local toolchain is 1.97.1, so this is a policy problem,
not a build problem. Recommended handling: put A2A work in a **new workspace
member** (`agent-mesh-a2a`) with its own `rust-version = "1.85"`, and state
plainly that `cargo build --workspace` now requires 1.85 while the six existing
published crates keep their 1.75 floor for downstream consumers. Do not bump the
floor of `agent-mesh-protocol`.

### 12.3 Contribution opportunities we would hit immediately

Both are *generic* SDK gaps, not Mesh-specific — ideal upstream PRs:

- **Client-side body access for interceptors.** Signing a request body is
  impossible today because `CallInterceptor::before` only gets `ServiceParams`.
  Every proposed message-signing extension (#1829 and friends) needs this. A
  `before_request(&self, method, req: &mut SendMessageRequest)` hook — or
  passing `&mut Value` alongside params — is the minimal generic fix.
- **Agent Card JWS verification with a verifier-controlled key resolver.**
  `a2a-python` has `utils/signing.py` (JCS + JWS sign/verify); `a2a-go` has a
  `KeyResolver` with a normative "MUST NOT use signer-supplied `jku`" constraint
  (per issue #2096). `a2a-rs` has neither. Porting the Go semantics is a
  self-contained, high-value PR that also closes a security gap.
- **Extension negotiation plumbing.** `A2A-Extensions` is defined but unread.
  `a2a-python` ships `extensions/common.py`; `a2a-rs` needs the equivalent —
  and *we* need it for architecture C.

---

## 13. Interoperability spike design (experimental, disposable)

**Crate:** `agent-mesh-a2a` — new workspace member, `publish = false` initially,
clearly marked experimental.

### 13.1 Outbound leg — Mesh → third-party A2A agent

```text
   newt / amesh                                  3rd-party A2A agent
        │                                        (a2a-samples helloworld)
        │ 1. GET /.well-known/agent-card.json  ─────────▶
        │ 2. pick skill from card.skills[]
        │ 3. A2AClientFactory::create_from_card(&card)
        │ 4. send_streaming_message(Message{parts:[text]})
        │ ◀───── 5. StreamResponse: TaskStatusUpdateEvent … TaskArtifactUpdateEvent
        │ 6. bind: SignedEnvelope over CID(canonical Task) — local evidence record
        ▼
   evidence: { agent_fp, user_fp, grant_id, card_cid, task_cid, artifact_cids[] }
```

Demonstrates all seven required behaviours from the brief. Note that steps 6–7
are **local**: the third party neither knows nor cares. That is the point — it
proves Mesh evidence can be recorded around an exchange with an agent that has
never heard of us.

`amesh a2a call <card-url> --skill <id> --text "…"` is the whole CLI surface.

### 13.2 Inbound leg — third-party A2A client → Mesh/Newt

```text
   any A2A client (a2acli, a2a-inspector, python sample)
        │  GET /.well-known/agent-card.json
        │  POST /  {"jsonrpc":"2.0","method":"SendMessage",…}
        ▼
   agent-mesh-a2a server (a2a-server-lf, JSON-RPC binding)
        │  MeshVerifyingHandler<DefaultRequestHandler>   ← decorator, not a fork
        │    · no mesh-identity metadata?  → serve normally (anonymous tier)
        │    · mesh-identity present?      → verify cert chain + sig
        │                                    → attach RequestContext-equivalent
        │                                    → record evidence
        ▼
   AgentExecutor → newt
```

The Mesh extensions are declared `required: false`, so an unmodified client
gets a working agent and a normal result. A Mesh-aware client that sets
`A2A-Extensions: …/mesh-identity/v1` gets a verified, attributed, evidence-backed
exchange. **This graduated-strength property is the whole design and must be
tested explicitly** — with `a2a-inspector` / `a2acli` as the ignorant client.

### 13.3 Validation targets

| # | Claim under test | Pass condition |
|---|---|---|
| 1 | `a2a-lf` types suffice to express our traffic | `newt-mesh`'s `InferenceRequest` round-trips as `Message`+`Part` with no loss |
| 2 | Unmodified third parties can call us | `a2acli` completes a task against our endpoint with zero mesh config |
| 3 | Extension metadata survives the SDK | signature attached in `Message.metadata` arrives byte-identical server-side |
| 4 | Client-side body signing is blocked | confirm `CallInterceptor` cannot reach the body → justifies the upstream PR |
| 5 | Canonicalisation is tractable | JCS over `Message` minus one metadata key verifies across a round trip |
| 6 | MSRV isolation works | `cargo check -p agent-mesh-protocol` still passes on 1.75 |

Explicitly **out of scope** for the spike: the custom protocol binding (D), push
notifications, gRPC, and any change to `agent-mesh-protocol`.

---

## 14. Upstream contribution opportunities

Classified per the brief's five options.

| Gap | Recommendation | Rationale |
|---|---|---|
| Client interceptor cannot see the request body (`a2a-rs`) | **Contribute an SDK hook upstream** | Purely generic; blocks every signing extension, not just ours |
| No Agent Card JWS verification in `a2a-rs` | **Contribute upstream**, port `a2a-go`'s `KeyResolver` semantics | Parity with Python/Go; also closes the #2096 trust-root hole in Rust |
| No extension negotiation plumbing in `a2a-rs` | **Contribute upstream** | Parity with `a2a-python`'s `extensions/common.py`; we need it anyway |
| §8.4.3 permits signer-controlled trust root via `jku` | **Support the existing spec issue** [#2096](https://github.com/a2aproject/A2A/issues/2096) | Already filed with proposed normative text; add the Rust-SDK data point rather than filing a duplicate |
| Artifact integrity (hash + signature) | **Support / co-author** [#1140](https://github.com/a2aproject/A2A/issues/1140) | Genuinely generic; we would otherwise build it privately |
| On-behalf-of / actor chain on the wire | **Support** [#2028](https://github.com/a2aproject/A2A/issues/2028) | Note that its RFC 8693 `act`-claim shape is *carriage*, not *verification* — our attenuation algebra is the complement, not a competitor |
| Per-message signing | **Watch** [#1829](https://github.com/a2aproject/A2A/issues/1829) (143 comments) | Do **not** open a rival proposal. If it converges on RFC 9421, our identity extension should carry ed25519 keys *into* that mechanism rather than beside it |
| **Attenuated-authority delegation with an enforcement witness** | **Private A2A extension first**, then propose | Nothing upstream covers `admit()`/L3 BOUND. But per governance, an experimental repo needs a **Maintainer sponsor** — earn it with a working reference implementation and adoption evidence first |
| Agent Mesh as a transport | **Propose a custom protocol binding** (`experimental-cpb-agent-mesh`) once D is built | Clear precedent (`experimental-cpb-slimrpc`); SDKs "SHOULD" implement official bindings |
| Floating identity / endpoint-independent addressing | **Keep entirely in Agent Mesh** | This contradicts A2A's URL-as-identity model at the root. Not a gap in A2A; a different philosophy |
| Auto-team rule / same-operator trust | **Keep entirely in Agent Mesh** | Deployment policy, not protocol |

**Governance note.** The `a2aproject` extension path requires: an issue in
`a2aproject/A2A` with abstract + motivation + draft; a Maintainer sponsor to
create `experimental-ext-*`; Apache-2.0; at least one reference implementation;
then a TSC vote (50% quorum, majority) to graduate. Given ~20 competing
identity/trust proposals and one graduated experimental repo, our realistic
route is: **build it, use it, publish the spec under our own URI namespace,
demonstrate adoption, then propose.** Trying to standardise first would be
premature.

---

## 15. Next steps, ordered by dependency

Every item is one branch and one PR, per workspace policy.

**Stage 0 — Mesh-internal, independent of A2A (do these regardless)**

| # | Work | Depends on | Why first |
|---|---|---|---|
| 0.1 | **Cite the grant on the wire** — carry `GrantId` (+ resolvable `Authority`) with a request; verify at admission | — | §3.1's biggest gap; blocks every provenance claim in §8.3, A2A or not |
| 0.2 | Land an `AttestationVerifier` so `Derivation::Elevation` is usable | 0.1 | `DenyAllElevations` currently makes half the algebra inert |
| 0.3 | Bind the cert to `conn.remote_id()` **in the transport**, not only the bus | — | Closes the field-guide §2 residual for non-bus consumers |

**Stage 1 — Adopt the vocabulary (low risk, high leverage)**

| # | Work | Depends on |
|---|---|---|
| 1.1 | Add `agent-mesh-a2a` workspace member; depend on `a2a-lf` only; MSRV 1.85 confined | — |
| 1.2 | `AgentCard` projection from mesh identity (`UserKey`/`AgentKey`/capabilities → card + skills) | 1.1 |
| 1.3 | Evidence record type: `SignedEnvelope` over `CID(canonical A2A object)` | 1.1, 0.1 |
| 1.4 | Amend ADR #58 and issue #67 to build on `contextId`/`taskId`/`Message`/`Artifact`; close #38 by adopting `Part` | 1.1 |

**Stage 2 — Outbound interop spike (experimental)**

| # | Work | Depends on |
|---|---|---|
| 2.1 | `amesh a2a call` — card fetch, skill select, streaming task, artifact capture | 1.2 |
| 2.2 | Record the exchange as an evidence record; `amesh a2a evidence show` | 1.3, 2.1 |
| 2.3 | Run against `a2a-samples` helloworld; write up validation targets 1–6 (§13.3) | 2.1 |

**Stage 3 — Upstream SDK contributions (parallel with stage 2, unblocked by it)**

| # | Work | Depends on |
|---|---|---|
| 3.1 | `a2a-rs` PR: extension negotiation helpers (`A2A-Extensions` read/write) | 2.3 evidence |
| 3.2 | `a2a-rs` PR: Agent Card JCS+JWS verification with verifier-controlled `KeyResolver` | — |
| 3.3 | `a2a-rs` PR/issue: client interceptor body access | 2.3 (validation target 4 is the justification) |
| 3.4 | Comment on A2A #2096 / #1140 / #2028 with our data | 2.3 |

**Stage 4 — Inbound surface + extension specs**

| # | Work | Depends on |
|---|---|---|
| 4.1 | `a2a-server-lf` endpoint with `MeshVerifyingHandler` decorator; anonymous tier works | 3.1, 3.3 (or a local workaround) |
| 4.2 | Publish `mesh-identity/v1` extension spec under our URI namespace | 4.1 |
| 4.3 | Publish `mesh-authority/v1` (grant chain) and `mesh-receipt/v1` | 4.2, 0.1, 0.2 |
| 4.4 | Prove graduated strength: `a2a-inspector` (ignorant) and a Mesh-aware client against one endpoint | 4.1–4.3 |

**Stage 5 — Custom protocol binding (only if 4.4 shows the extension tier is insufficient)**

| # | Work | Depends on |
|---|---|---|
| 5.1 | `MeshTransportFactory` implementing `a2a_client::TransportFactory` over the bus | 4.4, #84 (session streams) |
| 5.2 | §5.1 functional-equivalence conformance incl. push-notification carve-out | 5.1 |
| 5.3 | Propose `experimental-cpb-agent-mesh` with a maintainer sponsor | 5.2 |

**Decisions taken unilaterally in this document** (reversible; flag any you want
changed): adopt A2A vocabulary rather than extend ours; recommend E over B;
reject envelope-wrapping as a wire format; confine the MSRV bump to a new crate;
use `a2a-lf` types-only as the first dependency; publish extensions under a
Gilamonster URI namespace before seeking a2aproject sponsorship; do not open a
rival message-signing proposal to #1829; treat #38 as answered by A2A `Part`.

---

## Appendix — primary sources consulted

**A2A (normative first):**
[`specification/a2a.proto`](https://github.com/a2aproject/A2A/blob/main/specification/a2a.proto) ·
[`docs/specification.md`](https://github.com/a2aproject/A2A/blob/main/docs/specification.md) ·
[`docs/topics/extensions.md`](https://github.com/a2aproject/A2A/blob/main/docs/topics/extensions.md) ·
[`docs/topics/extension-and-binding-governance.md`](https://github.com/a2aproject/A2A/blob/main/docs/topics/extension-and-binding-governance.md) ·
[releases](https://github.com/a2aproject/A2A/releases) ·
issues [#1014](https://github.com/a2aproject/A2A/issues/1014),
[#1140](https://github.com/a2aproject/A2A/issues/1140),
[#1497](https://github.com/a2aproject/A2A/issues/1497),
[#1716](https://github.com/a2aproject/A2A/issues/1716),
[#1829](https://github.com/a2aproject/A2A/issues/1829),
[#1937](https://github.com/a2aproject/A2A/issues/1937),
[#2028](https://github.com/a2aproject/A2A/issues/2028),
[#2079](https://github.com/a2aproject/A2A/issues/2079),
[#2096](https://github.com/a2aproject/A2A/issues/2096)

**SDKs:** [`a2a-rs`](https://github.com/a2aproject/a2a-rs) @ `9d70cfd` ·
[`a2a-python`](https://github.com/a2aproject/a2a-python) (`src/a2a/utils/signing.py`,
`src/a2a/extensions/common.py`) ·
[`a2a-samples`](https://github.com/a2aproject/a2a-samples) (`extensions/{secure-passport,timestamp,traceability,agp}`) ·
[`experimental-cpb-slimrpc`](https://github.com/a2aproject/experimental-cpb-slimrpc) ·
[`experimental-ext-oid4vp-auth`](https://github.com/a2aproject/experimental-ext-oid4vp-auth)

**Agent Mesh:** `main` `d3b2263` — `agent-mesh-protocol/src/{envelope,agent_key,user_key,caveats,authority,github_binding,signer}.rs` ·
`agent-mesh-bus/src/{bus,inbox,reply,replay,transport}.rs` ·
`agent-mesh-transport/src/handshake.rs` · `agent-mesh-discovery/src/peer.rs` ·
`agent-mesh-cli/src/mcp.rs` · `docs/field_guide.md` ·
`docs/decisions/{session_streams,agent_mesh_store,floating_identity,bus_vs_nats,ssh_transport}.md` ·
open issues #30, #38, #42–#49, #58, #65–#67, #71, #84, #85

---

## 16. Pre-existing solutions survey — what we should reuse instead of build

*Added on a second research pass. This section materially revises §9's
architecture-C sketch: the hand-rolled "signature in a `metadata` map with a
bespoke canonicalisation rule" was a mistake, and there are standards for every
piece of it.*

The headline: **almost every primitive Agent Mesh would need to carry into A2A
already exists as a standard with a Rust implementation.** The parts that do
*not* exist are exactly two — and they are the parts that make agent-mesh
distinctive.

### 16.1 The survey

| # | Candidate | What it is | Maturity (2026-08) | Fit with agent-mesh | Verdict |
|---|---|---|---|---|---|
| 1 | **[UCAN 1.0.0](https://github.com/ucan-wg/spec)** | Local-first capability chains: attenuation-only delegation, `did:key` principals, **CIDv1 + DAG-CBOR + Ed25519**, explicit *delegation ≠ invocation* split, revocation | Spec finalised 1.0.0 | **Uncanny.** Same hash/codec/curve triple we already use (`content-addressable`, dag-cbor, ed25519). Our `Grant`/`Derivation` is a UCAN-shaped design arrived at independently | **Adapt** |
| 2 | **[Biscuit 3.x](https://www.biscuitsec.org/)** (Eclipse; Rust ref impl `biscuit-auth` 6.0.0) | Offline attenuation by chaining signed blocks with single-use keypairs; **Datalog** authorizer; **third-party blocks** for cross-domain auth with no out-of-band sync | Production, 3rd major version, Eclipse-governed | Wire format for attenuated authority. Note [GHSA-p9w4-585h-g3c7 / CVE-2024-41948](https://github.com/biscuit-auth/biscuit-rust/security/advisories/GHSA-p9w4-585h-g3c7) — public-key confusion in third-party blocks | **Adopt as a projection target** |
| 3 | **[AIP — Agent Identity Protocol](https://arxiv.org/abs/2603.24775)** | Invocation-Bound Capability Tokens: identity + attenuated authz + provenance in one append-only chain. Compact mode = signed JWT; **chained mode = Biscuit + Datalog** for multi-hop. Python **and Rust** impls | Paper + reference impls; proposed to A2A as [#2054](https://github.com/a2aproject/A2A/issues/2054) | **The closest thing to us that already exists**, explicitly targeting *both* MCP and A2A — the exact two-protocol span in our §8 trace | **Engage, do not duplicate** |
| 4 | **[AGNTCY Identity](https://github.com/agntcy/identity)** | "Agent Badge": an enveloped W3C Verifiable Credential over an agent definition — **explicitly including the A2A Agent Card schema** — with ProofValue + ResolverMetadata | Open source, Cisco/Outshift-backed | ⚠️ **AGNTCY authors `a2a-rs`** (every file is `Copyright AGNTCY Contributors`). The identity layer most likely to arrive *inside* the Rust SDK we plan to depend on | **Align — and watch closely** |
| 5 | **[IETF WIMSE](https://datatracker.ietf.org/wg/wimse/documents/)** | Workload identity: architecture, credentials, identifier format, mTLS profile. Introduces a **Dual-Identity Credential binding agent identity to owner identity** | Active WG; multiple adopted drafts; AI agents explicitly in scope | The dual-identity credential *is* our `UserKey → AgentKey` cert chain, standardised. WIMSE explicitly **does not define delegation authority** — the hole we fill | **Align** (frame our chain in WIMSE terms) |
| 6 | **[SPIFFE/SPIRE](https://spiffe.io/)** (our issue [#71](https://github.com/Gilamonster-Foundation/agent-mesh/issues/71)) | X509-SVID / JWT-SVID workload identity; production at Uber/Stripe/Netflix | Mature, CNCF | Three documented mismatches for agents: needs dedicated infra (attestation nodes, registration server, CA); X.509 issuance latency vs ephemeral agents; **no cross-protocol flow** — an SVID for an MCP call has no A2A mapping | **Adapter, not foundation** |
| 7 | **[OAuth Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)** (draft-11, 2026-07-30) | Short-lived signed JWTs propagating **user identity + workload identity + authorization context through a call chain**; `txn`, `sub`, `req_wl`, `tctx` (immutable), `rctx`; passed *unmodified* downstream via a `Txn-Token` header | **WG Last Call**; IESG submission milestone Dec 2026 | Directly addresses §8's "the operator vanishes by hop 3" — but only *within a trusted domain*, with **no delegation and no attenuation**. Bearer, not capability | **Bridge to it** |
| 8 | **[RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)** (`act` / `may_act`) | Standard claim shape for "acting on behalf of" | RFC since 2020 | The shape A2A [#2028](https://github.com/a2aproject/A2A/issues/2028) mirrors. It is **carriage of a chain, not verification of one** — complementary to our algebra | **Align** |
| 9 | **[RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)** (Feb 2024; Rust [`httpsig`](https://crates.io/crates/httpsig) 0.0.24) | Signs selected HTTP components (`@method`, `@path`, `content-digest`) with `created`/`nonce`/`keyid`; Ed25519 test vectors in the RFC | Published RFC; Rust crate active | **This replaces the hand-rolled canonicalisation in §9-C.** `content-digest` + `nonce` gives us body integrity *and* replay protection over plain HTTPS, using the mechanism A2A [#1829](https://github.com/a2aproject/A2A/issues/1829) is already converging on | **Adopt** |
| 10 | **RFC 8785 JCS + RFC 7515 JWS** | Canonical JSON + detached signatures | Already **normative in A2A §8.4** for Agent Cards | Do not invent an Agent Card signing scheme. Use A2A's, and fix its trust-root hole ([#2096](https://github.com/a2aproject/A2A/issues/2096)) | **Adopt as-is** |
| 11 | **[in-toto Attestation Framework](https://github.com/in-toto/attestation) + DSSE** | `Statement { subject: [{name, digest}], predicateType: URI, predicate: {...} }`, signed with DSSE. Subjects matched **purely by digest** | Mature; the substrate under SLSA | **This is the evidence-record format we were about to invent.** Subject = CID of the A2A `Task`/`Artifact`; `predicateType` = our authority provenance URI; predicate = the grant chain | **Adopt** |
| 12 | **W3C VC / DID / [OID4VP](https://github.com/a2aproject/experimental-ext-oid4vp-auth)** | Verifiable credentials + presentations | **The only experimental extension in `a2aproject`** — for in-task authorization | The sanctioned A2A path for §7.6 in-task authorization. Heavier than we need for peer identity; right for operator↔third-party assertions | **Bridge** |
| 13 | **[W3C Trace Context](https://www.w3.org/TR/trace-context/) / OpenTelemetry** | `traceparent` / `tracestate` correlation | W3C REC | A2A [#2026](https://github.com/a2aproject/A2A/issues/2026) proposes it for A2A↔MCP audit chains. **Unauthenticated** — a correlation aid, never trust | **Adopt for correlation only** |
| 14 | **[C2PA](https://c2pa.org/)** | Content credentials for media artifacts | v2, industry-backed | Relevant only once `Artifact` `Part`s carry media | **Watch** |
| 15 | **Macaroons** | The original caveat/attenuation design | Academic + deployed | HMAC-based ⇒ verification requires the root secret. Our chains must be **publicly verifiable** | **Reject** (ancestor, not target) |
| 16 | **ZCAP-LD** | W3C object-capability delegation | Draft, low adoption | JSON-LD weight, superseded in practice by UCAN | **Reject** |
| 17 | **[KERI](https://keri.one/)** | Key Event Receipt Infrastructure: self-certifying identifiers, witnesses, rotation | Spec + impls, niche | Its self-certifying identifier *is* our BLAKE3 fingerprint. Its **key rotation + witness** model is the answer to a problem we have not solved (agent key rotation without breaking chains) | **Study for rotation** |
| 18 | **Cedar / OPA-Rego** | Policy engines | Production | Our lattice is a *proved* meet-semilattice with a mechanised `admit()`; a general policy engine is strictly weaker for that job. Possible for local, non-safety-critical policy | **Reject for the lattice** |

### 16.2 What the survey changes

Three findings that should alter the plan:

1. **Do not invent an evidence-record format.** in-toto `Statement` + DSSE
   already has exactly our shape (digest-addressed subjects, URI-typed
   predicate, detached signature envelope), plus an ecosystem of verifiers.
   Our contribution becomes *one predicate type*, not a format.
2. **Do not invent per-message signing.** RFC 9421 over `content-digest` +
   `nonce` gives body integrity and replay protection on the HTTP binding, is
   already implemented in Rust, and is where A2A #1829's 143-comment thread is
   heading. Signing inside a `metadata` map with a homegrown canonicalisation
   would be strictly worse and strictly less interoperable.
3. **Do not present cryptographic agent identity as our differentiator.** Between
   AGNTCY Agent Badges, WIMSE dual-identity credentials, AIP, DANE-anchored
   cards (#2043), CTEF (#1786, 236 comments) and #1672 (**657 comments**), agent
   identity in A2A is the most crowded design space in the ecosystem. We will not
   win it and do not need to.

### 16.3 What genuinely remains ours

After subtracting everything above, exactly two properties have **no**
pre-existing solution that fits:

**(a) A proved attenuation lattice checked against an OS enforcement witness.**
UCAN and Biscuit both express attenuation, but neither answers *"was the
authority actually enforced?"* Our `ResolvedAuthority` / `relate()` /
`admit()` chain (`authority.rs:582-832`) computes the L3 BOUND relation between
a granted authority and what a real kernel fence permitted, and agent-bridle
supplies the witness. Nothing else in the surveyed set has an enforcement side
at all — they all stop at "the token says you may."

**(b) Expected-responder binding.** Every surveyed system authenticates the
*caller*. Only `agent-mesh-bus/src/reply.rs:41` refuses a reply that was not
signed by the peer the request was addressed to. UCAN's invocation model, AIP's
IBCTs, Txn-Tokens and SPIFFE all leave the response direction unauthenticated.

That is the sentence in §11, sharpened by evidence:

> **Agent Mesh's contribution is not "cryptographic agent identity" — that is
> now commodity. It is a delegated-authority lattice whose grants can be checked
> against what the operating system actually enforced, and a delivery layer that
> proves the answer came from the agent you asked.**

---

## 17. Concrete integration proposals

Seven proposals, each spec-compliant, each reusing a standard from §16, ordered
by increasing cost. P1–P3 are the recommended near-term set.

### P1 — Adopt A2A types internally (no protocol exposure)

**What.** Depend on `a2a-lf`; express mesh payloads as `Message`/`Part`, results
as `Artifact`, and lifecycle as `TaskState`. Replace `newt-mesh`'s
`InferenceRequest` and the dock's `SessionInput` with A2A objects carried
verbatim inside `SignedEnvelope.payload`.

**Reuses.** A2A data model. **Costs.** One crate, one MSRV carve-out.
**Unlocks.** Everything else; closes issue #38; deletes the §10 list.
**Interop gained.** None yet — and that is fine, this is the cheap step.

### P2 — Evidence records as in-toto Statements

**What.** Define one predicate type,
`https://gilamonster.foundation/attestations/mesh-authority/v1`, carrying
`{ userFp, agentFp, certChain, grantId, authorityId, chain[], deliveryProvenance, enforcementWitness? }`.
Subject = the CID of the canonical A2A `Task` or `Artifact`. Envelope = DSSE.

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "task/9f2c…",
                "digest": { "blake3": "…", "sha256": "…" } }],
  "predicateType": "https://gilamonster.foundation/attestations/mesh-authority/v1",
  "predicate": {
    "operator":  { "userFp": "…", "anchor": "github:hartsock" },
    "requester": { "agentFp": "…", "certChain": "…" },
    "authority": { "grantId": "bafy…", "authorityId": "bafy…",
                   "chain": ["bafy…", "bafy…"], "trustedRoot": "bafy…" },
    "delivery":  { "provenance": "direct", "carrierAgentFp": "…" },
    "enforcement": { "witness": "agent-bridle", "admitted": true }
  }
}
```

**Reuses.** in-toto Statement + DSSE. **Costs.** One serde type; no new crypto.
**Unlocks.** Existing attestation tooling can consume our provenance;
`enforcement` has no counterpart anywhere, which makes the predicate worth
publishing on its own merits.
**Depends on.** §15 items 0.1 (cite the grant on the wire) and 0.2 (signed
assertions) — without those the predicate is decorative.

### P3 — `mesh-provenance/v1` A2A extension, evidence by reference

**What.** One `AgentExtension`, `required: false`. Rather than embedding
signatures in `metadata`, the extension carries **a reference to a P2
attestation**:

```jsonc
"metadata": {
  "https://gilamonster.foundation/a2a/ext/mesh-provenance/v1": {
    "attestation": "bafy…",                 // CID of the DSSE-wrapped Statement
    "fetch": ["https://newt.example/attest/bafy…"],
    "agentFp": "…", "grantId": "bafy…"      // hints; the attestation is authoritative
  }
}
```

**Why by reference.** It sidesteps the whole canonicalisation problem: nothing
inside the A2A object is signed, so no JCS-over-a-subtree rule is needed, and
`metadata` staying mutable does not break anything. Integrity of the *exchange*
is P4's job; this extension is about *attributable evidence*.

**Reuses.** A2A §4.6 extension mechanism, content addressing.
**Costs.** A spec document and a small serde type.
**Interop.** Full — extension-unaware peers ignore it entirely.

### P4 — RFC 9421 signatures on the HTTP binding

**What.** Sign outbound A2A HTTP requests with the AgentKey per RFC 9421:
components `("@method" "@authority" "@path" "content-digest")`, params
`created`, `nonce`, `keyid = <agent fingerprint>`. Verify inbound the same way
in a `MeshVerifyingHandler` decorator over `RequestHandler`.

**Reuses.** RFC 9421 + the Rust `httpsig` crate.
**Gains over P3.** Body integrity, replay protection (the `nonce` param feeds
straight into our existing `NonceCache`), and a verified caller identity —
i.e. `RequestContext` semantics over plain HTTPS, with **no new crypto and no
bespoke canonicalisation**.
**Still cannot do.** Expected-responder binding — RFC 9421 can sign responses,
but nothing binds the responder key to the agent you *intended*, because A2A
Agent Cards have no agent identifier (#1014). That gap is structural and is
P6's job.
**Blocked by.** `a2a-rs`'s client interceptor cannot see the body
(`a2a-client/src/middleware.rs:12`) — hence §14's upstream hook. Workaround for
a spike: a wrapping `Transport` impl.

### P5 — Project grants into Biscuit for third parties

**What.** Keep `Authority`/`Grant` as the internal truth, and emit an equivalent
**Biscuit** token (attenuated blocks + Datalog facts derived from `Caveats`) for
peers that cannot parse our DAG. `Caveats` maps cleanly: each `Scope::Only(set)`
axis becomes a Datalog fact set; `⊑` becomes block attenuation.

**Reuses.** `biscuit-auth` (Rust reference implementation).
**Caution.** Biscuit's third-party blocks carry a known public-key-confusion
class of bug (CVE-2024-41948); if used, pin a patched version and prefer
first-party attenuation.
**Note.** This is also the on-ramp to AIP interop — AIP's chained mode *is*
Biscuit.
**Verdict.** Do this only once a real third party asks. Do not build it
speculatively.

### P6 — `cpb-agent-mesh` custom protocol binding

Unchanged from §9-D. This is the only proposal that delivers
expected-responder binding, because that property requires owning the
transport. Gate it on §13.3 validation showing P3+P4 are insufficient.

### P7 — Bridge to Transaction Tokens and WIMSE (enterprise leg)

**What.** A projection in each direction: (a) mint a `Txn-Token`-shaped JWT from
a Mesh grant chain when crossing into an enterprise trust domain; (b) accept a
Txn-Token's `sub`/`req_wl`/`tctx` as the *origin* of a Mesh grant chain when
work arrives from one. Similarly, express the `UserKey → AgentKey` chain as a
WIMSE dual-identity credential.

**Why.** Transaction Tokens are in WG Last Call with an IESG milestone this
December. When they land, they will be *the* enterprise answer to call-chain
context, and being projectable into them is far more valuable than competing
with them. Note the asymmetry that makes this a genuine contribution: Txn-Tokens
carry context but **cannot attenuate**; our chain attenuates but has no
enterprise deployment story. Each covers the other's gap.

**Timing.** Not before the draft is an RFC. Track it.

### 17.1 Proposal → property matrix

| Property | P1 | P2 | P3 | P4 | P5 | P6 | P7 |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Vanilla A2A peers can call us | – | – | ✓ | ✓ | ✓ | ✗ | ✓ |
| Attributable evidence for an exchange | – | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Body integrity | – | – | – | ✓ | – | ✓ | – |
| Replay protection | – | – | – | ✓ | – | ✓ | – |
| Verified caller identity | – | – | – | ✓ | ✓ | ✓ | ✓ |
| **Expected-responder binding** | – | – | – | – | – | **✓** | – |
| Attenuated delegation chain | – | ✓ | ✓ | – | ✓ | ✓ | partial |
| **Enforcement witness (OS fence)** | – | **✓** | **✓** | – | – | ✓ | – |
| Third-party tooling can consume it | – | ✓ | ✓ | ✓ | ✓ | – | ✓ |
| New crypto we must own | – | none | none | none | none | existing | none |

### 17.2 Revision to §15

Insert before stage 3, and adjust:

- **1.3 is superseded**: the evidence record is an **in-toto Statement + DSSE**
  (P2), not a bespoke `SignedEnvelope`-over-CID type.
- **4.2/4.3 are superseded**: publish **one** extension (`mesh-provenance/v1`,
  P3, evidence-by-reference) rather than three; identity and authority ride
  inside the referenced attestation.
- **New stage 2.4**: RFC 9421 signing via a wrapping `Transport` (P4), which is
  also the empirical justification for upstream PR 3.3.
- **New stage 0.4**: study KERI-style key rotation before the cert chain
  ossifies — agent key rotation without invalidating historical grants is
  unsolved in agent-mesh today and none of the surveyed systems solves it for us.
- **Engagement, not code**: comment on A2A #2054 (AIP) and #1672/#1829 offering
  the **enforcement-witness** angle specifically. That is the contribution nobody
  else in those threads has.

---

## 18. A2A standardization trajectory — evidence

*Third research pass (2026-08-18), adversarially verified: 25 candidate claims,
3-vote refutation panel each, **11 confirmed / 14 refuted**. Confidence levels
below are the panel's, not the author's. This section answers §14's open
question — "should we be in the standards fight at all?" — with primary evidence,
and it changes the answer from a hunch to a decision.*

### 18.1 The pipeline has never produced an official extension

**Confidence: high (3-0).** The `a2aproject` org holds exactly **17 public
repos**. Only two match the extension/binding naming convention, and both still
carry the `experimental-` prefix:

- `experimental-ext-oid4vp-auth` — created **2025-05-14 06:43:30Z**
- `experimental-cpb-slimrpc` — created **2025-05-14 06:46:45Z**

Created three minutes apart on the same day — a single seeding event, not
organic pipeline flow. Under A2A's own governance the rename
`experimental-ext-*` → `ext-*` **is** the graduation marker, so the absence of
any bare `ext-*`/`cpb-*` repo is direct proof of **zero graduations**. Roughly
three months of observation with n=0 completions.

> Methodological note carried from the verification pass: the Jul/Aug 2026 dates
> shown in the GitHub org listing are `pushed_at`, **not** `created_at`. Anyone
> reading the org page casually will get the age of these repos wrong.

### 18.2 The gate is a named maintainer sponsor — not merit, not consensus

**Confidence: high (3-0).** Two independent, non-hedged statements in
`docs/topics/extension-and-binding-governance.md`:

> "An experimental repository can **ONLY** be created with sponsorship from an
> A2A Maintainer."
> "…2. **Repository Creation:** The sponsoring Maintainer creates the
> `experimental-ext-*` or `experimental-cpb-*` repository under `a2aproject`."

The proposer never creates the repo. All **seven** issues carrying the
`extension-proposal` label (#1387, #1439, #1441, #1786, #1796, #1864, #1887) are
open with no corresponding repo. #1786 (CTEF) asked for sponsorship explicitly on
2026-04-25 and had still not received it as of 2026-08-12.

### 18.3 Comment volume is not a signal — it is close to an anti-signal

**Confidence: high (3-0 / 2-1 merged).** Across every identity-adjacent
proposal checked, comments from `MEMBER`/`OWNER`/`COLLABORATOR`/`CONTRIBUTOR`
accounts total **zero**:

| Issue | Comments | Insider comments |
|---|---:|---:|
| #1672 Agent Identity Verification | 657 | **0** |
| #1786 Cryptographic Agent Identity (CTEF) | 236 | **0** |
| #2028 actor-chain delegation | 22 | **0** |
| #2043 DANE-anchored identity | 12 | **0** |
| #1140 content integrity | 10 | **0** |
| #1497 identity & trust framework | 9 | **0** |
| #2096 `jku` trust-root bug | 2 | **0** |
| #2054 AIP partners list | 1 | **0** |

All 16 commenters on #1786 were cross-checked against `MAINTAINERS.md` **and**
`orgs/a2aproject/public_members` — zero matches. Zero reactions on the issue;
the timeline shows no `labeled`/`assigned`/`milestoned` events by any actor.
Nor does enterprise weight help: **#1796** (telecom) drew in-thread support from
a Telecom Italia senior architect and a Vodafone Group engineer, behind a
Huawei-authored proposal with a shipped open-source reference implementation
(A2A-T) — and still produced no repo. It progressed **outside** the org instead.

One qualification the panel insisted on: Sam Betts (Cisco) *did* apply the
`extension-proposal` label to #1796 on 2026-06-25, which requires triage rights.
So maintainer **triage** happens; maintainer **sponsorship** does not. Governance
treats these as distinct, and so should we.

### 18.4 What the two successful proposals actually looked like

**Confidence: medium** (n=2; correlation, and the causal direction is not
established by the public record — a sponsor may have been recruited privately
and only then commented).

| | #1723 SLIMRPC | #1463 OID4VP |
|---|---|---|
| Comments | **3** | few |
| Insiders in thread | `msampathkumar` (MEMBER), `Tehsmash` (CONTRIBUTOR, Cisco) | `darrelmiller` (Microsoft TSC seat), `amye` (Linux Foundation staff) |
| Outcome | closed 2026-05-14, same day the repo was created | closed 2026-06-23 |
| Elapsed | ~5 weeks | — |

The shape is unmistakable: **quiet threads with an insider in them produce
repos; loud threads without one do not.**

### 18.5 The TSC

**Confidence: high (3-0).** Eight seats, **all vendor-appointed**, no individual
or community-elected seats:

| Org | Seat |
|---|---|
| Google | Todd Segal (`@ToddSegal`) |
| Microsoft | Darrel Miller (`@darrelmiller`) |
| Cisco | Luca Muscariello (`@muscariello`) |
| AWS | Abhimanyu Siwach (`@siwachabhi`) |
| Salesforce | Stephen Petschulat (`@spetschulatSFDC`) |
| ServiceNow | Sugandh Rakha (`@sugandhrakha`) |
| SAP | Sivakumar N. (`@SivaNSAP`) |
| IBM | Stefano Maestri (`@maeste`) |

New organizations join only by majority TSC vote. "Steady state" composition is
deferred to 18 months after inception (2025-06-23) — i.e. **~2026-12-23**, still
future. Graduation requires a TSC vote at 50% quorum and majority of those
present: with 8 seats, **4 present, 3 votes carry**. Corroborated mechanically by
`.gitvote.yml` (`allowed_voters.teams: [a2a-tsc]`, `pass_threshold: 51`).
Asynchronous voting is *harder* than in-meeting: an electronic vote without a
meeting needs a majority of **all** members.

**This procedure appears never to have been exercised.** With zero graduated
repos there is no recorded instance of the vote running.

### 18.6 `MAINTAINERS.md` cannot tell you who can sponsor you

**Confidence: medium (2-1; one closely-related sub-claim about the spec repo was
separately refuted 0-3, an internal inconsistency the panel flagged — re-verify
before relying on that detail).**

`MAINTAINERS.md` is a **1058-byte** personnel roster: bare GitHub handles under
`role:maintain` / `role:admin` for six SDK and sample repos. `grep` for
`tsc|steering|sponsor|extension|graduat|vote|approv|process|charter` returns
**zero matches**. Only 3 of the 8 TSC members appear in it at all, none labeled
as TSC. `CONTRIBUTING.md` likewise has zero hits for
`sponsor|extension|graduat|tsc|steering|experimental`. The extension lifecycle
lives *solely* in `docs/topics/extension-and-binding-governance.md`.

Practical consequence: a newcomer following the obvious documents will not
discover who is empowered to sponsor them.

### 18.7 What was refuted

Reported for honesty — 14 of 25 candidate claims did not survive, including
several that would have been convenient:

- *"A2A deliberately routes identity to external SDOs (IETF/W3C/OIDF)."*
  **Refuted 0-3.** No primary source states such a policy, and no dedicated A2A
  identity/security working group surfaced. The OID4VP repo is a **single
  observation** consistent with several explanations — including simple sponsor
  availability (a Microsoft TSC member with existing OIDF involvement).
- *"Cisco's founding-member status is the observed path to landing an
  extension."* **Refuted 0-3.** Cisco's footprint is real (Sam Betts authored the
  governance doc via PR #1619; Aron Kerekes updated it via PR #2015; Tehsmash
  triaged #1796 and participated in #1723), but two datapoints cannot separate
  "Cisco sponsors extensions" from "Cisco **staffs** the extension process."
- *"Multiple cross-validated reference implementations materially help."*
  **Refuted 0-3.**
- *"The roadmap's silence on identity proves no identity proposal was elevated."*
  **Refuted 0-3.**
- *"Time-in-queue is a meaningful metric."* **Refuted 0-3** — with n=0
  graduations there is no denominator.

### 18.8 What this changes

1. **Do not pursue an `a2aproject` extension repo as a near-term goal.** The
   pipeline has produced zero graduations, the vote has never run, and steady-state
   governance is still four months out. Targeting it would be planning against a
   process with no observed completions.
2. **Governance explicitly blesses the alternative.** Same document: *"Anyone may
   develop and publish extensions or custom protocol bindings independently. The
   tiers and lifecycle described here apply specifically to those hosted under the
   `a2aproject` GitHub organization."* Publishing `mesh-provenance/v1` under our
   own URI namespace is not a consolation prize — it is the documented path, and
   it is what the telecom effort (A2A-T) did after its proposal stalled.
3. **Stop treating issue threads as advocacy channels.** #1672 has 657 comments
   and zero insider replies. Adding a 658th is not a strategy. Comment only where
   we have a *specific technical correction* (e.g. #2096, where our finding is a
   verifiable spec bug with proposed normative text), not to build support.
4. **The sponsorship path runs through code, not threads — and it points at one
   place.** Cisco/AGNTCY authors `a2a-rs`, staffs the extension-governance
   process, and ships a competing identity framework (Agent Badge). Our §14
   upstream SDK PRs (extension negotiation, card JWS verification, interceptor
   body access) are therefore not merely good citizenship: **they are the only
   credible way to become known to the people who can sponsor us**, and they are
   valuable to us regardless of whether sponsorship ever materialises. That is a
   strictly better bet than a proposal issue.
5. **Revised §14 verdict** for the row "Attenuated-authority delegation with an
   enforcement witness": *private extension under our own namespace, published
   spec, working implementation, no sponsorship request in the near term.*
   Revisit after 2026-12-23 when TSC steady-state composition is settled.
