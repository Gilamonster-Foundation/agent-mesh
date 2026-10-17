# agent-mesh-flock-server

The I/O half of a flock: it owns one flock's signed, append-only log. The pure
model (schema, admission table, board fold) is `agent-mesh-flock`; this crate
reuses it and adds nothing to it. Design: `docs/decisions/flock.md`.

Licensed under Apache-2.0.

## What it does

- `init` mints the server key (an `AgentKey` under the user key), signs the
  genesis and stores the seed and certificate in a mode-0600 file, loaded with
  `AgentKey::from_seed_and_cert`. A restart re-verifies genesis; it never mints
  a new one.
- `Server::open` takes an exclusive lock on the log (a second server on the
  same flock refuses to start), cuts off a torn final frame, and rebuilds the
  board from the retained frames.
- `Snapshot::read` is the lock-free reader: it replays the log like `open`
  (and fails closed on the same damage) but never locks or repairs; a torn
  tail is left unread, so it is safe beside a live server.
- `Server::admit` is one transaction: duplicate lookup, then signer, then the
  model's writer-chain, reference and table checks, then **one frame and one
  fsync**. A refused event writes nothing to `log`, joins no board and takes
  no admission index; it goes to the refusal chain.

A flock directory holds `server.key`, `genesis`, `log` and `refusals`.

## The refusal chain

`refusals` uses the same frame format, one entry per frame and one fsync:
`MerkleNode { parents: {previous refusal, or genesis}, payload: { event,
author, reason, admitted } }` plus the server key's `Assertion` over its id.
`reason` is a typed enum (`Reason`), not text; `admitted` is how many events
were admitted at the time. It is separate from the admission chain so a refused
event can never be mistaken for an admitted one. `Server::open` checks the
server signature, the parent link (the first is rooted at genesis) and that
`admitted` never decreases or exceeds the log, so an edited reason or a removed
or reordered interior refusal fails the open. Dropping the newest refusals is
not detectable here (rollback detection is step 6).

## Open order

1. Lock `log` (a second server refuses), then parse `log` and `refusals`
   **without modifying either**; note where an incomplete final frame begins.
2. Verify everything retained: genesis, every admission (signatures, record
   bindings, indexes, epochs, model admission), then the refusal chain.
3. Only then cut each torn tail (`set_len` + fsync). Any failure before this
   leaves both files byte-for-byte as found.

## The one byte format

```text
frame = len:u32be | check:u32be | payload[len]
check = first 4 bytes of blake3(len:u32be || "flock-frame/v1")
payload = canonical dag-cbor of Frame { sealed: [Sealed] }
Sealed  = { event, event_sig, record, record_sig }
```

Every identity inside is a `content-addressable` id; the header only lets
recovery tell a torn tail from damage. An incomplete final header or payload is
cut off. A complete header whose check fails, or a complete payload that does
not decode canonically and verify, is damage in committed history: the server
refuses to open and repairs nothing.

The admission chain is `MerkleNode { parents: {previous record, or genesis},
payload: { index, epoch, event, cert } }`, signed by the server key itself (a
session key delegated by the server does not qualify). Recovery checks the
signature, the parent, the contiguous index, that the record names its event
and certificate, and that the epoch moves only with an `epoch` event, by one.

## Sessions and the epoch ratchet

Who may sign is derived from the log, never stored: `Sessions` is rebuilt by
replaying admitted events in order, so a session that ended at index 9 was
still a session at index 8, and today's flags are never applied to old events.

| Call | What happens |
|---|---|
| `invite(member)` | `invite` event with only a **digest** of a random token; the token is returned once and never stored, so a log reader cannot redeem it |
| `enroll_begin(token, member, pubkey)` | token, claimed member and key checked; the server mints a `PossessionChallenge` for that key |
| `enroll_finish(challenge, proof)` | challenge consumed, key certified, `session-start` admitted (which consumes the token), one frame |
| `end_session(session, reason)` | `session-end` then `epoch`, **one frame** |
| `renewal_challenges()` | after a bump, a challenge for each live session behind the epoch |
| `renew_begin(last_cert)` | the `renew` entry: an earlier logged certificate of a session that has not ended |
| `renew_finish(challenge, proof)` | new certificate, `renewal` event |

A session must sign with a certificate the log recorded for it (its
`session-start` or a renewal); a certificate another session issued fails even
if it verifies. A `session-end` is admitted only together with its `epoch`
bump: `admit` refuses it alone and `Server::open` refuses a frame that holds
one without the other.

A session certificate is `delegate_external` with `valid_for_generation =
Only({epoch})`, so an old-epoch certificate fails `verify_at`. Each admission
record names the certificate its event was verified with, so a reader checks
any old event at its own epoch. Challenges are held in memory, consumed once,
and bound to a session and epoch: an answer that races a bump or a session end
is refused. A restart forgets outstanding challenges; the holder asks again.

A member's first session is active. Any later session for the same member is
admitted `pending` and signs nothing until a hand-off activates it.

`handoff(approval, sig)` moves a member's role. The approval
(`HandoffApproval`: flock, member, from, to, resume, context) is signed by an
active shepherd session, and only for a helper; the context (the `HANDOFF.md`
file ref) is required. Operator, shepherd and adapter hand-offs, and any key
merely certified by the user key, are refused until the roster binds operator
devices. The
`handoff` event carries the approval and its signature, so a reader re-checks
the authority. It ends `from`, activates the pending `to` and is followed by
an `epoch` bump in the same frame; `admit` refuses it alone and `open` refuses
a frame without the bump. `from` must be the member's current holder, so of two
competing replacements exactly one is activated, and an approval cannot be
reused. The activated session's first event must have `prev = handoff`. Server-signed events are checked against the log too: a
`session-start` must consume an unconsumed invite for its member and carry an
epoch-bounded certificate for the key it names.

## Boundaries

- The entry points are plain calls; the SSH stream that carries them is step 5.
  Who may ask for an `invite` (the roster role) is for that caller to establish.
- `serve` (Unix) owns the log and answers the wire in `wire.rs` on a 0600
  socket in a 0700 directory (`private.rs` refuses a loose directory and checks
  the peer's uid on accept). A connection carries one session; one that ends without `End` records it
  `lost`, and `End` is answered only once the end is durable. If persisting
  fails the server stops (`Serving::wait` returns the failure). It is the flock owner's local surface, not the SSH stream of
  step 9, which authenticates by a fresh signed challenge.
- Not yet: `watch` (step 6), the epoch bump when a member leaves the roster,
  per-device operator listing in the roster (so no operator approval),
  operator-signed events, any CLI beyond `amesh flock init`, MCP or TUI.
- Unix only (file modes and `flock(2)`); on other hosts the crate builds, the
  key and lock functions return an unsupported-host error, and the Unix tests
  are not compiled.
