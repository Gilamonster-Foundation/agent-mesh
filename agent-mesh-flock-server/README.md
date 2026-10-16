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
- `Server::admit` is one transaction: duplicate lookup, then signer, then the
  model's writer-chain, reference and table checks, then **one frame and one
  fsync**. Refused events write nothing to the log; they go to a side journal.

A flock directory holds `server.key`, `genesis`, `log` and `refusals.log`.

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

## Boundaries

- Signers come from a `SignerResolver`. The default accepts only the server's
  own key; invites, sessions, epoch bumps and hand-off (step 4) supply the
  session table.
- Refusals are advisory: `refusals.log` is not part of the signed chain.
- No `watch` (step 6), no CLI beyond `amesh flock init`, no MCP or TUI.
- Unix only (file modes and `flock(2)`).
