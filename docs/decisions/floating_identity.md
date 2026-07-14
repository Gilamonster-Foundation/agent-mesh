# Floating identity — locations are candidates, never load-bearing

**Status:** accepted doctrine (Shawn, 2026-07-14 — articulated on PR #62 while
diagnosing #61). This document binds design review: a change that makes a
socket address load-bearing for reaching an identity is wrong by construction,
even when it passes tests.

## The thesis

The mesh exists so that **identity floats**. A conversational context should
move over agent harnesses the way a container workload moves over pods: the
individual harnesses are *containers for conversational context*, and the
context "floats over" the top of them all. Shawn's 20-year playbook, one layer
up each decade:

> Crawl into a container. Walk over to a new computer. Run in the cloud.

Process → container → cloud workload → **conversational context over agent
harnesses**. Each step made the *substrate* fungible and the *workload* the
durable thing. The mesh is that step for agent conversations; ratcheted
properly it ends somewhere a marketing person will eventually name
("commodity intelligence").

## The design laws this binds

1. **The routing key is the identity (fingerprint), never a location.** A
   `SocketAddr` may only ever be a *candidate path* to an identity — one of
   several, tried in a race. No reply, request, or session may depend on
   exactly one address being dialable.
2. **Candidate sets, not single addresses.** Any dial derives a set: the
   request's source path (with its `recvmsg` scope_id preserved so link-local
   is actually dialable), loopback for same-host, mDNS-announced addresses
   when the peer announces, direct-dial hints when configured. Losing any one
   path must not lose the identity.
3. **A quiet peer is still an identity.** `announce: false` reduces the
   candidate set; it must never reduce it to *zero* usable paths. The
   dial-back path exists precisely for identities that choose invisibility.
4. **Conversations outlive locations.** Session/conversation primitives (the
   session-streams ADR) attach to fingerprints. A peer that re-binds, roams
   hosts, or changes address mid-conversation is the DESIGNED case, not an
   edge case.

## The case study that forced the articulation (#61)

PR #21 made replies dial the request's **source socket address** — pinning a
reply to a location. On CI (and most Linux hosts) that source is a scopeless
link-local IPv6, undialable → `sendmsg InvalidInput` → for a quiet-bind peer
(mDNS-invisible) the reply was simply lost.

The empirical results read exactly as the thesis predicts:

- **Adding candidate paths** (loopback beside the source) fixed the isolated
  case — the identity became reachable more than one way.
- **Removing the source path** regressed it — the quiet peer's only location
  was gone; the identity had no resolution at all.

Both experiments say the same thing: the bug isn't the bad address, it's the
**singular** address. `dial_reply_peer(pubkey, [one addr])` is the shape to
retire, not patch.

## What this means for reviewers

- Reject single-address dial paths; require candidate-set resolution keyed by
  fingerprint.
- Treat "works on my LAN" as insufficient: link-local scope, CGNAT, roaming,
  and quiet peers are the normal world for a floating identity.
- Prefer changes that move state *toward* the identity layer (session streams,
  conversation contexts) and *away* from transport specifics.
- The ratchet direction: every release should make the harness more fungible
  and the conversational context more durable.

## Related

- Issue #61 / PR #62 — the dial-back diagnosis + stepping-stone candidate.
- `docs/decisions/session_streams.md` — conversations as mesh primitives
  (the workload the identities carry).
- newt-mobile — mesh-first client: a phone as a caveat-limited mesh peer is
  this doctrine's proof case (identity persists across radio/network churn).
