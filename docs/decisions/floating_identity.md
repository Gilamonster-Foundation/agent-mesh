# Floating identity — locations are candidates, never load-bearing

**Status:** accepted doctrine (Shawn, 2026-07-14; articulated on #62 while
diagnosing #61). Binds design review: making a socket address load-bearing for
reaching an identity is wrong by construction, even when tests pass.

## The thesis

The mesh exists so **identity floats**. Agent harnesses are fungible substrate
— containers for conversational context; the context is the durable workload
that floats over them. Keep the workload addressable by *who it is*, never
*where it ran*.

## The design laws this binds

1. **The routing key is the identity (fingerprint), never a location.** A
   `SocketAddr` is only ever a *candidate*, tried in a race. Nothing — reply,
   request, or session — may depend on one address being dialable.
2. **Candidate sets, not single addresses.** Every dial derives a set: the
   source path (with its `recvmsg` scope_id preserved so link-local dials),
   loopback for same-host, mDNS addresses when announced, direct-dial hints
   when configured. Losing one path must not lose the identity.
3. **A quiet peer is still an identity.** `announce: false` shrinks the
   candidate set but never to zero; dial-back exists for identities that
   choose invisibility.
4. **Conversations outlive locations.** Session primitives (the session-streams
   ADR) attach to fingerprints. A peer that re-binds, roams hosts, or changes
   address mid-conversation is the designed case, not an edge case.
5. **First contact is a ceremony, not an assumption.** Keyless first contact
   is a TOFU "leap of faith" open to MITM — RFC 7401's own admission, and the
   one failure mode of key-as-identity systems with primary-source backing. A
   fingerprint's key is learned over a verifiable channel or an explicit
   pinning ceremony. The mesh exposes the introduction as data; the consumer
   renders the ask (#65).

## Case study (#61)

#21 dialed replies at the request's **source socket address**, pinning a reply
to a location. On CI (and most Linux hosts) that source is a scopeless
link-local IPv6 → undialable → `sendmsg InvalidInput` → a quiet-bind
(mDNS-invisible) peer's reply is lost.

The experiments matched the thesis:

- **More candidate paths** (loopback beside the source) → isolated case passed.
- **Dropping the source path** → regressed; the quiet peer's only location was
  gone.

The bug is the **singular** address, not the bad one.
`dial_reply_peer(pubkey, [one addr])` is the shape to retire, not patch.

## For reviewers

- Reject single-address dial paths; require fingerprint-keyed candidate sets.
- "Works on my LAN" is insufficient — link-local scope, CGNAT, roaming, and
  quiet peers are the normal world here.
- Prefer state moving *toward* the identity layer (sessions, conversations),
  *away* from transport specifics.
- Ratchet direction: each release, more-fungible substrate and more-durable
  context.

## Prior art

This doctrine re-derives ~30 years of loc/ID-split and Zero Trust canon —
cite it, don't reargue it:

- Saltzer, RFC 1498 (1993): an address is a mutable binding to a location,
  categorically not the identity.
- HIP, RFC 7401 / RFC 9063: identity = public key; the HIT (hash of the key)
  is its self-certifying fingerprint; IPs are disposable locators transport
  associations migrate across. Also the TOFU admission behind law 5.
- NIST SP 800-207, Tenet 2: "Network location alone does not imply trust."
- SPIFFE: workload trust from a signature chain, never from topology.
- iroh: "IP addresses break, dial keys instead" — addresses as raced
  candidates, the model law 2 ships.

## Related

- Issue #61 / PRs #62 (diagnosis), #64 (fix); #65 (first-contact and other
  decision surfaces as data, never TUI).
- `docs/decisions/session_streams.md` — conversations as mesh primitives.
- newt-mobile — mesh-first client: a phone as a caveat-limited mesh peer,
  identity persisting across radio/network churn.
