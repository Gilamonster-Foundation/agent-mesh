# agent-mesh-flock

The pure model of an agent-mesh flock: the genesis and event schema (content-addressed
`MerkleNode` payloads), the admission table, and the board fold. No I/O, no async, no
clock, no server.

**Boundary.** This crate trusts its inputs. Callers must verify each detached
`Assertion` and certificate (at the current epoch) and resolve the signer's class and
session state (`Signer`) *before* calling `admit` or `Board::fold`. Nothing here
authenticates a signer.

See `docs/decisions/flock.md` in the repository for the design.

License: Apache-2.0.
