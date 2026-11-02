# agent-mesh-flock-session

The process behind `amesh flock session`, in the manner of `ssh-agent`.

- It generates a session key, enrolls with an invite token through `amesh flock
  serve`, and keeps the certified key only in memory: `mlock`ed (it refuses to
  start if it cannot, unless told `--allow-unlocked`), `RLIMIT_CORE` zero,
  non-dumpable (`PR_SET_DUMPABLE`; `PT_DENY_ATTACH` on macOS), scrubbed by the
  key's own drop. `SIGTERM`/`SIGINT` end it cleanly; `kill -9` is the case the
  design accepts, and the server records it `lost`.
- It serves the CLI on a 0600 socket in a 0700 directory, one request per
  connection (`Whoami`, `Emit`, `End`, in `ctl.rs`). The CLI never sees the key;
  the session builds, signs and submits the event.
- The wire is the server crate's (`wire.rs`): length-prefixed canonical
  dag-cbor of the protocol's own types. Nothing here has an identity of its own.

The socket keeps out other Unix users. It does not keep out other processes of
the same user; that boundary is agent-bridle's.

Enrollment locks memory first (it refuses to go on if it cannot), generates the
seed straight into the locked allocation, and only then talks to the server;
renewal rebuilds the key from that locked seed. What is not locked: the key
struct is briefly rebuilt on the stack to sign a challenge or to be boxed, with
no blocking call in between. Unix only: elsewhere the crate is empty.

`Reader` is the client side of `watch`: a verified prefix of a flock saved in one
file by write-temp, fsync, rename, fsync-directory (`Fs` makes each step
injectable), extended by `Watch` from its own head; it refuses any history that
does not extend that head, and a `Caught` marker that disagrees with its own
verified head. One `Reader` per state directory (an exclusive lock held for
its life).
`Reader::follow_on` takes a connection the caller owns, so a caller can stop a
blocked read by shutting its clone of that connection down.
