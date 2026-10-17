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
the same user; that boundary is agent-bridle's. Between enrollment and the
first lock the fresh seed is on the stack for a few calls; after a renewal the
new key is locked as well. Unix only: elsewhere the crate is empty.
