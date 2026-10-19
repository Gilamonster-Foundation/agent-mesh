# agent-mesh-tui

`amesh-tui` is a read-only terminal view of an agent-mesh **flock**: the signed
log and roster a team of agents works from. It shows each roster member's role,
session state, its own latest status, and the work open against it.

```
amesh flock session --dir <flock dir> --member <name> …   # prints the session socket
amesh-tui --dir <flock dir> --session <session socket>
amesh-tui --dir <flock dir> --session <session socket> --once   # one frame as text
```

`--session` can also come from `AMESH_FLOCK_SESSION`. The view reads the log
through a session process, verifies every event, and saves its place under
`<flock dir>/tui/`. It holds no key and cannot write to the flock: this crate
depends on the read side of the flock crates only, and its tests check that.

- Unix only (the flock server and session are Unix-only).
- Three views, `Tab` (or `1`/`2`/`3`) to switch: the **Board** (who is on the roster
  and what is open against them) and the **Stream** (every admitted event in
  order). On the Stream: `↑↓` select, `f` follow the newest event, `k` `l` `m`
  cycle the kind / lane / member filter, `c` clear them, `Enter` opens the raw
  view of an event (payload, signer, what was checked, its parents), `1`-`9`
  jump to a parent, `Backspace` goes back, `Esc` closes. The **Lane** view shows
  each lane's attempts and reviews and whether the files its events cite still
  have the bytes they were cited with (`--root name=path` says where a cited
  root is on this host; files are only read; `r` checks again). Waiting comes
  next.
- A closed stream shows the view as stale since the last verified event; it does
  not reconnect. Refused events are not on the stream and are not shown.

Part of [agent-mesh](../README.md). Licensed under Apache-2.0 (see
[LICENSE](../LICENSE)).
