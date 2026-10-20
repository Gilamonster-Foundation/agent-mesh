---
name: flock
description: What an agent-mesh flock is (a signed channel and roster for a team of agents), its roles, events and board, and which parts exist today versus planned. Load when working on or with `amesh flock`, the flock crates, or the flock epic (#109).
---

# Flock

Source of truth: [`docs/decisions/flock.md`](../../docs/decisions/flock.md). This
page is a map; it links rather than restates.

## What it is

A flock is a **signed, append-only event log plus a roster** for a team of
agents working one project. One home server owns the log; every event is named
by its content ID and the channel carries content IDs, never file bodies. The
mesh carries, admits and stores events. It decides nothing: dispatch, review
policy and merge gates stay in the
[herdr-flock skill](https://github.com/hartsock/shepherds-pi/blob/main/skills/herdr-flock/SKILL.md).
Lane files stay plain text on disk; events cite them by content ID.

## Roles and events

Roles: **operator**, **shepherd**, **reviewer**, **helper**, **adapter** (the
herdr bridge; it can nudge and report status but never `ack`).

A lane goes through: `brief` (shepherd) → `ack` (addressee) → `result` (addressee)
→ `review` (shepherd) → `verdict` (reviewer). Also `ask` / `answer` (operator
signs the answer), `job` / `job-end`, `status`, `nudged` and `nudge-misfire` (the adapter only; each may cite, as `of`, the brief or review it was about, and then the target must be that work's addressee; neither closes or acks anything), `roster` (server or
shepherd), and server-signed `epoch`, `renewal`, `session-*`, `handoff`, `invite`.

The **board** is a fold over the log in admission order, so every reader gets
the same board. A brief is `submitted`, `working` (acked), `input-required`
(open ask) or `completed` / `failed` (result). A second closer is logged as
`conflict`; corrections append, never edit. The signer table and admission
checks are in the decision doc ("Admission").

## Keys, sessions, epochs

The server key is minted by `amesh flock init`. Each harness session gets a
random key certified by the server and bounded to the current **epoch**; the
server bumps the epoch whenever authority shrinks (session ends, hand-off,
member removed), so a dead session is visible in the log itself. A replacement
session starts pending and can sign nothing until a hand-off activates it.

## Built vs planned

Built (plan steps 1–4, 4c read-only herdr view, 4d operator devices):
- the detached author `Assertion` (`agent-mesh-protocol`);
- the `agent-mesh-flock` model crate: schema, admission table, board fold, and
  real `invite`, `session-start`, `session-end`, `epoch` and `renewal` bodies;
- `agent-mesh-flock-server` (init, signed log, admission, recovery; the epoch
  counter is signed into each admission and verified on replay) and
  `amesh flock init`;
- server API for **invites and enrollment** (`invite`, `enroll_begin` /
  `enroll_finish`: a digest-only invite, a server-minted possession challenge,
  token and challenge consumed with `session-start` in one transaction);
- the **log-derived session resolver**: who may sign comes from replaying the
  log in order, and a session must present a certificate the log recorded for
  it, never a peer-issued one;
- **end-driven epoch bumps**: `end_session` writes `session-end` and `epoch`
  as one frame, enforced at admission and on replay;
- **renewal**: the renewal exchange after a bump and the `renew` entry for a
  session that missed bumps, each logged with its certificate. A member's
  later sessions start pending;
- **hand-off**: `handoff(approval, sig)` on a single-use approval bound to
  `{flock, member, from, to, resume, context}`; `context` (the `HANDOFF.md`
  file ref) is required. Signed by an active shepherd for a helper, or by a
  **listed operator device** for a shepherd; reviewer, adapter and operator
  members are refused, and so is a key merely certified by the user key but
  not listed. One
  frame: `handoff` ends `from`, activates the pending `to` and is followed by
  the `epoch` bump. The new session's first event must have `prev = handoff`;
  only a member's current holder can be handed off, so competing hand-offs
  yield one winner;
- **`amesh flock serve`** (owns the log; socket `<flock>/run/serve.sock`, dir
  0700, socket 0600), **`amesh flock invite`**, and **`amesh flock session`**
  (an ssh-agent-style process: the session key lives only in its memory,
  `mlock`ed, core dumps off, zeroized on exit; it serves the CLI over a 0600
  socket; the token comes from `AMESH_FLOCK_TOKEN`). A session's connection is
  its life: a drop without goodbye (`kill -9`) is recorded `lost`, and the
  epoch bump leaves its key uncertified. `mlock` denied means the session
  refuses to start, unless `--allow-unlocked`. The sockets keep out other Unix
  users, not other harnesses under the same account (agent-bridle's job). The
  CLI commands that use it are below (step 7a). Unix only.
- **operator devices**: an operator member in the roster carries `devices`
  (fingerprints of keys the user key certified). The check is "chains to this
  flock's user key" **and** "listed in the roster at that point in the log", so
  a removed device can't approve later, and an earlier hand-off still replays.
  Devices change only in a server-signed `roster` event (`replace_roster`) or
  genesis; a shepherd's roster must leave them as they are. Operator members
  only. Rosters without devices encode as before;
- **operator `answer` verification** (step 13b; the verifying side only, there is
  no signer or `amesh flock answer` yet): an `answer` is accepted when its
  signature chains **directly** to the flock's user key (assertion domain, valid
  generation), its author is that device, the device's certificate was
  **registered** in the log (`Server::register_device`, a server-only
  `device-cert` event holding the existing `CertChain`, kept after removal), and
  the roster lists the device at that index (`NotAListedDevice` otherwise). The
  same check runs at admission and on replay, so a revoked device is refused now
  while its earlier answers still verify, and a logged answer whose certificate
  is missing fails replay. Registration grants nothing; an indirect or
  other-user certificate cannot be registered. `Req::Admit` already carries the
  caller's signature unchanged, so an externally signed answer is admitted as-is
  and never re-signed by a member key. A `relayed-answer` is a member's copy and
  closes nothing; a second `answer` is a `SecondCloser` conflict;
- **the delegate** (step 13a): at most one roster member has `delegate: true`
  (the member that holds the operator's screen; omitted from the encoding when
  false, so every existing id is unchanged). It is set only by a server-signed
  `roster` (`replace_roster`) or genesis; a shepherd's roster must leave it as it
  is (`DelegateLocked`), and two delegates are refused (`MultipleDelegates`).
  The delegate's hand-off needs a **listed operator device** approval whatever
  its role, checked before the shepherd-approves-helper rule, so a shepherd
  cannot approve its delegate's replacement. Approvals are judged at their own
  index on replay. The delegate gains no operator authority. No signing gesture
  or `answer` yet (13b/13c);
- **the operator's answer signer** (step 13c): `amesh flock device-init`
  (terminal, passphrase twice) mints a device seed certified directly by the
  user key and stores it **age-encrypted** (scrypt passphrase, armored, `0600`
  in a `0700` directory); `device-register` sends the certificate to the owner
  socket (`Req::RegisterDevice`, never offered on the attach socket), and the
  roster must still list the fingerprint under the operator. `amesh flock sign`
  is a separate foreground process that **refuses to start unless stdin is a
  TTY**. `amesh flock answer --ask <cid> --text ...` sends it one typed request
  (flock, ask, text): the signer re-reads the verified log, refuses another
  flock, a non-ask, an already-answered ask or an empty/oversized text **before
  any prompt**, shows flock, ask id and text (escaped), lane and the exact
  answer on `/dev/tty`, and only on `y` asks for the passphrase there (no env
  var, no flag), signs that one event id, drops the key, and admits it as-is.
  Each untrusted field (ask text, lane, answer) is escaped on its own, so none can forge the signer's headings; the passphrase prompt turns echo off before it appears. `device-init` refuses an existing device directory that others can enter. The terminal paths are tested through the production binary on a pty. There is no "sign these bytes" request and no blanket consent. An agent
  never holds the key. **Limits:** the signer socket and files are `0600`,
  which keeps out other users, not a process of the same user that can read
  your terminal, ptrace the signer or replace the binary; the passphrase is
  only as strong as you make it. A test-only auto-confirming UI exists behind
  the `test-ui` feature, which no default build or binary path names;
- **byte strings**: keys, signatures, fingerprints and nonces are CBOR byte
  strings in the canonical encoding and on the session wire (they were arrays of
  one integer per byte: about 22% larger frames, and a size that varied with the
  key's bytes). JSON paths are unchanged. This changed every record id, so a
  flock created before it cannot be opened, and `init` will not reuse its
  directory (it refuses an existing `server.key`, genesis or log): create a new
  flock in a fresh directory, or move the old one aside first. Release note for
  agent-mesh-protocol: the Rust API is unchanged, its CBOR encoding is not (minor
  bump);
- **cited certificates**: a stored or streamed event carries its signature only.
  The certificate it was signed under is the one the server-signed
  `record.cert` names, and both are already in the log: the server's in genesis,
  a session's in its `session-start` or a `renewal`. A reader holding the log up
  to that point resolves it; a record citing a certificate the log does not hold
  is refused, and the certificate must still be one recorded for the event's
  author at the record's epoch. Event, record and certificate ids did not change.
  A brief frame went from 1699 to 543 bytes. The request an event arrives in
  (`Admit`) still carries its chain, and a hand-off's operator-device approval
  keeps its inline chain (that certificate is not in the log). Flocks made before
  this cannot be opened either: new flock, fresh directory;
- **the attach socket** (`amesh flock serve --attach`, Unix): a second socket,
  `run/attach.sock` (mode 0600, private directory), the surface a remote host's
  bridge connects to (step 9b, below). Without
  `--attach` nothing remote can reach the flock. On it only these requests are
  offered: `Hello`, `Genesis` (the public genesis node; its hash is the flock
  id, which a remote attacher checks against the id it was given), enroll,
  renew, `Head`, `Admit`, the stream challenge and `Watch`, and goodbye. Minting
  an invite stays on the owner socket; the attach socket answers "not offered on
  the attach socket". The list has one arm per request and no wildcard, so a new
  request cannot be added without deciding whether a remote host may make it.
  Whoever is on the far end still proves membership the usual way (invite token,
  possession proof, a signature over a fresh challenge bound to flock and
  connection). v1 attaches same-user hosts only: the host-to-host handshake
  (the bus's auto-team rule) requires both hosts to belong to one user;
- **roots and the cited-file service (step 9c)**, Unix. A roster event may carry
  `roots`: the *names* of directories members cite files from (never a path;
  empty roots are not encoded, so every existing id is unchanged). Only a
  server-signed roster changes them, like operator devices (`roots-locked`),
  and names are 1-64 of `A-Za-z0-9._-`, not `.`/`..`, unique (`bad-root`). The
  home host maps name to directory in its own flag, `amesh flock serve --root
  name=path` (repeatable; the directory must exist; naming a root the roster
  lacks has the server declare it), so no path is ever in the log. A connection
  proves membership (`WatchBegin`, then `Prove` with the same signature a
  `Watch` carries) and may then ask `FileStat{root,path}` (what the file hashes
  to now) and `File{root,path,id}` (the bytes, **only if they still hash to
  `id`**; otherwise `ChangedSinceCited{current}`, reported and not served, or
  `Unavailable{reason}`: unknown root, outside the root, not a regular file,
  missing, too large). All three are on the attach socket's allow-list.
  Every request re-checks that the session is still an active one of a current
  member. The file is opened by `Beneath` (the same helper the TUI's drift
  check uses): the root is opened once and the path is resolved relative to
  that descriptor, on Linux by `openat2` with `RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS`, elsewhere by a component walk with `O_NOFOLLOW`, so
  there is no checked pathname for a swapped directory to make stale. An
  absolute path or `..` is refused before the file system is touched; **every**
  symlink on the path is refused, a link that stays inside the root too;
  mounts and hard links are part of the tree. The open does not block (a fifo
  cannot hang the server), and the opened file must be a regular file within
  one message (`MAX_FILE`, a little under 1 MiB; chunking is later).
  **Limit:** the root is opened by its path, so replacing the mapped
  directory (or an ancestor) before it is opened is the owner's own mapping
  changing. On the reader side
  (`agent_mesh_flock_session::Files`) the bytes are hashed again and must equal
  the cited id; a server that sends other bytes, bytes past the limit, or
  "changed" for the id that was cited is refused (`stat` is the server's word:
  the bytes are not sent). The TUI's drift column asks the server for any root
  the operator did not map with `--root` (so over a remote attach it asks the
  home host, through the proxy);
- **the bridge and `attach` (step 9b)**, Unix, same-user hosts only. `amesh flock
  serve --attach --bridge [--bridge-port N] [--bridge-quiet]` (the home host;
  needs `amesh keygen`) joins the mesh as a bus agent and serves a session
  stream per remote on topic `flock/<flock id>`; each stream is piped to the
  attach socket, so the allow-list applies and `Invite` is never offered
  remotely. It prints `bridge <agent fingerprint> <agent pubkey> <port>`.
  `amesh flock attach --dir D --id <flock id> --peer <pubkey>@<ip:port | fingerprint>`
  (the remote host, the same user's key) fetches the genesis, **refuses unless
  its hash is the `--id` you were given** (the id is the out-of-band anchor, like
  a fingerprint) and unless it verifies as a genesis, all in memory before
  anything is written. `D` must be a private directory (created 0700, or an
  existing one that is ours and closed to others) and is held by an exclusive
  lock while `attach` runs, so a second `attach` on it is refused. The genesis
  is kept as `D/genesis` through a fresh temporary file (fsync, rename, fsync
  of the directory); an existing pin for the same flock is left exactly as it is,
  one for another flock, a symlink or anything that is not a regular file is
  refused, never replaced. `attach` then serves `D/run/serve.sock`: every flock
  tool (`session`, `watch`, `join`, the TUI, a `Reader`) runs unchanged against
  `D`, one bus stream per local connection. The proxy holds no flock-member key
  (it does use this host's mesh identity, its user key's agent) and has no emit path; the wire is the
  server's own `Req`/`Resp`, one session message per wire message, and a body
  that is not exactly one wire message (up to 1 MiB) is dropped with the
  connection. Enrolling uses a token the owner mints at home; the key is made
  and stays on the remote. A session that was quiet across epoch bumps renews
  through the proxy; two flocks at different epochs (one topic each, on one bus
  on each side) do not touch each other. Today each session stream is its own
  QUIC connection; nothing is shared between streams, and the tests do not
  claim a single carrier. A connection that
  drops without goodbye is recorded `lost` at home as before. What the bus
  handshake proves is only that the two hosts belong to the same user; the
  proofs above (token, possession, a stream signature) are what admit a member.
  `--peer <fingerprint>` finds the home by mDNS; `pubkey@addr` dials directly.
  Open streams are counted before anything is connected: at the home, in all
  (default 64) and per peer (default 16), a stream over its share is refused
  ("too many open sessions") without touching the attach socket; the proxy caps
  its local connections the same way (an excess connection simply ends) and
  tracks its tasks, so capacity returns when a stream ends, fails or is
  cancelled. A held-open but idle admitted stream keeps its place until its
  peer closes it (no application-progress deadline yet). A place is held until
  the home's backend connection has really closed, not only until the bridge is
  done: the server watches each watch's socket for its end and wakes the worker
  waiting for the next record, so a reader that vanishes ends its worker even
  when nothing is ever published; the server also closes a finished connection
  completely (it keeps no duplicate handle), which is what lets a place go back.
- **the attach suite over ssh (step 9d)**: the bridge is transport-agnostic (it
  takes any `Bus`), and `agent-mesh-cli/tests/flock_bridge_ssh.rs` runs the same
  scenarios as the iroh suite (remote enrol and emit, replay then live watch,
  renew after missed epochs, the refusals, a cited-file read) with both buses on
  `agent-mesh-transport-ssh` and a real loopback `sshd` between them (throwaway
  host and user keys, the host key pinned, forwarding only to the home's mesh
  port). A test fails if no ssh login was logged. Without OpenSSH installed the
  tests fail (a skip would show as a pass); `AMESH_SKIP_SSHD=1` skips them
  deliberately. CI installs sshd on Linux and runs the suite on macOS too. `amesh flock attach` and `serve --bridge` still
  dial iroh only: there is no `--transport ssh` choice, so ssh is proven at the
  library level, not by the CLI.
- **MCP tools** (`amesh mcp --flock-session <sock>` or `AMESH_FLOCK_SESSION`,
  Unix): `flock_whoami`, `flock_inbox`, `flock_status` and `flock_emit{kind,
  refs, body}` join the `mesh_*` tools, only when a session is given. The
  socket is fixed at startup, bound to its flock (a socket that is not a live
  session of the flock holding it stops the server), and no tool takes one. The
  tools hold no key and make no policy check: `flock_emit` is the same single
  `Emit` the CLI sends, so the session signs, admission decides, and a refusal
  (a non-addressee's `ack`, any server-signed kind) comes back as the tool
  error with the log unchanged;
- **`Snapshot`** (`agent-mesh-flock-server`): reads and replays the log with no
  lock and no repair, stopping at a torn tail, so it runs beside a live server;
- **`amesh flock panes --name <flock> [--tab <id>] [--map member=pane]`**:
  read-only. Joins the roster to `herdr pane list` (a member is the pane whose
  label is its name, within `--tab`; `--map` overrides) and prints herdr's
  claims next to the verified flock state. It only ever lists; it never
  prompts, sends keys or renames. Off-roster panes are never shown. A VIA
  column says how a pane was linked: `map`, `session` or `label`;
- **the pane claim** (`Kind::Pane`): a session started inside a herdr pane
  (`HERDR_PANE_ID` and `HERDR_TAB_ID` both set) signs a `pane` event naming it;
  `CtlReq::Announce` repeats it. It is a *claim*: the signature proves the
  session said it, nothing proves the pane is real or still that pane. `panes`
  trusts only the active session's latest claim, only if herdr still lists
  that pane (in `--tab`, if given), ranks it below `--map` and above a label,
  and a pane two members claim is `ambiguous`. A replacement session is
  pending; once a hand-off activates it, the server's answer to "what is my
  head?" is the hand-off until its first event, so it can announce and emit.
  A session's first event is checked the same way live and on replay: an activated replacement writes exactly the hand-off that activated it as `prev`; any other session writes no `prev` (it cannot chain onto a hand-off that was not its own).

- **`watch --from (index, signed head)`** (library, `serve` and the `amesh flock
  watch` command). One stream carries the replay, a `Caught` marker,
  then live frames, each exactly once: the server publishes a frame to a
  journal only after its fsync, and readers read the journal without the
  writer's lock. The resume token is the last signed admission record. The
  reader (`Reader`, in `agent-mesh-flock-session`) verifies every frame from
  its own saved head, so an older backup, a shorter history, or an altered
  prefix is refused as a `Rollback` whatever the server says; a server that
  forks different histories to different readers is not caught by one reader.
  The reader's state is one file (the verified frames) saved by write temp,
  fsync, rename, fsync directory; a head is witnessed only after that returns.
  A stream needs an *active* session of a *current* member signing a fresh
  challenge bound to the flock and the connection (a certified non-member, a
  pending or ended session, or a proof from another connection is refused),
  and it closes right after any epoch-bearing frame after which its session is no
  longer live or its member is no longer on the roster (a `session-end`, a
  hand-off away, or a roster change that drops a member). A `roster` that drops
  a name always carries its `epoch` in the same frame: the server's own roster
  path and a shepherd's roster event are sealed `roster, epoch`, and both readers
  (open/recovery and the follower) refuse a log where it is not. Adding members or
  changing devices or roles needs no bump. A request whose frame would not fit one
  stream message is refused (`TooLarge`) before it is committed, so every
  admitted frame can be watched. One reader per state directory (locked). Ceilings: the journal is in memory; the reader rewrites its
  whole file per save.

- **citing files from a brief or review (trial fix B1)**: `brief` and `review` take `--cite root:path` (repeatable) with `--root name=path` (the same mapping as `serve --root`). The CLI hashes the file itself under the mapped root (the session signs what it is handed, as it does the body) and the event carries the `FileRef {root, path, id}`, so the log shows the file the brief meant and the TUI Lane FILES column and `✓`/`⚠ changed since cited` have something to check. The id comes from `agent_mesh_flock_server::file_id`, the one rule the TUI's check uses too (regular files only, at most 64 MiB). The CLI refuses, before sending anything: a root the roster does not declare, a root declared but not mapped here, a malformed `root:path`, a path with `..` or an absolute one, any symlink on the path (an in-root link too), a missing file, a file that is not regular (directory, fifo), a file over the limit. A repeated cite is carried once. One bad cite among good ones sends nothing. Admission does not read cited files (it never has); a reader checks them.
- **the CLI, first half (step 7a)**, Unix only, every write through a session
  process (the CLI holds no key and checks nothing admission decides):
  `join [--announce]` (who is this session; its `state` is read from the log when a flock is named, the session's own `pending` is labelled as the enrollment-time flag), `inbox` (open briefs and reviews
  addressed to this session's member), `status` (lanes), `log [--from N]`
  (events with full content ids), and the writers `brief --to --lane`,
  `review --to --lane --head`, `take <cid>` (an `ack`), `result <brief>
  --outcome completed|failed`, `verdict <review> --head --approve|--reject`.
  The session is `--session <socket>`, else `AMESH_FLOCK_SESSION`, else the one
  live `run/session-*.sock` in `--dir`/`--name` (dead sockets skipped; none or
  several is an error that names them). When a flock is named, the session must belong to it (any selector; a session of another flock is refused before anything is sent); with none named the session alone decides. Reads replay the log without its lock
  (as `panes` does) and do not check for rollback; only `watch` does.
- **`run` and `watch` (step 7b)**, Unix only. `run --lane L [--label T] --
  <cmd>` emits a `job`, runs the command with inherited stdio, emits a `job-end`
  and exits like a shell (128 + signal). A `job-end` carries exactly one of
  `code` (it exited) and `signal` (a signal ended it): explicit fields, each
  skipped when absent so the exit-code form keeps its pinned id; admission
  refuses neither or both (`BadExit`). A command that cannot start is recorded
  as exit 127; but once the command has started, a failed wait writes no
  `job-end` (its outcome is unknown) and the job stays open, as it does if the
  `run` process itself is killed. `watch [--from N] [--once]` follows the log through a
  `Reader` kept in `<flock>/watch/<id>/` (the content id of the member's name,
  never the name itself as a path; both directories must be the user's own and
  closed to others, or the watch is refused): each frame is verified against
  the saved head, saved, and only then printed, so a run shows only what is new
  to that reader (`--from` also replays saved events from an index; `--once`
  stops at the `-- caught up --` marker). The stream challenge is signed by the
  session (`CtlReq::ProveStream`, only for its own flock, after renewing its
  certificate to the current epoch), so the CLI holds no key. A closed stream is an error exit with the server's reason.

- **read-side features (step 8a)**: `agent-mesh-flock-server` has a `serve`
  feature (the `Server`, entry/enrollment, sockets, key file, log writer and
  journal) and `agent-mesh-flock-session` an `emit` feature (the session
  process, its locked key, `CtlReq::Emit`/`Announce`). Both are on by default
  and nothing else changes. Without them the crates still verify and follow a
  log: `Snapshot`, `Follower`, `Reader`/`Watch`, `session_prover` (the
  `ProveStream` client) and the types. The workspace entries are
  `default-features = false`, so a member that writes asks for the writer
  (the CLI does); a read-only member (the TUI, step 8b) takes them as they
  stand. With both off, no signing or mutating API resolves for a consumer:
  `seal`, `RefusalEntry::sign`, `Server`, `init`, `Session`, the request
  variants `Invite`/`EnrollBegin`/`EnrollFinish`/`Renew`/`RenewFinish`/`Head`/
  `Admit`/`End` and `CtlReq::{Emit, Announce, End}` are all gated, and the held-key
  `key_prover` lives only in test code. What stays is verify, follow and watch
  (`Snapshot`, `Follower`, `Reader`/`Watch`, `session_prover`, the stream
  requests, `read_msg`/`write_msg` as plain framing). The session's proof
  renews its own certificate first (intended). `read_side_api.rs` proves it by
  compiling a scratch consumer (writer APIs must fail, the same lines must
  compile with the writer on, the read API must compile), and
  `agent-mesh-flock-session/tests/read_side.rs` enforces the feature names from
  `cargo tree -p … --format "{p}|{f}"` (per-package resolution; `cargo
  metadata` unifies features across the workspace and would always see the
  CLI's).

- **`amesh-tui` (step 8b)**, Unix only, a separate crate (`agent-mesh-tui`, bin
  `amesh-tui`): a read-only terminal view. `amesh-tui --dir <flock dir> --session
  <session socket> [--once]` follows the log through a verified, saved `Reader`
  (state under `<flock>/tui/<id of the member's name>/`, private to the user);
  the stream challenge is signed by the session (`ProveStream`), and the view
  holds no key and has no emit path. A session of another flock is refused
  before anything is read. The model is a pure fold of the verified log
  (`model.rs`); views are newtui components over it. Built: the header (flock,
  id, member count, `log ✓ N`, epoch, `live` / `stale since #n` / `✗ reason`) and
  the **Board** (each roster member: role, session state from the log, its own
  latest `status`, open work: jobs without a `job-end`, lanes briefed to it still
  submitted or working, unanswered asks; events since it last wrote). Not shown,
  because the log has no record of them: model, the herdr status tier (step 10),
  the delegate line (step 13), and refused events (`!`), which live in the
  server's refusal chain, not on the stream (said in the footer). `--once` prints
  one frame as text. Proofs: golden text screens (`UPDATE_SNAPSHOTS=1` rewrites),
  newtui's explorer (selection in range; no key changes the displayed data), a
  real server and session feeding the model, and the same cargo-tree and
  compile-probe checks as the read side (`tests_common::readside`) run against
  the TUI: neither writer feature resolves and no writer API can be named by a
  consumer of the crate. The Board scrolls to keep the selected member on screen (header and footer fixed). A frame whose checkpoint cannot be saved is rolled back by the reader itself (`Reader::follow` keeps nothing it did not save, and `Reader::open` makes a checkpoint it finds durable (file and directory fsync) before showing it, or does not open: a rename left visible by a failed directory fsync is never presented as saved until it will survive power loss), so the view and `amesh flock watch` only ever show the saved prefix; the TUI header says `cannot save the checkpoint` and keeps the last saved state. **Stream (step 8c)**: a second tab (`Tab`, or `1`/`2`) lists every admitted event in order (index, kind, signer, lane, one-line summary; conflicts marked) with kind / lane / member filters (`k` `l` `m` cycle through what the log has and back to all, `c` clears) and a follow mode (on at the start; moving up leaves it, `f` or `End` returns). An event's lane is its own or that of the event it answers. `Enter` opens the raw view: id, "✓ signature, session certificate and admission checked", signer (member and session fingerprint), lane, claimed time, parents (`prev` then references, numbered; `1`-`9` jump to one, `Backspace` returns; a filter that hides the parent is cleared), cited files and the pretty-printed body. Everything is folded from the verified board; nothing is fetched or checked again, and the event list is shared and extended between models. Everything drawn passes one function, `inert` (`ui/inert.rs`), which spells out control characters (C0 including ESC/BEL/CR/TAB, DEL, C1 including U+009B, and line/bidi/zero-width controls) as `\x1b`, `\r`, `\x9b` ...: a signature says who spoke, not that the text is safe to print, so a member's status, lane, label, file path or name cannot send the operator's terminal a command (tests: the screens carry no control character, and the bytes sent through a real crossterm backend carry only the renderer's own escapes). A signer is shown as member and session, with no role (the log knows only today's roster). The CLI shares that boundary (`agent_mesh_flock::text::inert`, which the TUI re-exports): `amesh flock log`/`watch`/`inbox`/`status`/`panes`, the MCP tools' errors and the final error printer escape member-authored text the same way, field by field, so a name with a newline cannot forge a row; the nudged and nudge-misfire summaries escape their target too. **Lane (step 8d)**: a third tab (`3`; `Tab`/`BackTab` cycle all three) lists each lane with its latest attempt (`completed, job open` verbatim from the fold), how many older attempts it has and one mark per cited file; the selected lane shows its older attempts, conflicts aimed at an attempt, its reviews and verdicts (head, and `newer result since #n` when the lane has a later non-conflict result: the reviewed head may be stale; the flock cannot see git, so this is the author's head against the log's order) and every file its events cite, first cited first. **Changed since cited**: `--root name=path` (repeatable, home-local; the roster declares no roots yet) maps a cited root to a directory; each file is opened **beneath** it with no pathname re-resolution (`agent_mesh_flock_server::Beneath`: the root is opened once and the file is opened relative to that descriptor, on Linux by one `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, elsewhere by a component walk of `openat` with `O_NOFOLLOW`, so a directory swapped for a link after a check cannot lead out; a path with `..` or an absolute path is refused before the file system is touched; **every** symlink on the path is refused, one that stays inside the root too, which shows as `?`; mounts and hard links are not links, and `NO_XDEV` is not set; the open does not block on a FIFO), read (at most 64 MiB, never written, created or touched) and hashed with the same raw content id: `✓` equal, `⚠ changed since cited` (cited and current ids shown), `?` unavailable with the reason (root not mapped, path leaves its root or crosses a link, file missing or unreadable, not a regular file, too big), `…` not checked yet. Files are checked on a worker thread, again when the log cites something new or on `r`; `amesh-tui --once --tab lane` checks synchronously. Everything drawn still passes `inert` (lane, root, path, head). **Waiting (step 8e)**: a fourth tab (`4`) lists what waits for someone, oldest first, with its age in events (events admitted since) and the member it waits on: asks nobody answered (waiting on whoever briefed the work they are about; a file the ask cites is named as `[draft: root/path]`, not read), reviews with no verdict (waiting on the reviewer), and briefs nobody has taken (a lane's latest attempt still only submitted; waiting on the addressee). It answers nothing and has no way to: it is read-only like the other views. All four views (Board, Stream, Lane, Waiting) are built; everything drawn passes the shared `agent_mesh_flock::text::inert`.

- **nudge records (step 10a)**: `nudged{target}` and the new `nudge-misfire{target, expected, found}` are signed by the herdr adapter's session only. Each may cite `of` (a brief or review); if it does, `target` must be that work's addressee, and `target` must be on the roster. `expected`/`found` are the adapter's own short, printable descriptions of the pane it chose and the pane it found after prompting (a claim, like `pane`). Neither closes the work or counts as receipt, so a nudged brief still shows as submitted until its addressee acks. The nudge adapter itself (`amesh flock nudge`) is 10b/10c; this is only the record it will write.
- **the nudge sequence (step 10b)**: `HerdrControl` (`herdr.rs`) runs exactly `pane list`, `agent get <pane>`, `agent wait <pane> --timeout <ms>` and `agent prompt <pane> <text>`; the read-only `Herdr` is unchanged, and no `send-keys`, `pane run`, `focus` or `rename` exists. A pane id from herdr goes on a command line only if it is 1-64 of `A-Za-z0-9:_.-` and does not start with `-`. The target is the roster-to-pane mapping (`--map`, then the active session's latest `pane` claim if herdr still lists it, then the label), and a nudge is **refused**, with a `status` and no wait or prompt, when: the member is not on the roster or is the operator or an adapter; the adapter cannot identify its herdr (`$HERDR_PANE_ID` unset, or not in the pane list); there is no pane, or two; `--map` names a pane herdr lacks; the session's claimed pane is gone (no quiet fall back to a label); the pane is the one the command runs in; the tab, workspace or pane is on the deny list; or an allow list is set and the pane is not on it. Every pane that is or may be the operator's or an adapter's is protected, independently of whether their own mapping came out unambiguous: each pane carrying their label, and each pane `--map` or their session's claim names. A helper mapped or claimed onto one is refused (a duplicate operator label does not free its candidates). The sequence: identify (pane, tab, label, agent kind, name, terminal id) -> `agent wait` with no target state, so herdr settles on `idle`, `done` or `blocked` (`--wait-timeout`; a timeout or failure gives up with a `status`, no retry) -> look again and stop, unprompted, if the mapping or the identity changed, or the state is not `idle` or `done` (`done` is an agent that finished its turn, as ready as `idle`; `blocked` is a `status`, never a prompt) -> `agent prompt` by pane id with the fixed text `amesh flock take <cid>` (nothing else is interpolated; a prompt error or `agent_prompt_stalled` is "not delivered", no `nudged`) -> look once more: the same identity is `nudged`, anything else (or an unreadable pane) is `nudge-misfire` with the expected and found identities (the full identity is compared, Debug-quoted so herdr text cannot forge a separator; the emitted `expected`/`found` are inert, never empty and at most 128 bytes, cut on a character boundary with `…`, which is what admission requires of a `nudge-misfire`). It returns what to emit (`Nudged`, `Misfire` or `Status`, all inert); it emits nothing. The window between the last look and the prompt remains: herdr has no "prompt only if idle". Lists: `<home>/herdr-nudge.deny` and `.allow` (one `tab:<id>`, `workspace:<id>` or `pane:<id>` per line, `#` comments; a line it does not understand is an error, never skipped) plus flags; local, never in the log; a workspace is the `workspace_id` herdr reports for the pane; where it reports none, a workspace deny rule treats the pane as covered (fail closed) and a workspace allow rule does not admit it. Tests use a scripted runner only, never the real herdr.
- **`amesh flock nudge` (step 10c, Unix)**: `amesh flock nudge --dir D --session S [--wait-timeout SECS (120)] [--map member=pane]... [--deny E]... [--allow E]... [--once]`, run as the **adapter** member's session (its role is read from the verified roster once the replay is caught up and again on every later frame, so a member promoted after genesis may act and a demoted one stops, with exit status 1, before herdr is touched). It must run inside herdr: `$HERDR_PANE_ID` is its own pane and must be in herdr's list. It follows the verified log (same `Reader` and session prover as `watch`, its own state under `<dir>/nudge/<id of the member name>/`; this process holds no key) and, only once the replay is caught up, nudges each `brief` or `review` addressed to a roster member who is not the operator or an adapter and has nothing to show it was handled: no `ack`, `nudged` or `nudge-misfire` citing it (`of`), and for a brief no `result`. Each pending event is tried once per run, in admission order (no timers, no retries). The outcome is emitted through the session's `Emit`: `nudged{target}` or `nudge-misfire{target, expected, found}` citing the event as `of`, or a `status` ("not nudged: <member>: <why> (of <cid>)", no citation). Dedupe is derived from the log, so a restart (or lost reader state, which replays everything) never nudges a recorded event twice; but a refusal or timeout leaves only a `status`, so a restart tries that event once more. A first run on an old log nudges every old unhandled brief or review. Output is one line per event (`Nudged of <cid>: admitted <id> at <n>`); an emit the session or admission refuses prints `not recorded` on stderr and is not retried. `--once` handles what is pending at catch-up and exits. Tests: real server, sessions and binary with a fake `herdr` script first on `PATH` that logs every argv (never the real herdr): the nudge cites the brief and the prompt is exactly `amesh flock take <cid>`, a restart or an ack stops more, a status for no pane, a misfire when the occupant changes under the prompt, deny list and file, a non-adapter session, outside herdr, `--map` and a session's pane claim, a live (non-`--once`) run takes new events and tries each once.

**Planned, not built:** operator approval of a **delegate**
hand-off (#127's other half; waits on the delegate designation, step 13); device changes
signed by a listed device (server-signed only today); operator-signed events (`answer`); the rest of
the CLI's `answer`; `amesh-tui`; the
`amesh-herdr` adapter beyond the read-only view and `nudge` (status tiers); native
newt receive. Until they land, lanes run on files
as the herdr-flock skill describes. Status: epic #109.

## Keep this current

Each flock step that changes behaviour updates this skill in the same PR.
