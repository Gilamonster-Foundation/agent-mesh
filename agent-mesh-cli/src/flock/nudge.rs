//! The herdr nudge, as pure code over a [`Runner`]: who may be prompted, and
//! the sequence that prompts them. It reads herdr and decides; it emits
//! nothing. The caller (step 10c) turns an [`Outcome`] into a session emit.
//!
//! herdr has no "prompt only if idle", and a pane's occupant can change
//! between any two calls, so the sequence is a best effort that records what
//! it saw: it identifies the pane, waits for it to settle (idle, done or
//! blocked), identifies it again and stops if anything moved or it is not
//! idle or done, prompts by pane id, and looks once more. If the
//! occupant changed across the prompt, the text may have gone to the wrong
//! agent, and the outcome is a misfire record rather than a nudge. The window
//! between the last look and the prompt remains; the prompt text is harmless
//! to a wrong recipient (acting on it needs that recipient's own flock
//! session).

use crate::herdr::{self, safe_id, Agent, HerdrControl, Pane, Runner};
use agent_mesh_flock::text::inert;
use agent_mesh_flock::{Member, Role};
use anyhow::{anyhow, bail, Result};
use content_addressable::ContentId;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

/// One line of a deny or allow list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Tab(String),
    Workspace(String),
    Pane(String),
}

impl Entry {
    fn parse(line: &str) -> Result<Self> {
        let (kind, id) = line.split_once(':').ok_or_else(|| {
            anyhow!(
                "'{}' must be tab:<id>, workspace:<id> or pane:<id>",
                inert(line)
            )
        })?;
        if !safe_id(id) {
            bail!("'{}' is not a herdr id", inert(line));
        }
        Ok(match kind {
            "tab" => Self::Tab(id.into()),
            "workspace" => Self::Workspace(id.into()),
            "pane" => Self::Pane(id.into()),
            _ => bail!("'{}' must start tab:, workspace: or pane:", inert(line)),
        })
    }

    /// Whether this entry covers `p`. A workspace is what herdr reports for
    /// the pane; when it reports none, `unknown` is the answer (a deny rule
    /// passes `true`, so what cannot be placed is treated as covered).
    fn covers(&self, p: &Pane, unknown: bool) -> bool {
        match self {
            Self::Tab(t) => &p.tab_id == t,
            Self::Pane(i) => &p.pane_id == i,
            Self::Workspace(w) => p.workspace_id.as_ref().map_or(unknown, |pw| pw == w),
        }
    }
}

/// Where a nudge may never go (deny, which always wins) and, when set, the only
/// places it may. Local to this host; never in the log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    pub deny: Vec<Entry>,
    pub allow: Vec<Entry>,
}

fn entries(text: &str) -> Result<Vec<Entry>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(Entry::parse)
        .collect()
}

fn read_list(path: &Path) -> Result<Vec<Entry>> {
    match std::fs::read_to_string(path) {
        Ok(text) => entries(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(anyhow!("read {}: {e}", path.display())),
    }
}

impl Scope {
    /// `<home>/herdr-nudge.deny` and `.allow` (a missing file is empty), plus
    /// the flag entries. A line that is not understood is an error, never
    /// skipped: a typo must not widen where a nudge can go.
    ///
    /// # Errors
    /// A file cannot be read or a line is not an entry.
    pub fn load(home: &Path, deny: &[String], allow: &[String]) -> Result<Self> {
        let mut scope = Self {
            deny: read_list(&home.join("herdr-nudge.deny"))?,
            allow: read_list(&home.join("herdr-nudge.allow"))?,
        };
        for d in deny {
            scope.deny.push(Entry::parse(d)?);
        }
        for a in allow {
            scope.allow.push(Entry::parse(a)?);
        }
        Ok(scope)
    }
}

/// Why a member is not nudged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not a roster member, or one that is never nudged (the operator, an adapter).
    NotNudgeable,
    /// The adapter cannot say which herdr and pane it is in.
    Unidentified,
    NoPane,
    Ambiguous(usize),
    /// `--map` names a pane herdr does not list.
    MapGone(String),
    /// The member's session claimed a pane herdr no longer lists.
    ClaimGone(String),
    /// The roster and `--map` disagree (a name that is not on the roster).
    Mapping(String),
    /// The pane this command runs in (the adapter's own).
    OwnPane,
    /// A pane that is, or may be, the operator's or an adapter's.
    Protected,
    Denied,
    NotAllowed,
    /// A pane id that is not safe to pass to herdr.
    UnsafeId,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNudgeable => f.write_str("not a member that is nudged"),
            Self::Unidentified => f.write_str("cannot identify this herdr session"),
            Self::NoPane => f.write_str("no pane"),
            Self::Ambiguous(n) => write!(f, "ambiguous pane ({n})"),
            Self::MapGone(id) => write!(f, "mapped pane {id} is gone"),
            Self::ClaimGone(id) => write!(f, "its claimed pane {id} is gone"),
            Self::Mapping(why) => write!(f, "mapping: {why}"),
            Self::OwnPane => f.write_str("the adapter's own pane"),
            Self::Protected => f.write_str("a protected pane (the operator's or an adapter's)"),
            Self::Denied => f.write_str("on the deny list"),
            Self::NotAllowed => f.write_str("not on the allow list"),
            Self::UnsafeId => f.write_str("a pane id that is not safe to pass"),
        }
    }
}

/// Who is nudged and what bounds it.
pub struct Target<'a> {
    pub roster: &'a [Member],
    pub member: &'a str,
    /// Each member's active session's last claimed pane (`panes::claims`).
    pub claims: &'a BTreeMap<String, String>,
    /// `--map member=pane`.
    pub explicit: &'a BTreeMap<String, String>,
    /// `$HERDR_PANE_ID`: the pane this command runs in.
    pub own_pane: Option<&'a str>,
    pub scope: &'a Scope,
}

/// The pane to prompt for `t.member`, or why none. One pane speaks for one
/// member (`join` calls two claimants ambiguous), so a pane that is the
/// operator's or the adapter's cannot also be a helper's. Pure: it looks only at
/// `panes`, and runs again on every fresh listing.
///
/// # Errors
/// A [`Refusal`].
pub fn resolve<'p>(t: &Target<'p>, panes: &'p [Pane]) -> std::result::Result<&'p Pane, Refusal> {
    let member = t
        .roster
        .iter()
        .find(|m| m.name == t.member)
        .filter(|m| !matches!(m.role, Role::Operator | Role::Adapter))
        .ok_or(Refusal::NotNudgeable)?;
    // we must be in the herdr we are asking: our own pane is in its listing
    let own = t
        .own_pane
        .filter(|id| panes.iter().any(|p| p.pane_id == *id));
    let own = own.ok_or(Refusal::Unidentified)?;

    if !t.explicit.contains_key(&member.name) {
        if let Some(claimed) = t.claims.get(&member.name) {
            if !panes.iter().any(|p| &p.pane_id == claimed) {
                return Err(Refusal::ClaimGone(claimed.clone()));
            }
        }
    }
    let mut effective = t.claims.clone();
    effective.extend(t.explicit.iter().map(|(k, v)| (k.clone(), v.clone())));
    let placed = herdr::join(t.roster, panes, &effective, None)
        .map_err(|e| Refusal::Mapping(e.to_string()))?;
    let pane = match placed.iter().find(|(m, _)| m.name == member.name) {
        Some((_, Ok(p))) => *p,
        Some((_, Err(herdr::Gap::NoPane))) | None => return Err(Refusal::NoPane),
        Some((_, Err(herdr::Gap::Ambiguous(n)))) => return Err(Refusal::Ambiguous(*n)),
        Some((_, Err(herdr::Gap::Gone(id)))) => return Err(Refusal::MapGone(id.clone())),
    };
    if !safe_id(&pane.pane_id) || !safe_id(&pane.tab_id) {
        return Err(Refusal::UnsafeId);
    }
    if pane.pane_id == own {
        return Err(Refusal::OwnPane);
    }
    if protected(t, panes).contains(pane.pane_id.as_str()) {
        return Err(Refusal::Protected);
    }
    if t.scope.deny.iter().any(|e| e.covers(pane, true)) {
        return Err(Refusal::Denied);
    }
    if !t.scope.allow.is_empty() && !t.scope.allow.iter().any(|e| e.covers(pane, false)) {
        return Err(Refusal::NotAllowed);
    }
    Ok(pane)
}

/// Every pane that is, or might be, the operator's or an adapter's: each pane
/// carrying their label, and each pane `--map` or their session's claim names,
/// whether or not their own mapping came out unambiguous. `join` leaves an
/// ambiguous member unplaced, which would free its candidates for someone else.
fn protected<'p>(t: &'p Target<'_>, panes: &'p [Pane]) -> BTreeSet<&'p str> {
    let mut out = BTreeSet::new();
    for m in t
        .roster
        .iter()
        .filter(|m| matches!(m.role, Role::Operator | Role::Adapter))
    {
        out.extend(
            panes
                .iter()
                .filter(|p| p.label.as_deref() == Some(m.name.as_str()))
                .map(|p| p.pane_id.as_str()),
        );
        out.extend(t.explicit.get(&m.name).map(String::as_str));
        out.extend(t.claims.get(&m.name).map(String::as_str));
    }
    out
}

/// What a pane is, for noticing that it changed. Not its status: that changes
/// as the agent works.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity(String);

fn identity(p: &Pane, a: &Agent) -> Result<Identity> {
    if a.pane_id != p.pane_id || a.tab_id != p.tab_id {
        bail!("`agent get` answered for another pane");
    }
    // Debug-quoted, so text from herdr cannot pass for the separators
    Ok(Identity(format!(
        "pane {} tab {} label {:?} agent {:?} name {:?} terminal {:?}",
        p.pane_id, p.tab_id, p.label, a.agent, a.name, a.terminal_id
    )))
}

/// The longest description a `nudge-misfire` may carry (the model's rule).
const DESCRIPTION: usize = 128;

/// `text` as a record field: inert, never empty, at most [`DESCRIPTION`]
/// bytes, cut on a character boundary with an ellipsis. The full identity is
/// kept for comparing; only what is emitted is bounded.
fn describe(text: &str) -> String {
    let text = inert(text);
    if text.is_empty() {
        return "?".to_owned();
    }
    if text.len() <= DESCRIPTION {
        return text.into_owned();
    }
    let mut end = DESCRIPTION - '…'.len_utf8();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// What to do with the result; the caller emits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The prompt went and the pane was still the one chosen.
    Nudged { target: String },
    /// The prompt went, but the pane is not what it was.
    Misfire {
        target: String,
        expected: String,
        found: String,
    },
    /// Nothing was prompted; this says why (inert).
    Status(String),
}

/// One nudge.
pub struct Job<'a> {
    pub target: Target<'a>,
    /// The brief or review.
    pub of: &'a ContentId,
    /// How long to wait for it to settle before giving up, in milliseconds.
    pub wait_ms: u64,
}

fn observe<R: Runner>(h: &HerdrControl<R>, t: &Target<'_>) -> Result<(String, Identity, Agent)> {
    let panes = h.panes()?;
    let pane = resolve(t, &panes).map_err(|r| anyhow!("{r}"))?;
    let agent = h.agent(&pane.pane_id)?;
    let id = identity(pane, &agent)?;
    Ok((pane.pane_id.clone(), id, agent))
}

/// Nudge `job.target.member` about `job.of`. See the module note.
pub fn nudge<R: Runner>(h: &HerdrControl<R>, job: &Job<'_>) -> Outcome {
    let who = job.target.member;
    let stop =
        |why: String| Outcome::Status(inert(&format!("not nudged: {who}: {why}")).into_owned());

    let (pane, before, _) = match observe(h, &job.target) {
        Ok(seen) => seen,
        Err(e) => return stop(e.to_string()),
    };
    if let Err(e) = h.wait_settled(&pane, job.wait_ms) {
        return stop(format!("did not settle: {e}"));
    }
    match observe(h, &job.target) {
        Err(e) => return stop(format!("changed while waiting: {e}")),
        Ok((p, now, agent)) => {
            if p != pane || now != before {
                return stop("the pane changed while waiting".into());
            }
            // `done` is an agent that finished its turn: as ready as `idle`
            match agent.agent_status.as_str() {
                "idle" | "done" => {}
                "blocked" => return stop("blocked: it is waiting on someone".into()),
                other => return stop(format!("no longer settled ({other})")),
            }
        }
    }
    // the text is fixed; only the re-formatted content id is in it
    let text = format!("amesh flock take {}", job.of);
    if let Err(e) = h.prompt(&pane, &text) {
        return stop(format!("the prompt was not delivered: {e}"));
    }
    match observe(h, &job.target) {
        Ok((p, after, _)) if p == pane && after == before => Outcome::Nudged {
            target: who.to_owned(),
        },
        Ok((_, after, _)) => Outcome::Misfire {
            target: who.to_owned(),
            expected: describe(&before.0),
            found: describe(&after.0),
        },
        Err(e) => Outcome::Misfire {
            target: who.to_owned(),
            expected: describe(&before.0),
            found: describe(&format!("unreadable: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Clone)]
    struct P {
        pane: &'static str,
        tab: &'static str,
        ws: Option<&'static str>,
        label: Option<String>,
        kind: &'static str,
        name: Option<String>,
        term: &'static str,
        status: &'static str,
    }

    fn p(pane: &'static str, label: &str) -> P {
        P {
            pane,
            tab: "w1:t1",
            ws: Some("w1"),
            label: Some(label.into()),
            kind: "newt",
            name: Some(label.into()),
            term: pane,
            status: "idle",
        }
    }

    #[derive(Default)]
    struct World {
        panes: Vec<P>,
        calls: Vec<Vec<String>>,
        fail: Vec<&'static str>, // "wait" | "prompt" | "get"
        get_error: Option<String>,
    }

    type Hook = Box<dyn FnMut(&mut World)>;

    /// A scripted herdr: answers from a world, records every argv, and lets a
    /// test change the world after the nth call of a command.
    #[derive(Default)]
    struct Fake {
        w: RefCell<World>,
        seen: RefCell<HashMap<String, usize>>,
        hooks: RefCell<Vec<(String, usize, Hook)>>,
    }

    impl Fake {
        fn new(panes: Vec<P>) -> Self {
            let f = Self::default();
            f.w.borrow_mut().panes = panes;
            f
        }
        fn after(&self, cmd: &str, nth: usize, f: impl FnMut(&mut World) + 'static) {
            self.hooks.borrow_mut().push((cmd.into(), nth, Box::new(f)));
        }
        fn failing(&self, what: &'static str) {
            self.w.borrow_mut().fail.push(what);
        }
        fn calls(&self) -> Vec<String> {
            self.w.borrow().calls.iter().map(|c| c.join(" ")).collect()
        }
        fn count(&self, verb: &str) -> usize {
            self.calls().iter().filter(|c| c.starts_with(verb)).count()
        }
    }

    fn q(s: &str) -> String {
        serde_json::to_string(s).unwrap()
    }

    impl Runner for &Fake {
        fn run(&self, args: &[&str]) -> Result<String> {
            let cmd = args[..args.len().min(2)].join(" ");
            let n = {
                let mut seen = self.seen.borrow_mut();
                let n = seen.entry(cmd.clone()).or_default();
                *n += 1;
                *n
            };
            let reply = {
                let mut w = self.w.borrow_mut();
                w.calls.push(args.iter().map(|a| (*a).to_owned()).collect());
                let fails = |k: &str| w.fail.contains(&k);
                match cmd.as_str() {
                    "pane list" => {
                        let items: Vec<String> = w
                            .panes
                            .iter()
                            .map(|p| {
                                format!(
                                    r#"{{"pane_id":{},"tab_id":{},"workspace_id":{},"label":{},"agent":{},"agent_status":{}}}"#,
                                    q(p.pane),
                                    q(p.tab),
                                    p.ws.map_or("null".into(), q),
                                    p.label.as_deref().map_or("null".into(), q),
                                    q(p.kind),
                                    q(p.status)
                                )
                            })
                            .collect();
                        Ok(format!(r#"{{"result":{{"panes":[{}]}}}}"#, items.join(",")))
                    }
                    "agent get" => {
                        let p = w.panes.iter().find(|p| p.pane == args[2]);
                        match p {
                            Some(p) if !fails("get") => Ok(format!(
                                r#"{{"result":{{"agent":{{"terminal_id":{},"name":{},"agent":{},"agent_status":{},"pane_id":{},"tab_id":{}}}}}}}"#,
                                q(p.term),
                                p.name.as_deref().map_or("null".into(), q),
                                q(p.kind),
                                q(p.status),
                                q(p.pane),
                                q(p.tab)
                            )),
                            _ => Err(anyhow!(
                                "{}",
                                w.get_error.as_deref().unwrap_or("herdr agent get failed")
                            )),
                        }
                    }
                    "agent wait" if fails("wait") => Err(anyhow!("timed out")),
                    "agent prompt" if fails("prompt") => Err(anyhow!("agent_prompt_stalled")),
                    "agent prompt" => {
                        if let Some(p) = w.panes.iter_mut().find(|p| p.pane == args[2]) {
                            p.status = "working";
                        }
                        Ok("{}".into())
                    }
                    "agent wait" => Ok("{}".into()),
                    other => panic!("a command outside the four: {other}"),
                }
            };
            for (c, nth, f) in self.hooks.borrow_mut().iter_mut() {
                if *c == cmd && *nth == n {
                    f(&mut self.w.borrow_mut());
                }
            }
            reply
        }
    }

    fn member(name: &str, role: Role) -> Member {
        Member {
            name: name.into(),
            role,
            devices: vec![],
            delegate: false,
        }
    }

    fn roster() -> Vec<Member> {
        vec![
            member("shep", Role::Shepherd),
            member("h1", Role::Helper),
            member("ad", Role::Adapter),
            member("op", Role::Operator),
        ]
    }

    fn world() -> Vec<P> {
        vec![
            p("w1:p0", "ad"),
            p("w1:p1", "h1"),
            p("w1:p2", "shep"),
            p("w1:p9", "op"),
        ]
    }

    fn cid() -> ContentId {
        "bafyr4igcgxd5zewv23avoi62l26625jtpibvrwufusuaa3x7olq7wgixam"
            .parse()
            .unwrap()
    }

    struct Ctx {
        roster: Vec<Member>,
        claims: BTreeMap<String, String>,
        explicit: BTreeMap<String, String>,
        own: Option<&'static str>,
        scope: Scope,
        who: &'static str,
    }

    impl Ctx {
        fn new() -> Self {
            Self {
                roster: roster(),
                claims: BTreeMap::new(),
                explicit: BTreeMap::new(),
                own: Some("w1:p0"),
                scope: Scope::default(),
                who: "h1",
            }
        }
        fn run(&self, f: &Fake) -> Outcome {
            let id = cid();
            nudge(
                &HerdrControl(f),
                &Job {
                    target: Target {
                        roster: &self.roster,
                        member: self.who,
                        claims: &self.claims,
                        explicit: &self.explicit,
                        own_pane: self.own,
                        scope: &self.scope,
                    },
                    of: &id,
                    wait_ms: 5000,
                },
            )
        }
    }

    /// Whatever happened, only the four commands were issued, the only prompt
    /// text is the fixed one, and nothing but a roster-mapped pane was targeted.
    fn audit(f: &Fake) {
        for c in &f.w.borrow().calls {
            match c.iter().map(String::as_str).collect::<Vec<_>>()[..] {
                ["pane", "list"] | ["agent", "get", _] => {}
                ["agent", "wait", _, "--timeout", _] => {}
                ["agent", "prompt", _, text] => {
                    assert_eq!(text, format!("amesh flock take {}", cid()));
                }
                _ => panic!("an argv outside the allow-list: {c:?}"),
            }
        }
    }

    fn status(o: &Outcome) -> &str {
        match o {
            Outcome::Status(s) => s,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_still_pane_is_prompted_once_with_the_fixed_text_and_recorded_as_nudged() {
        let f = Fake::new(world());
        let o = Ctx::new().run(&f);
        assert_eq!(
            o,
            Outcome::Nudged {
                target: "h1".into()
            }
        );
        assert_eq!(f.count("agent prompt"), 1);
        assert_eq!(f.count("agent wait"), 1);
        // by pane id, after the wait
        let calls = f.calls();
        let at = |s: &str| calls.iter().position(|c| c.starts_with(s)).unwrap();
        assert!(at("agent wait") < at("agent prompt"));
        assert!(calls[at("agent prompt")].starts_with("agent prompt w1:p1 amesh flock take "));
        assert!(calls[at("agent wait")].ends_with("--timeout 5000"));
        audit(&f);
    }

    #[test]
    fn a_swap_between_the_re_check_and_the_prompt_is_a_misfire_and_one_prompt() {
        let f = Fake::new(world());
        // the second `agent get` is the re-check; the swap follows it
        f.after("agent get", 2, |w| {
            w.panes[1].kind = "claude";
            w.panes[1].name = Some("someone".into());
            w.panes[1].term = "other";
        });
        let o = Ctx::new().run(&f);
        let Outcome::Misfire {
            target,
            expected,
            found,
        } = o
        else {
            panic!("{o:?}")
        };
        assert_eq!(target, "h1");
        assert!(
            expected.contains("\"newt\"") && found.contains("\"claude\""),
            "{expected} / {found}"
        );
        assert_eq!(f.count("agent prompt"), 1);
        audit(&f);
    }

    #[test]
    fn a_swap_before_the_re_check_stops_without_a_prompt() {
        for what in ["kind", "name", "terminal", "label"] {
            let f = Fake::new(world());
            f.after("agent wait", 1, move |w| match what {
                "kind" => w.panes[1].kind = "claude",
                "name" => w.panes[1].name = Some("x".into()),
                "terminal" => w.panes[1].term = "t2",
                _ => w.panes[1].label = Some("h1 ".into()),
            });
            let o = Ctx::new().run(&f);
            // a changed label unmaps the member (no pane); the rest are identity
            assert!(status(&o).starts_with("not nudged: h1:"), "{what}: {o:?}");
            assert_eq!(f.count("agent prompt"), 0, "{what}");
            audit(&f);
        }
    }

    #[test]
    fn a_pane_that_went_busy_again_is_not_prompted() {
        let f = Fake::new(world());
        f.after("agent wait", 1, |w| w.panes[1].status = "working");
        let o = Ctx::new().run(&f);
        assert!(status(&o).contains("no longer settled"), "{o:?}");
        assert_eq!(f.count("agent prompt"), 0);
    }

    #[test]
    fn a_pane_that_finished_its_turn_is_ready_and_prompted() {
        // live: a pi pane that finished its turn reports `done`, never `idle`
        let mut w = world();
        w[1].status = "done";
        let f = Fake::new(w);
        let o = Ctx::new().run(&f);
        assert_eq!(
            o,
            Outcome::Nudged {
                target: "h1".into()
            }
        );
        assert_eq!(f.count("agent prompt"), 1);
        audit(&f);
    }

    #[test]
    fn a_blocked_pane_is_a_status_and_not_prompted() {
        let mut w = world();
        w[1].status = "blocked";
        let f = Fake::new(w);
        let o = Ctx::new().run(&f);
        assert!(status(&o).contains("blocked"), "{o:?}");
        assert_eq!(f.count("agent prompt"), 0);
        audit(&f);
    }

    #[test]
    fn the_wait_names_no_target_state_so_herdr_settles_on_idle_done_or_blocked() {
        let f = Fake::new(world());
        Ctx::new().run(&f);
        let calls = f.calls();
        let w = calls.iter().find(|c| c.starts_with("agent wait")).unwrap();
        assert!(!w.contains("--until"), "{w}");
    }

    #[test]
    fn a_wait_that_times_out_gives_up_with_a_status_and_no_prompt() {
        let f = Fake::new(world());
        f.failing("wait");
        let o = Ctx::new().run(&f);
        assert!(status(&o).contains("did not settle"), "{o:?}");
        assert_eq!(f.count("agent prompt"), 0);
        assert_eq!(f.count("agent wait"), 1, "no retry");
    }

    #[test]
    fn a_prompt_that_errors_or_stalls_is_not_a_nudge() {
        let f = Fake::new(world());
        f.failing("prompt");
        let o = Ctx::new().run(&f);
        assert!(status(&o).contains("not delivered"), "{o:?}");
        assert_eq!(f.count("agent prompt"), 1, "no retry");
    }

    #[test]
    fn a_re_read_that_fails_after_the_prompt_is_a_misfire_not_a_nudge() {
        let f = Fake::new(world());
        f.after("agent prompt", 1, |w| w.fail.push("get"));
        let o = Ctx::new().run(&f);
        let Outcome::Misfire { found, .. } = o else {
            panic!("{o:?}")
        };
        assert!(found.starts_with("unreadable"), "{found}");
    }

    fn refused(c: &Ctx, f: &Fake, why: &str) {
        let o = c.run(f);
        assert!(status(&o).contains(why), "{why}: {o:?}");
        assert_eq!(f.count("agent prompt"), 0, "{why}: a prompt was sent");
        assert_eq!(f.count("agent wait"), 0, "{why}: waited on a refused pane");
        audit(f);
    }

    #[test]
    fn every_refusal_prompts_nothing() {
        // no pane
        let mut w = world();
        w.remove(1);
        refused(&Ctx::new(), &Fake::new(w), "no pane");
        // two panes carry the label
        let mut w = world();
        w.push(p("w1:p7", "h1"));
        refused(&Ctx::new(), &Fake::new(w), "ambiguous");
        // --map names a pane herdr lacks
        let mut c = Ctx::new();
        c.explicit.insert("h1".into(), "w1:p77".into());
        refused(&c, &Fake::new(world()), "is gone");
        // the session's claimed pane is gone, though a label would match
        let mut c = Ctx::new();
        c.claims.insert("h1".into(), "w1:p55".into());
        refused(&c, &Fake::new(world()), "its claimed pane");
        // the operator and the adapter are never nudged
        for who in ["op", "ad", "stranger"] {
            let mut c = Ctx::new();
            c.who = who;
            refused(&c, &Fake::new(world()), "not a member that is nudged");
        }
        // a member mapped onto the operator's pane: two members, one pane
        let mut c = Ctx::new();
        c.explicit.insert("h1".into(), "w1:p9".into());
        refused(&c, &Fake::new(world()), "ambiguous");
        // the pane this command runs in, even when it is the member's own
        let mut w = world();
        w[0].label = Some("h1".into());
        w.remove(1);
        refused(&Ctx::new(), &Fake::new(w), "own pane");
        // not in herdr, or in a herdr that does not list us
        let mut c = Ctx::new();
        c.own = None;
        refused(&c, &Fake::new(world()), "cannot identify");
        let mut c = Ctx::new();
        c.own = Some("w9:p9");
        refused(&c, &Fake::new(world()), "cannot identify");
        // an id that could be read as an option
        let mut w = world();
        w[1].pane = "-rf";
        let mut c = Ctx::new();
        c.explicit.insert("h1".into(), "-rf".into());
        refused(&c, &Fake::new(w), "not safe");
    }

    #[test]
    fn deny_wins_and_an_allow_list_confines() {
        let deny = |e: Entry| Scope {
            deny: vec![e],
            allow: vec![],
        };
        for e in [
            Entry::Tab("w1:t1".into()),
            Entry::Workspace("w1".into()),
            Entry::Pane("w1:p1".into()),
        ] {
            let mut c = Ctx::new();
            c.scope = deny(e);
            refused(&c, &Fake::new(world()), "deny list");
        }
        // another tab or workspace is not covered
        let mut c = Ctx::new();
        c.scope = deny(Entry::Workspace("w2".into()));
        assert!(matches!(c.run(&Fake::new(world())), Outcome::Nudged { .. }));
        // an allow list: off it is refused, on it is nudged, deny still wins
        let mut c = Ctx::new();
        c.scope = Scope {
            deny: vec![],
            allow: vec![Entry::Tab("w1:t2".into())],
        };
        refused(&c, &Fake::new(world()), "allow list");
        c.scope = Scope {
            deny: vec![],
            allow: vec![Entry::Tab("w1:t1".into())],
        };
        assert!(matches!(c.run(&Fake::new(world())), Outcome::Nudged { .. }));
        c.scope = Scope {
            deny: vec![Entry::Pane("w1:p1".into())],
            allow: vec![Entry::Tab("w1:t1".into())],
        };
        refused(&c, &Fake::new(world()), "deny list");
    }

    #[test]
    fn a_pane_off_the_roster_is_never_prompted_whatever_its_label() {
        let mut w = world();
        w.push(p("w1:p5", "reviewer-from-nowhere"));
        w.remove(1); // h1 has no pane; the stranger's must not stand in
        refused(&Ctx::new(), &Fake::new(w), "no pane");
    }

    #[test]
    fn hostile_text_from_herdr_or_the_log_is_never_interpolated_or_printed_raw() {
        let mut w = world();
        w[1].label = Some("h1".into());
        w[1].name = Some("x\u{1b}]0;pwn\u{7}\n; rm -rf /".into());
        let f = Fake::new(w);
        let o = Ctx::new().run(&f);
        assert!(matches!(o, Outcome::Nudged { .. }), "{o:?}");
        audit(&f); // the prompt is exactly the fixed text
                   // a refusal whose reason carries hostile text is inert
        let mut c = Ctx::new();
        c.explicit.insert("h1".into(), "w1:p1".into());
        let mut w = world();
        w[1].name = Some("\u{1b}[2J".into());
        let f = Fake::new(w);
        f.failing("wait");
        let o = c.run(&f);
        assert!(!status(&o).chars().any(char::is_control), "{o:?}");
        // identities Debug-quote it, so a misfire record carries no raw control either
        let mut w = world();
        w[1].name = Some("a".into());
        let f = Fake::new(w);
        f.after("agent get", 2, |w| {
            w.panes[1].name = Some("\u{1b}[31m\r".into());
        });
        let Outcome::Misfire { found, .. } = Ctx::new().run(&f) else {
            panic!()
        };
        assert!(!found.chars().any(char::is_control), "{found:?}");
    }

    #[test]
    fn a_claim_beats_a_label_and_a_map_beats_a_claim() {
        let mut w = world();
        w.push(p("w1:p3", "elsewhere"));
        w.push(p("w1:p4", "other"));
        let mut c = Ctx::new();
        c.claims.insert("h1".into(), "w1:p3".into());
        let f = Fake::new(w.clone());
        assert!(matches!(c.run(&f), Outcome::Nudged { .. }));
        assert!(f
            .calls()
            .iter()
            .any(|c| c.starts_with("agent prompt w1:p3 ")));
        c.explicit.insert("h1".into(), "w1:p4".into());
        let f = Fake::new(w);
        assert!(matches!(c.run(&f), Outcome::Nudged { .. }));
        assert!(f
            .calls()
            .iter()
            .any(|c| c.starts_with("agent prompt w1:p4 ")));
    }

    #[test]
    fn a_map_stands_even_when_the_sessions_old_claim_is_gone() {
        let mut c = Ctx::new();
        c.claims.insert("h1".into(), "w1:p55".into());
        c.explicit.insert("h1".into(), "w1:p1".into());
        assert!(matches!(c.run(&Fake::new(world())), Outcome::Nudged { .. }));
    }

    #[test]
    fn an_answer_for_another_pane_is_not_an_identity() {
        let pane = Pane {
            pane_id: "w1:p1".into(),
            tab_id: "w1:t1".into(),
            workspace_id: None,
            label: None,
            agent: None,
            agent_session: None,
            agent_status: None,
        };
        let agent = |pane_id: &str, tab_id: &str| Agent {
            terminal_id: "t".into(),
            name: None,
            agent: None,
            agent_status: "idle".into(),
            pane_id: pane_id.into(),
            tab_id: tab_id.into(),
        };
        assert!(identity(&pane, &agent("w1:p1", "w1:t1")).is_ok());
        assert!(identity(&pane, &agent("w1:p2", "w1:t1")).is_err());
        assert!(identity(&pane, &agent("w1:p1", "w1:t2")).is_err());
    }

    /// Admit `outcome` as a real `nudge-misfire` (or whatever it is) into a real
    /// server's log, as the adapter's session would send it.
    fn admitted(outcome: &Outcome) -> std::result::Result<(), String> {
        use agent_mesh_flock_server::{init, InitSpec, Server};
        use agent_mesh_protocol::{AgentKey, Assertion, UserKey};
        use content_addressable::ContentAddressable as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        let dir = tempfile::tempdir().unwrap();
        let spec = InitSpec {
            name: "t".into(),
            roster: vec![
                member("shep", Role::Shepherd),
                member("h1", Role::Helper),
                member("ad", Role::Adapter),
            ],
            salt: "s".into(),
            host: "fixture".into(),
            issued_at: "2026-10-15T00:00:00Z".into(),
        };
        init(dir.path(), &UserKey::generate(), spec).unwrap();
        let mut server = Server::open(dir.path()).unwrap();
        let mut enroll = |who: &str| {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let invite = server.invite(who).unwrap();
            let ch = server
                .enroll_begin(&invite.token, who, sk.verifying_key().to_bytes())
                .unwrap();
            let done = server
                .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
                .unwrap();
            AgentKey::from_seed_and_cert(&sk.to_bytes(), done.cert).unwrap()
        };
        let (shep, ad) = (enroll("shep"), enroll("ad"));
        let mut send = |key: &AgentKey,
                        kind: agent_mesh_flock::Kind,
                        refs: BTreeMap<String, ContentId>,
                        body: agent_mesh_flock::Body| {
            let author = key.fingerprint().hex();
            let node = agent_mesh_flock::Event {
                flock: server.flock(),
                kind,
                prev: server.board().head_of(&author),
                author,
                refs,
                files: vec![],
                at: 0,
                body,
            }
            .node();
            let sig = Assertion::sign(key, &node.content_id().unwrap());
            let id = node.content_id().unwrap();
            server
                .admit(node, sig)
                .map(|_| id)
                .map_err(|e| e.to_string())
        };
        let brief = send(
            &shep,
            agent_mesh_flock::Kind::Brief,
            BTreeMap::new(),
            agent_mesh_flock::Body::Brief {
                to: "h1".into(),
                lane: "l".into(),
            },
        )
        .unwrap();
        let cites = BTreeMap::from([("of".to_owned(), brief)]);
        let (kind, body) = match outcome {
            Outcome::Nudged { target } => (
                agent_mesh_flock::Kind::Nudged,
                agent_mesh_flock::Body::Nudged {
                    target: target.clone(),
                },
            ),
            Outcome::Misfire {
                target,
                expected,
                found,
            } => (
                agent_mesh_flock::Kind::NudgeMisfire,
                agent_mesh_flock::Body::NudgeMisfire {
                    target: target.clone(),
                    expected: expected.clone(),
                    found: found.clone(),
                },
            ),
            Outcome::Status(text) => (
                agent_mesh_flock::Kind::Status,
                agent_mesh_flock::Body::Status { text: text.clone() },
            ),
        };
        let cites = if kind == agent_mesh_flock::Kind::Status {
            BTreeMap::new()
        } else {
            cites
        };
        send(&ad, kind, cites, body).map(drop)
    }

    #[test]
    fn a_misfire_the_model_would_refuse_is_never_produced() {
        // a misfire is admissible at all with ordinary fields (the fixture works)
        let f = Fake::new(world());
        f.after("agent get", 2, |w| w.panes[1].kind = "claude");
        let o = Ctx::new().run(&f);
        assert!(matches!(o, Outcome::Misfire { .. }));
        admitted(&o).unwrap();

        for name in [
            "n".repeat(129),
            "é".repeat(100),          // 200 bytes, a multibyte char at every boundary
            "x\u{1b}[31m".repeat(40), // control characters, long
            "日本語".repeat(30),
        ] {
            // changed before the prompt's re-read: expected is the long one
            let mut w = world();
            w[1].name = Some(name.clone());
            let f = Fake::new(w);
            f.after("agent get", 2, |w| w.panes[1].kind = "claude");
            let o = Ctx::new().run(&f);
            let Outcome::Misfire {
                expected, found, ..
            } = &o
            else {
                panic!("{o:?}")
            };
            for d in [expected, found] {
                assert!(!d.is_empty() && d.len() <= 128, "{} bytes", d.len());
                assert!(!d.chars().any(char::is_control), "{d:?}");
            }
            admitted(&o).unwrap_or_else(|e| panic!("admission refused {name:?}: {e}"));
        }
        // the unreadable path with a long error
        let f = Fake::new(world());
        f.w.borrow_mut().get_error = Some("e".repeat(500));
        f.after("agent prompt", 1, |w| w.fail.push("get"));
        let o = Ctx::new().run(&f);
        let Outcome::Misfire { found, .. } = &o else {
            panic!("{o:?}")
        };
        assert!(
            found.starts_with("unreadable") && found.len() <= 128,
            "{found}"
        );
        admitted(&o).unwrap();
        // and what the sequence says by way of status is admissible too
        let f = Fake::new(world());
        f.failing("wait");
        f.w.borrow_mut().get_error = None;
        admitted(&Ctx::new().run(&f)).unwrap();
    }

    #[test]
    fn a_protected_members_candidate_panes_stay_protected_when_its_own_mapping_is_ambiguous() {
        let two_ops = || {
            let mut w = world();
            w.push(p("w1:p8", "op")); // two panes carry the operator's label
            w
        };
        // a helper --mapped onto one candidate
        let mut c = Ctx::new();
        c.explicit.insert("h1".into(), "w1:p9".into());
        refused(&c, &Fake::new(two_ops()), "protected");
        // a helper's session claims one
        let mut c = Ctx::new();
        c.claims.insert("h1".into(), "w1:p8".into());
        refused(&c, &Fake::new(two_ops()), "protected");
        // the same for the adapter: its label on a second pane
        let mut w = world();
        w.push(p("w1:p7", "ad"));
        let mut c = Ctx::new();
        c.explicit.insert("h1".into(), "w1:p7".into());
        refused(&c, &Fake::new(w), "protected");
        // the operator's pane named by --map or a claim, with no label at all
        let mut c = Ctx::new();
        c.explicit.insert("op".into(), "w1:p6".into());
        c.explicit.insert("h1".into(), "w1:p6".into());
        let mut w = world();
        w.push(p("w1:p6", "other"));
        refused(&c, &Fake::new(w), "ambiguous");
        let mut c = Ctx::new();
        c.claims.insert("op".into(), "w1:p6".into());
        c.explicit.insert("h1".into(), "w1:p6".into());
        let mut w = world();
        w.push(p("w1:p6", "other"));
        refused(&c, &Fake::new(w), "ambiguous");
    }

    #[test]
    fn a_protected_members_stale_claim_is_still_protected_when_a_map_overrides_it() {
        // the operator's session once claimed p6; --map now says p9, so join
        // never looks at p6 for the operator, but it may still be theirs
        let mut w = world();
        w.push(p("w1:p6", "other"));
        let mut c = Ctx::new();
        c.claims.insert("op".into(), "w1:p6".into());
        c.explicit.insert("op".into(), "w1:p9".into());
        c.explicit.insert("h1".into(), "w1:p6".into());
        refused(&c, &Fake::new(w), "protected");
    }

    #[test]
    fn a_description_is_never_empty() {
        assert_eq!(describe(""), "?");
        assert_eq!(describe("abc"), "abc");
        let long = describe(&"é".repeat(100));
        assert!(long.len() <= 128 && long.ends_with('…'));
    }

    #[test]
    fn a_workspace_rule_uses_the_workspace_herdr_reports_and_fails_closed_without_it() {
        let ws = |w: Option<&'static str>| {
            let mut v = world();
            v[1].ws = w;
            v
        };
        let rule = |w: &str| Scope {
            deny: vec![Entry::Workspace(w.into())],
            allow: vec![],
        };
        // reported and equal: denied, whatever the pane id looks like
        let mut c = Ctx::new();
        c.scope = rule("w1");
        refused(&c, &Fake::new(ws(Some("w1"))), "deny list");
        // reported and different: allowed
        c.scope = rule("w2");
        assert!(matches!(
            c.run(&Fake::new(ws(Some("w1")))),
            Outcome::Nudged { .. }
        ));
        // a pane id that merely starts with the denied workspace, in another one
        let mut w = world();
        w[1].ws = Some("w7");
        c.scope = rule("w1");
        assert!(matches!(c.run(&Fake::new(w)), Outcome::Nudged { .. }));
        // not reported: a workspace deny cannot be decided, so it denies
        refused(&c, &Fake::new(ws(None)), "deny list");
        // and an allow list for a workspace does not admit an unreported one
        c.scope = Scope {
            deny: vec![],
            allow: vec![Entry::Workspace("w1".into())],
        };
        refused(&c, &Fake::new(ws(None)), "allow list");
        // a tab or pane rule does not need the workspace
        c.scope = Scope {
            deny: vec![Entry::Tab("w1:t2".into())],
            allow: vec![],
        };
        assert!(matches!(
            c.run(&Fake::new(ws(None))),
            Outcome::Nudged { .. }
        ));
    }

    #[test]
    fn a_pane_whose_tab_id_is_not_safe_is_refused_before_anything_runs() {
        for bad in ["--evil", "-t", "w1 t1", "w1:t1;x"] {
            let mut w = world();
            w[1].tab = bad;
            refused(&Ctx::new(), &Fake::new(w), "not safe");
        }
    }

    #[test]
    fn the_lists_are_read_from_files_and_flags_and_a_bad_line_is_an_error() {
        let home = tempfile::tempdir().unwrap();
        // missing files are empty
        assert_eq!(
            Scope::load(home.path(), &[], &[]).unwrap(),
            Scope::default()
        );
        std::fs::write(
            home.path().join("herdr-nudge.deny"),
            "# keep out\ntab:w1:t7\n\n  workspace:w3  \n",
        )
        .unwrap();
        std::fs::write(home.path().join("herdr-nudge.allow"), "tab:w1:t1\n").unwrap();
        let s = Scope::load(home.path(), &["pane:w1:p5".into()], &["tab:w1:t2".into()]).unwrap();
        assert_eq!(
            s.deny,
            [
                Entry::Tab("w1:t7".into()),
                Entry::Workspace("w3".into()),
                Entry::Pane("w1:p5".into())
            ]
        );
        assert_eq!(
            s.allow,
            [Entry::Tab("w1:t1".into()), Entry::Tab("w1:t2".into())]
        );
        for bad in ["tab", "team:x", "tab:", "tab:-x", "pane:a b"] {
            std::fs::write(home.path().join("herdr-nudge.deny"), bad).unwrap();
            assert!(Scope::load(home.path(), &[], &[]).is_err(), "{bad}");
        }
        assert!(Scope::load(home.path(), &["nonsense".into()], &[]).is_err());
    }
}
