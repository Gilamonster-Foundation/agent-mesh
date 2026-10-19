//! A read-only view of herdr, and the join of a flock roster onto its panes.
//!
//! herdr is wrapped from outside: one fixed command, `herdr pane list`. The
//! type has no method that could change herdr, so nothing here prompts, sends
//! keys, renames or focuses. What herdr says is its own claim (`herdr` tier);
//! only the flock columns come from the verified log.

use agent_mesh_flock::Member;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

/// One pane as `herdr pane list` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Pane {
    /// `w1:p2A`.
    pub pane_id: String,
    /// The tab it sits in; labels are only unique within one.
    pub tab_id: String,
    /// The pane label, when one was set.
    #[serde(default)]
    pub label: Option<String>,
    /// The detected agent, for panes without an `agent_session`.
    #[serde(default)]
    pub agent: Option<String>,
    /// herdr reports a session's agent here instead of under `agent`.
    #[serde(default)]
    pub agent_session: Option<AgentSession>,
    /// herdr's status word.
    #[serde(default)]
    pub agent_status: Option<String>,
}

/// The part of `agent_session` we read.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AgentSession {
    /// `claude`, `codex`, ...
    pub agent: String,
}

impl Pane {
    /// The agent herdr detected, from either place it reports one.
    #[must_use]
    pub fn agent(&self) -> Option<&str> {
        self.agent
            .as_deref()
            .or_else(|| self.agent_session.as_ref().map(|s| s.agent.as_str()))
    }
}

/// Runs the herdr binary with fixed arguments and returns its stdout.
pub trait Runner {
    /// # Errors
    /// The command could not run or exited non-zero.
    fn run(&self, args: &[&str]) -> Result<String>;
}

/// The real `herdr` on `PATH`.
pub struct System;

impl Runner for System {
    fn run(&self, args: &[&str]) -> Result<String> {
        let out = std::process::Command::new("herdr")
            .args(args)
            .output()
            .context("run herdr")?;
        if !out.status.success() {
            bail!("herdr {} failed: {}", args.join(" "), out.status);
        }
        String::from_utf8(out.stdout).context("herdr output is not utf-8")
    }
}

/// herdr, read-only by construction: `panes` is the only thing it can ask.
pub struct Herdr<R>(pub R);

impl<R: Runner> Herdr<R> {
    /// Every pane herdr knows.
    ///
    /// # Errors
    /// herdr failed or its output did not parse.
    pub fn panes(&self) -> Result<Vec<Pane>> {
        #[derive(Deserialize)]
        struct Listing {
            panes: Vec<Pane>,
        }
        #[derive(Deserialize)]
        struct Envelope {
            result: Listing,
        }
        let text = self.0.run(&["pane", "list"])?;
        let env: Envelope = serde_json::from_str(&text).context("parse `herdr pane list`")?;
        Ok(env.result.panes)
    }
}

/// Why a member has no pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    /// No pane carries the member's name.
    NoPane,
    /// Several do (or two members claim one pane): not guessed.
    Ambiguous(usize),
    /// `--map` named a pane herdr does not have.
    Gone(String),
}

/// A member and the pane it maps to.
pub type Placement<'a> = (&'a Member, std::result::Result<&'a Pane, Gap>);

/// Join the roster onto `panes`.
///
/// A member maps by `explicit` (`member -> pane id`) first, else to the pane
/// whose label equals its name, within `tab` when given. A pane that is not
/// the answer for a roster member is never mapped, so off-roster panes and
/// labels do not appear.
///
/// # Errors
/// `explicit` names someone who is not on the roster.
pub fn join<'a>(
    roster: &'a [Member],
    panes: &'a [Pane],
    explicit: &BTreeMap<String, String>,
    tab: Option<&str>,
) -> Result<Vec<Placement<'a>>> {
    if let Some(who) = explicit
        .keys()
        .find(|who| !roster.iter().any(|m| &m.name == *who))
    {
        return Err(anyhow!("--map names '{who}', who is not on the roster"));
    }
    let mut out: Vec<Placement<'a>> = roster
        .iter()
        .map(|m| {
            let found = if let Some(id) = explicit.get(&m.name) {
                panes
                    .iter()
                    .find(|p| &p.pane_id == id)
                    .ok_or_else(|| Gap::Gone(id.clone()))
            } else {
                let hits: Vec<_> = panes
                    .iter()
                    .filter(|p| tab.is_none() || tab == Some(p.tab_id.as_str()))
                    .filter(|p| p.label.as_deref() == Some(m.name.as_str()))
                    .collect();
                match hits.as_slice() {
                    [] => Err(Gap::NoPane),
                    [one] => Ok(*one),
                    many => Err(Gap::Ambiguous(many.len())),
                }
            };
            (m, found)
        })
        .collect();
    // One pane can speak for one member.
    let taken: Vec<String> = out
        .iter()
        .filter_map(|(_, p)| p.as_ref().ok().map(|p| p.pane_id.clone()))
        .collect();
    for (_, p) in &mut out {
        if let Ok(pane) = p {
            let n = taken.iter().filter(|t| **t == pane.pane_id).count();
            if n > 1 {
                *p = Err(Gap::Ambiguous(n));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_flock::Role;
    use std::cell::RefCell;

    struct Mock {
        calls: RefCell<Vec<Vec<String>>>,
        reply: String,
    }
    impl Runner for &Mock {
        fn run(&self, args: &[&str]) -> Result<String> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|a| (*a).to_owned()).collect());
            Ok(self.reply.clone())
        }
    }

    fn pane(id: &str, tab: &str, label: Option<&str>) -> Pane {
        Pane {
            pane_id: id.into(),
            tab_id: tab.into(),
            label: label.map(Into::into),
            agent: None,
            agent_session: None,
            agent_status: None,
        }
    }

    fn roster() -> Vec<Member> {
        [("shep", Role::Shepherd), ("h1", Role::Helper)]
            .into_iter()
            .map(|(n, role)| Member {
                name: n.into(),
                role,
                devices: vec![],
                delegate: false,
            })
            .collect()
    }

    #[test]
    fn only_the_read_command_is_ever_issued() {
        let mock = Mock {
            calls: RefCell::default(),
            reply: r#"{"id":"x","result":{"panes":[{"pane_id":"w1:p1","tab_id":"w1:t1",
                "label":"h1","agent":"newt","agent_status":"idle","extra":1},
                {"pane_id":"w1:p2","tab_id":"w1:t1","agent_session":{"agent":"claude","kind":"id"}}]}}"#
                .into(),
        };
        let panes = Herdr(&mock).panes().unwrap();
        assert_eq!(panes.len(), 2);
        assert_eq!(panes[1].agent(), Some("claude"));
        assert_eq!(panes[0].agent_status.as_deref(), Some("idle"));
        assert_eq!(panes[0].agent(), Some("newt"));
        // The allowlist: any other argv would be a state-changing request.
        assert_eq!(*mock.calls.borrow(), vec![vec!["pane", "list"]]);
    }

    #[test]
    fn a_pane_off_the_roster_is_never_mapped() {
        let panes = [
            pane("w1:p1", "t", Some("reviewer")),
            pane("w1:p2", "t", Some("h1")),
            pane("w1:p3", "t", None),
        ];
        let r = roster();
        let placed = join(&r, &panes, &BTreeMap::new(), None).unwrap();
        let mapped: Vec<_> = placed
            .iter()
            .filter_map(|(_, p)| p.as_ref().ok().map(|p| p.pane_id.as_str()))
            .collect();
        assert_eq!(mapped, ["w1:p2"]);
        assert_eq!(placed[0].1, Err(Gap::NoPane));
    }

    #[test]
    fn explicit_maps_win_but_only_for_roster_members() {
        let panes = [pane("w1:p1", "t", Some("h1")), pane("w1:p9", "t", None)];
        let r = roster();
        let map = BTreeMap::from([("h1".to_owned(), "w1:p9".to_owned())]);
        let placed = join(&r, &panes, &map, None).unwrap();
        assert_eq!(placed[1].1.as_ref().unwrap().pane_id, "w1:p9");
        let bad = BTreeMap::from([("stranger".to_owned(), "w1:p1".to_owned())]);
        assert!(join(&r, &panes, &bad, None).is_err());
        let gone = BTreeMap::from([("h1".to_owned(), "w1:p0".to_owned())]);
        assert_eq!(
            join(&r, &panes, &gone, None).unwrap()[1].1,
            Err(Gap::Gone("w1:p0".into()))
        );
    }

    #[test]
    fn labels_repeat_across_tabs_so_a_tab_scopes_them_and_ties_are_not_guessed() {
        let panes = [
            pane("w1:p1", "w1:ta", Some("h1")),
            pane("w1:p2", "w1:tb", Some("h1")),
        ];
        let r = roster();
        let all = join(&r, &panes, &BTreeMap::new(), None).unwrap();
        assert_eq!(all[1].1, Err(Gap::Ambiguous(2)));
        let one = join(&r, &panes, &BTreeMap::new(), Some("w1:tb")).unwrap();
        assert_eq!(one[1].1.as_ref().unwrap().pane_id, "w1:p2");
    }

    #[test]
    fn one_pane_cannot_speak_for_two_members() {
        let panes = [pane("w1:p1", "t", Some("h1"))];
        let r = roster();
        let map = BTreeMap::from([("shep".to_owned(), "w1:p1".to_owned())]);
        let placed = join(&r, &panes, &map, None).unwrap();
        assert!(placed.iter().all(|(_, p)| p == &Err(Gap::Ambiguous(2))));
    }
}
