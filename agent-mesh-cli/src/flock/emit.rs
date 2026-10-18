//! Commands that write: each is one `Emit` to the session, which holds the
//! key, fills `prev`, signs and sends it. The CLI signs nothing, and checks
//! nothing the server's admission decides.

use super::discover::{who, Where};
use agent_mesh_flock::{Body, Kind, Outcome};
use agent_mesh_flock_session::{call, CtlReq, CtlResp};
use anyhow::{anyhow, bail, Result};
use content_addressable::ContentId;
use std::collections::BTreeMap;
use std::path::Path;

/// Send one event through the session and print what the server admitted.
pub fn emit(home: &Path, w: &Where, kind: Kind, refs: &[(&str, &str)], body: Body) -> Result<()> {
    let refs = refs
        .iter()
        .map(|(role, cid)| {
            cid.parse::<ContentId>()
                .map(|c| ((*role).to_owned(), c))
                .map_err(|e| anyhow!("'{cid}' is not a content id: {e}"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    match call(&w.socket(home)?, &CtlReq::Emit { kind, refs, body })? {
        CtlResp::Admitted { event, index } => {
            println!("admitted {event} at {index}");
            Ok(())
        }
        _ => bail!("the session answered something else"),
    }
}

/// `join`: who is this session, and optionally tell the log its pane.
pub fn join(home: &Path, w: &Where, announce: bool) -> Result<()> {
    let socket = w.socket(home)?;
    let me = who(&socket)?;
    println!("flock:   {}", me.flock);
    println!("member:  {}", me.member);
    println!("session: {}", me.session);
    println!("state:   {}", if me.pending { "pending" } else { "active" });
    if announce {
        match call(&socket, &CtlReq::Announce)? {
            CtlResp::Admitted { event, index } => println!("announced {event} at {index}"),
            _ => bail!("the session answered something else"),
        }
    }
    Ok(())
}

pub fn parse_outcome(s: &str) -> Result<Outcome> {
    match s {
        "completed" => Ok(Outcome::Completed),
        "failed" => Ok(Outcome::Failed),
        _ => bail!("outcome must be completed or failed"),
    }
}
