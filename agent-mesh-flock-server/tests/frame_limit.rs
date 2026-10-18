//! `frame_fits` is the limit on what a watcher can be sent as one message. A
//! single event's request now outgrows its frame (the frame cites the author's
//! certificate), so the boundary is tested on frames directly.
#![cfg(unix)]
mod support;

use agent_mesh_flock::{Body, Kind};
use agent_mesh_flock_server::wire::{frame_fits, Resp, MAX_MESSAGE};
use agent_mesh_flock_server::{seal, Sealed};
use content_addressable::canonical::to_canonical_dagcbor;
use support::{enroll, Env};

fn frame_with_lane(env: &mut Env, lane_len: usize) -> Vec<Sealed> {
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let (node, sig) = env.event(
        &shep.key,
        Kind::Brief,
        None,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "x".repeat(lane_len),
        },
    );
    vec![seal(&env.server_key(), server.head_record(), 99, 0, node, sig).unwrap()]
}

#[test]
fn a_frame_fits_exactly_up_to_the_message_limit() {
    // the string header is the same size from 64 KiB up: one byte per byte
    let probe = 100_000;
    let mut env = Env::new();
    let size = to_canonical_dagcbor(&Resp::Frame(frame_with_lane(&mut env, probe)))
        .unwrap()
        .len();
    let exact = probe + (MAX_MESSAGE - size);
    for (extra, fits) in [(0, true), (1, false)] {
        let mut env = Env::new();
        let f = frame_with_lane(&mut env, exact + extra);
        assert_eq!(frame_fits(&f).unwrap(), fits, "lane {}", exact + extra);
    }
}
