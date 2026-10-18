//! The session wire and the frames carry keys, nonces and signatures as CBOR
//! byte strings, so their size does not depend on the bytes' values.
#![cfg(unix)]
mod support;

use agent_mesh_flock_server::wire::{Req, StreamChallenge};
use agent_mesh_protocol::agent_key::PossessionChallenge;
use content_addressable::canonical::to_canonical_dagcbor;
use ed25519_dalek::Signature;
use support::{enroll, Env};

fn len<T: serde::Serialize>(v: &T) -> usize {
    to_canonical_dagcbor(v).unwrap().len()
}

#[test]
fn wire_keys_nonces_and_proofs_cost_the_same_whatever_their_bytes() {
    let env = Env::new();
    let (lo, hi) = (1u8, 250u8);
    let chal = |b: u8| StreamChallenge {
        flock: env.flock,
        nonce: [b; 32],
    };
    assert_eq!(len(&chal(lo)), len(&chal(hi)), "stream nonce");
    let begin = |b: u8| Req::EnrollBegin {
        token: "t".into(),
        member: "m".into(),
        pubkey: [b; 32],
    };
    assert_eq!(len(&begin(lo)), len(&begin(hi)), "enroll pubkey");
    let pc = |b: u8| PossessionChallenge {
        issuer_pubkey: [b; 32],
        subject_pubkey: [b; 32],
        nonce: [b; 32],
    };
    let finish = |b: u8| Req::EnrollFinish {
        challenge: pc(b),
        proof: Signature::from_bytes(&[b; 64]),
    };
    assert_eq!(len(&finish(lo)), len(&finish(hi)), "challenge and proof");
}

#[test]
fn a_real_admission_frame_stays_under_its_ceiling() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let prev = server.board().head_of(&shep.key.fingerprint().hex());
    let (node, sig) = env.brief(&shep.key, prev, "l1");
    server.admit(node, sig).unwrap();
    let j = server.journal();
    let mut c = j.cursor_from(None).unwrap();
    let mut last = vec![];
    while c.delivered() < j.len() {
        last = c.next_frame().unwrap().0.to_vec();
    }
    let n = len(&agent_mesh_flock_server::Frame { sealed: last });
    // a cited certificate, not a carried one: with the two certificate chains inline it was 1.7 KB
    assert!(n <= CEILING, "a brief frame is {n} bytes, over {CEILING}");
}

const CEILING: usize = 600;
