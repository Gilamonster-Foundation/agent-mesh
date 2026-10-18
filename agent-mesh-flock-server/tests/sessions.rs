//! Invites, enrollment, session end, the epoch ratchet and renewal.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::{Body, EndReason, Kind, Refusal};
use agent_mesh_flock_server::{
    cert_cid, session_caveats, token_digest, CrashPlan, ServerError, Status,
};
use agent_mesh_protocol::AgentKey;
use content_addressable::ContentAddressable;
use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
use support::{bump_and_renew, enroll, id, read_frames, Env};

fn session_err<T: std::fmt::Debug>(r: Result<T, ServerError>) -> String {
    match r {
        Err(ServerError::Session(why)) => why,
        other => panic!("expected a session-rule refusal, got {other:?}"),
    }
}

#[test]
fn the_first_session_is_active_and_its_certificate_is_bounded_to_the_epoch() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    assert!(!shep.pending);
    assert_eq!(
        shep.key.cert().metadata.caveats,
        session_caveats(0),
        "valid_for_generation = Only({{epoch}})"
    );
    assert_eq!(
        server.sessions().get(&shep.session).unwrap().status,
        Status::Active
    );
    let (n, s) = env.brief(&shep.key, None, "lane-a");
    assert!(!server.admit(n, s).unwrap().duplicate);
}

#[test]
fn a_replayed_token_is_refused() {
    let env = Env::new();
    let mut server = env.open();
    let invite = server.invite("h1").unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let ch = server
        .enroll_begin(&invite.token, "h1", sk.verifying_key().to_bytes())
        .unwrap();
    server
        .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
        .unwrap();
    let again = SigningKey::generate(&mut OsRng);
    let why =
        session_err(server.enroll_begin(&invite.token, "h1", again.verifying_key().to_bytes()));
    assert!(why.contains("consumed"), "{why}");
}

#[test]
fn a_token_for_the_wrong_member_is_refused() {
    let env = Env::new();
    let mut server = env.open();
    let invite = server.invite("h1").unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    session_err(server.enroll_begin(&invite.token, "shep", sk.verifying_key().to_bytes()));
    session_err(server.enroll_begin("not a token", "h1", sk.verifying_key().to_bytes()));
    assert!(server.invite("nobody").is_err(), "not on the roster");
}

#[test]
fn a_challenge_built_by_the_caller_is_refused() {
    let env = Env::new();
    let mut server = env.open();
    let invite = server.invite("h1").unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let real = server
        .enroll_begin(&invite.token, "h1", sk.verifying_key().to_bytes())
        .unwrap();
    // same issuer and subject, a nonce the server never issued
    let mut forged = real.clone();
    forged.nonce = [7; 32];
    session_err(server.enroll_finish(&forged, &sk.sign(&forged.signing_bytes())));
    // a challenge from some other issuer
    let other = AgentKey::issue(
        &agent_mesh_protocol::UserKey::generate(),
        support::meta("x"),
    );
    let foreign = other.possession_challenge(sk.verifying_key().to_bytes());
    session_err(server.enroll_finish(&foreign, &sk.sign(&foreign.signing_bytes())));
    // a real nonce with altered fields
    let attacker = SigningKey::generate(&mut OsRng);
    let mut altered = real.clone();
    altered.subject_pubkey = attacker.verifying_key().to_bytes();
    session_err(server.enroll_finish(&altered, &attacker.sign(&altered.signing_bytes())));
    assert_eq!(server.admitted(), 1, "only the invite was admitted");
}

#[test]
fn a_challenge_is_consumed_once_and_a_bad_proof_does_not_burn_the_token() {
    let env = Env::new();
    let mut server = env.open();
    let invite = server.invite("h1").unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    let ch = server.enroll_begin(&invite.token, "h1", pk).unwrap();
    // proof by a key that does not hold the subject
    let thief = SigningKey::generate(&mut OsRng);
    assert!(server
        .enroll_finish(&ch, &thief.sign(&ch.signing_bytes()))
        .is_err());
    // the challenge is spent even so
    session_err(server.enroll_finish(&ch, &sk.sign(&ch.signing_bytes())));
    // the token is not: a fresh challenge enrolls
    let ch = server.enroll_begin(&invite.token, "h1", pk).unwrap();
    let done = server
        .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
        .unwrap();
    session_err(server.enroll_finish(&ch, &sk.sign(&ch.signing_bytes())));
    assert_eq!(done.cert.agent_pubkey, pk);
}

#[test]
fn a_reader_holding_the_whole_log_cannot_redeem_an_outstanding_invite() {
    let env = Env::new();
    let mut server = env.open();
    let invite = server.invite("h1").unwrap();
    let log = std::fs::read(env.log_path()).unwrap();
    assert!(
        !log.windows(invite.token.len())
            .any(|w| w == invite.token.as_bytes()),
        "the token is not in the log"
    );
    // what the log does hold is the digest; presenting it is not redeeming
    let digest = token_digest(&invite.token);
    let held = read_frames(&env).iter().flat_map(|f| f.sealed.iter()).any(
        |s| matches!(&s.event.payload.body, Body::Invite { verifier, .. } if *verifier == digest),
    );
    assert!(held, "the invite event carries the digest");
    let digest = digest.to_string();
    let sk = SigningKey::generate(&mut OsRng);
    session_err(server.enroll_begin(&digest, "h1", sk.verifying_key().to_bytes()));
    // and after a restart the invite is still outstanding and still redeemable
    drop(server);
    let mut server = env.open();
    let ch = server
        .enroll_begin(&invite.token, "h1", sk.verifying_key().to_bytes())
        .unwrap();
    server
        .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
        .unwrap();
}

#[test]
fn a_second_session_for_a_member_starts_pending_and_signs_nothing() {
    let mut env = Env::new();
    let mut server = env.open();
    let first = enroll(&mut server, "shep");
    let second = enroll(&mut server, "shep");
    assert!(second.pending);
    assert_eq!(
        server.sessions().get(&second.session).unwrap().status,
        Status::Pending
    );
    let (n, s) = env.brief(&second.key, None, "lane-a");
    assert!(matches!(
        server.admit(n, s),
        Err(ServerError::Refused(Refusal::PendingSession))
    ));
    // the first is unaffected
    let (n, s) = env.brief(&first.key, None, "lane-a");
    server.admit(n, s).unwrap();
}

#[test]
fn ending_a_session_and_bumping_the_epoch_is_one_frame() {
    let env = Env::new();
    let mut server = env.open();
    let h1 = enroll(&mut server, "h1");
    let before = read_frames(&env).len();
    server.end_session(&h1.session, EndReason::Lost).unwrap();
    assert_eq!(server.epoch(), 1);
    let frames = read_frames(&env);
    assert_eq!(frames.len(), before + 1, "one frame");
    let last = frames.last().unwrap();
    let kinds: Vec<_> = last.sealed.iter().map(|s| s.event.payload.kind).collect();
    assert_eq!(kinds, [Kind::SessionEnd, Kind::Epoch]);
    let epochs: Vec<_> = last.sealed.iter().map(|s| s.record.payload.epoch).collect();
    assert_eq!(epochs, [0, 1]);
    assert_eq!(
        server.sessions().get(&h1.session).unwrap().status,
        Status::Ended
    );
    session_err(server.end_session(&h1.session, EndReason::Closed));
}

#[test]
fn a_crash_during_end_session_leaves_both_events_or_neither() {
    for plan in [
        CrashPlan::AfterBytes(5),
        CrashPlan::AfterBytes(200),
        CrashPlan::BeforeSync,
        CrashPlan::AfterSync,
    ] {
        let env = Env::new();
        let mut server = env.open();
        let h1 = enroll(&mut server, "h1");
        server.plan_crash(Some(plan));
        assert!(server.end_session(&h1.session, EndReason::Closed).is_err());
        drop(server);
        let mut server = env.open();
        let whole = matches!(plan, CrashPlan::BeforeSync | CrashPlan::AfterSync);
        assert_eq!(server.epoch(), u64::from(whole), "{plan:?}");
        let status = server.sessions().get(&h1.session).unwrap().status;
        assert_eq!(status == Status::Ended, whole, "{plan:?}: ended iff bumped");
        if !whole {
            server.end_session(&h1.session, EndReason::Closed).unwrap();
            assert_eq!(server.epoch(), 1);
        }
    }
}

#[test]
fn an_old_epoch_certificate_is_refused_by_verify_at() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let h1 = enroll(&mut server, "h1");
    assert!(shep.key.cert().verify_at(0).is_ok());
    server.end_session(&h1.session, EndReason::Closed).unwrap();
    assert!(shep.key.cert().verify_at(1).is_err(), "bounded to epoch 0");
    let (n, s) = env.brief(&shep.key, None, "lane-a");
    assert!(matches!(server.admit(n, s), Err(ServerError::Signer(_))));
}

#[test]
fn an_ended_session_cannot_sign_even_with_a_valid_certificate() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let (n, s) = env.brief(&shep.key, None, "lane-a");
    let first = id(&n);
    server.admit(n, s).unwrap();
    server
        .end_session(&shep.session, EndReason::Closed)
        .unwrap();
    let (n, s) = env.brief(&shep.key, Some(first), "lane-b");
    assert!(matches!(server.admit(n, s), Err(ServerError::Signer(_))));
}

#[test]
fn a_fresh_reader_verifies_every_event_across_several_bumps() {
    let mut env = Env::new();
    let mut server = env.open();
    let mut shep = enroll(&mut server, "shep");
    let mut prev = None;
    for round in 0..4 {
        let (n, s) = env.brief(&shep.key, prev, &format!("lane-{round}"));
        prev = Some(id(&n));
        server.admit(n, s).unwrap();
        let throwaway = enroll(&mut server, "h1");
        bump_and_renew(&mut server, &throwaway, &mut [&mut shep]);
    }
    assert_eq!(server.epoch(), 4);
    let server_pub = server.server_pub();
    drop(server);
    // the reader holds only the bytes: each event verifies at the epoch its
    // own record names, with the certificate that record names
    let mut epochs_seen = std::collections::BTreeSet::new();
    for sealed in read_frames(&env).iter().flat_map(|f| f.sealed.iter()) {
        let (rec, cid) = (&sealed.record.payload, sealed.event.content_id().unwrap());
        sealed
            .event_sig
            .verify(&cid, &server_pub, rec.epoch)
            .unwrap();
        assert_eq!(rec.cert, cert_cid(sealed.event_sig.author()).unwrap());
        if sealed.event.payload.kind == Kind::Brief {
            epochs_seen.insert(rec.epoch);
        }
    }
    assert_eq!(
        epochs_seen,
        (0..4).collect(),
        "a brief at each epoch, each under its own certificate"
    );
    assert!(
        env.open().epoch() == 4,
        "and the server replays the same log"
    );
}

#[test]
fn a_session_that_missed_three_bumps_renews_through_renew() {
    let mut env = Env::new();
    let mut server = env.open();
    let mut shep = enroll(&mut server, "shep");
    for _ in 0..3 {
        let throwaway = enroll(&mut server, "h1");
        server
            .end_session(&throwaway.session, EndReason::Closed)
            .unwrap();
    }
    assert_eq!(server.epoch(), 3);
    let (n, s) = env.brief(&shep.key, None, "lane-a");
    assert!(server.admit(n, s).is_err(), "uncertified at epoch 3");
    let ch = server.renew_begin(shep.key.cert()).unwrap();
    let cert = server.renew_finish(&ch, &shep.prove(&ch)).unwrap();
    assert_eq!(cert.metadata.caveats, session_caveats(3));
    shep.recertify(cert);
    let (n, s) = env.brief(&shep.key, None, "lane-a");
    server.admit(n, s).unwrap();
    // already current: a second renewal is not needed and not issued
    session_err(server.renew_begin(shep.key.cert()));
}

#[test]
fn an_ended_session_cannot_renew_and_a_stranger_cannot_either() {
    let env = Env::new();
    let mut server = env.open();
    let h1 = enroll(&mut server, "h1");
    server.end_session(&h1.session, EndReason::Lost).unwrap();
    session_err(server.renew_begin(h1.key.cert()));
    assert!(
        server
            .renewal_challenges()
            .iter()
            .all(|(s, _)| *s != h1.session),
        "ended sessions are never challenged"
    );
    // a certificate the log never recorded for that session
    let forged = AgentKey::issue(
        &agent_mesh_protocol::UserKey::generate(),
        support::meta("x"),
    );
    session_err(server.renew_begin(forged.cert()));
}

#[test]
fn a_renewal_challenge_is_bound_to_its_session_and_epoch() {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let h1 = enroll(&mut server, "h1");
    let spare = enroll(&mut server, "h1");
    server
        .end_session(&spare.session, EndReason::Closed)
        .unwrap();
    let challenges = server.renewal_challenges();
    let (_, shep_ch) = challenges
        .iter()
        .find(|(s, _)| *s == shep.session)
        .unwrap()
        .clone();
    let (_, h1_ch) = challenges
        .iter()
        .find(|(s, _)| *s == h1.session)
        .unwrap()
        .clone();

    // a proof from the wrong session's key
    assert!(server.renew_finish(&shep_ch, &h1.prove(&shep_ch)).is_err());
    // the challenge is consumed by that attempt
    session_err(server.renew_finish(&shep_ch, &shep.prove(&shep_ch)));

    // racing a session end
    server.end_session(&h1.session, EndReason::Closed).unwrap();
    assert!(server.renew_finish(&h1_ch, &h1.prove(&h1_ch)).is_err());
}

#[test]
fn a_renewal_that_races_another_bump_is_refused() {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let a = enroll(&mut server, "h1");
    let b = enroll(&mut server, "h1");
    server.end_session(&a.session, EndReason::Closed).unwrap();
    let (_, ch) = server
        .renewal_challenges()
        .into_iter()
        .find(|(s, _)| *s == shep.session)
        .unwrap();
    server.end_session(&b.session, EndReason::Closed).unwrap(); // epoch 2 now
    let why = session_err(server.renew_finish(&ch, &shep.prove(&ch)));
    assert!(why.contains("moved"), "{why}");
}

#[test]
fn a_renewal_is_logged_with_its_certificate() {
    let env = Env::new();
    let mut server = env.open();
    let mut shep = enroll(&mut server, "shep");
    let h1 = enroll(&mut server, "h1");
    bump_and_renew(&mut server, &h1, &mut [&mut shep]);
    assert!(
        server.renewal_challenges().is_empty(),
        "a session already certified for the epoch is not challenged again"
    );
    let renewals: Vec<_> = read_frames(&env)
        .into_iter()
        .flat_map(|f| f.sealed)
        .filter(|s| s.event.payload.kind == Kind::Renewal)
        .collect();
    assert_eq!(renewals.len(), 1);
    let Body::Renewal {
        session,
        epoch,
        cert,
    } = &renewals[0].event.payload.body
    else {
        panic!("renewal body")
    };
    assert_eq!((session, *epoch), (&shep.session, 1));
    assert_eq!(cert, shep.key.cert());
}

#[test]
fn consumed_tokens_sessions_and_epochs_are_rebuilt_from_the_frames() {
    let env = Env::new();
    let mut server = env.open();
    let used = server.invite("h1").unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let ch = server
        .enroll_begin(&used.token, "h1", sk.verifying_key().to_bytes())
        .unwrap();
    server
        .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
        .unwrap();
    let mut shep = enroll(&mut server, "shep");
    let h1 = enroll(&mut server, "h1");
    bump_and_renew(&mut server, &h1, &mut [&mut shep]);
    let admitted = server.admitted();
    drop(server);

    let mut server = env.open();
    assert_eq!((server.admitted(), server.epoch()), (admitted, 1));
    assert_eq!(
        server.sessions().get(&h1.session).unwrap().status,
        Status::Ended
    );
    assert_eq!(server.sessions().get(&shep.session).unwrap().epoch, 1);
    // the consumed token stays consumed
    let again = SigningKey::generate(&mut OsRng);
    session_err(server.enroll_begin(&used.token, "h1", again.verifying_key().to_bytes()));
    // the ended session stays ended
    session_err(server.renew_begin(h1.key.cert()));
    // the renewed session signs after the restart
    let env_flock = env.flock;
    assert_eq!(server.flock(), env_flock);
    let mut env = env;
    let (n, s) = env.brief(&shep.key, None, "lane-a");
    server.admit(n, s).unwrap();
}

#[test]
fn server_events_are_checked_against_the_log_not_trusted() {
    let mut env = Env::new();
    let mut server = env.open();
    let key = env.server_key();
    // an unbounded session certificate is not a session certificate
    let invite = server.invite("h1").unwrap();
    let info = server
        .sessions()
        .invite(&token_digest(&invite.token))
        .unwrap();
    let rogue = key.delegate(support::meta("h1")).unwrap();
    let (n, s) = env.event(
        &key,
        Kind::SessionStart,
        None,
        &[("invite", info.event)],
        Body::SessionStart {
            member: "h1".into(),
            session: rogue.fingerprint().hex(),
            cert: rogue.cert().clone(),
        },
    );
    session_err(server.admit(n, s));
    // an epoch event whose body is not the epoch it moves to
    let (n, s) = env.event(&key, Kind::Epoch, None, &[], Body::Epoch { epoch: 5 });
    session_err(server.admit(n, s));
    assert_eq!(server.epoch(), 0);
}

/// A certificate for `sk`, bounded to `epoch`, minted straight from the
/// server key (what only the server could do, and the test of what the
/// replay rules refuse when it does it wrongly).
fn cert_for(env: &Env, sk: &SigningKey, epoch: u64) -> agent_mesh_protocol::CertChain {
    let key = env.server_key();
    let ch = key.possession_challenge(sk.verifying_key().to_bytes());
    let mut meta = support::meta("h1");
    meta.caveats = session_caveats(epoch);
    key.delegate_external(&ch, &sk.sign(&ch.signing_bytes()), meta)
        .unwrap()
}

fn bounded_cert(env: &Env, epoch: u64) -> (SigningKey, agent_mesh_protocol::CertChain) {
    let sk = SigningKey::generate(&mut OsRng);
    let cert = cert_for(env, &sk, epoch);
    (sk, cert)
}

#[test]
fn every_session_rule_holds_for_a_server_signed_event_too() {
    let mut env = Env::new();
    let mut server = env.open();
    let key = env.server_key();
    let live = enroll(&mut server, "h1");
    let used = server.sessions().get(&live.session).unwrap();
    let spare = server.invite("h1").unwrap();
    let spare_ev = server
        .sessions()
        .invite(&token_digest(&spare.token))
        .unwrap()
        .event;
    let consumed_ev = {
        // the invite `live` consumed: the one before its session-start
        let frames = read_frames(&env);
        let start = frames
            .iter()
            .flat_map(|f| &f.sealed)
            .find(|s| s.event.payload.kind == Kind::SessionStart)
            .unwrap();
        start.event.payload.refs["invite"]
    };
    let start = |env: &mut Env, invite, member: &str, session: String, cert| {
        env.event(
            &key,
            Kind::SessionStart,
            None,
            &[("invite", invite)],
            Body::SessionStart {
                member: member.into(),
                session,
                cert,
            },
        )
    };
    let (_, c1) = bounded_cert(&env, 0);
    let fp = |c: &agent_mesh_protocol::CertChain| c.agent_fingerprint().hex();
    let cases: Vec<(&str, (_, _))> = vec![
        (
            "consumed invite",
            start(&mut env, consumed_ev, "h1", fp(&c1), c1.clone()),
        ),
        (
            "another member's invite",
            start(&mut env, spare_ev, "shep", fp(&c1), c1.clone()),
        ),
        (
            "certificate for another key",
            start(&mut env, spare_ev, "h1", "ab".repeat(32), c1.clone()),
        ),
        (
            "unknown invite",
            start(&mut env, used.start, "h1", fp(&c1), c1.clone()),
        ),
        ("wrong epoch", {
            let (_, c) = bounded_cert(&env, 9);
            start(&mut env, spare_ev, "h1", fp(&c), c)
        }),
        (
            "key already enrolled",
            start(
                &mut env,
                spare_ev,
                "h1",
                live.session.clone(),
                live.key.cert().clone(),
            ),
        ),
        ("duplicate verifier", {
            env.event(
                &key,
                Kind::Invite,
                None,
                &[],
                Body::Invite {
                    member: "h1".into(),
                    verifier: token_digest(&spare.token),
                },
            )
        }),
        (
            "renewal for the wrong epoch",
            env.event(
                &key,
                Kind::Renewal,
                None,
                &[("session", used.start)],
                Body::Renewal {
                    session: live.session.clone(),
                    epoch: 3,
                    cert: live.key.cert().clone(),
                },
            ),
        ),
        (
            "renewal already current",
            env.event(
                &key,
                Kind::Renewal,
                None,
                &[("session", used.start)],
                Body::Renewal {
                    session: live.session.clone(),
                    epoch: 0,
                    cert: live.key.cert().clone(),
                },
            ),
        ),
        (
            "session-end naming another start",
            env.event(
                &key,
                Kind::SessionEnd,
                None,
                &[("session", spare_ev)],
                Body::SessionEnd {
                    session: live.session.clone(),
                    reason: EndReason::Closed,
                },
            ),
        ),
        (
            "session-end for no session",
            env.event(
                &key,
                Kind::SessionEnd,
                None,
                &[("session", used.start)],
                Body::SessionEnd {
                    session: "00".into(),
                    reason: EndReason::Closed,
                },
            ),
        ),
    ];
    let before = server.admitted();
    for (name, (n, s)) in cases {
        assert!(
            matches!(server.admit(n, s), Err(ServerError::Session(_))),
            "{name}"
        );
    }
    assert_eq!(server.admitted(), before, "nothing was written");
}

#[test]
fn an_ended_session_stays_dead_even_if_the_server_key_certifies_it_again() {
    let mut env = Env::new();
    let mut server = env.open();
    let key = env.server_key();
    let h1 = enroll(&mut server, "h1");
    let start = server.sessions().get(&h1.session).unwrap().start;
    server.end_session(&h1.session, EndReason::Closed).unwrap();
    // a certificate for the ended key, validly bounded to the new epoch
    let fresh = cert_for(&env, &h1.sk, 1);
    let revived = AgentKey::from_seed_and_cert(&h1.sk.to_bytes(), fresh.clone()).unwrap();
    let (n, s) = env.brief(&revived, None, "lane-a");
    let why = match server.admit(n, s) {
        Err(ServerError::Signer(why)) => why,
        other => panic!("expected a signer refusal, got {other:?}"),
    };
    assert!(why.contains("ended"), "{why}");
    // the server's own renewal and a second end are refused by the log rules
    let (n, s) = env.event(
        &key,
        Kind::Renewal,
        None,
        &[("session", start)],
        Body::Renewal {
            session: h1.session.clone(),
            epoch: 1,
            cert: fresh,
        },
    );
    session_err(server.admit(n, s));
    let (n, s) = env.event(
        &key,
        Kind::SessionEnd,
        None,
        &[("session", start)],
        Body::SessionEnd {
            session: h1.session.clone(),
            reason: EndReason::Lost,
        },
    );
    session_err(server.admit(n, s));
}

#[test]
fn a_renewal_must_match_the_epoch_and_be_issued_by_the_server_itself() {
    let mut env = Env::new();
    let mut server = env.open();
    let key = env.server_key();
    let shep = enroll(&mut server, "shep");
    let h1 = enroll(&mut server, "h1");
    let mut peer = enroll(&mut server, "h1");
    let start = server.sessions().get(&shep.session).unwrap().start;
    // epoch 1; the peer renews, the shepherd has not yet
    bump_and_renew(&mut server, &h1, &mut [&mut peer]);
    let good = cert_for(&env, &shep.sk, 1);
    let renewal = |env: &mut Env, epoch, cert: agent_mesh_protocol::CertChain| {
        env.event(
            &key,
            Kind::Renewal,
            None,
            &[("session", start)],
            Body::Renewal {
                session: shep.session.clone(),
                epoch,
                cert,
            },
        )
    };
    // the body claims an epoch the record is not at
    let (n, s) = renewal(&mut env, 5, good.clone());
    session_err(server.admit(n, s));
    // a certificate for the shepherd's key issued by another session, not
    // by the server key: it verifies and chains to the server, but is refused
    let ch = peer
        .key
        .possession_challenge(shep.sk.verifying_key().to_bytes());
    let mut meta = support::meta("shep");
    meta.caveats = session_caveats(1);
    let by_peer = peer
        .key
        .delegate_external(&ch, &shep.sk.sign(&ch.signing_bytes()), meta)
        .unwrap();
    assert!(by_peer.verify_at(1).is_ok());
    let (n, s) = renewal(&mut env, 1, by_peer);
    session_err(server.admit(n, s));
    // the right one is admitted
    let (n, s) = renewal(&mut env, 1, good);
    server.admit(n, s).unwrap();
}

#[test]
fn renew_wants_a_certificate_the_log_recorded() {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let spare = enroll(&mut server, "h1");
    server
        .end_session(&spare.session, EndReason::Closed)
        .unwrap();
    // a genuine server-issued certificate for the live key that never reached the log
    let unlogged = cert_for(&env, &shep.sk, 1);
    session_err(server.renew_begin(&unlogged));
    server.renew_begin(shep.key.cert()).unwrap();
}

#[test]
fn a_peer_issued_certificate_for_a_stale_session_is_refused() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let mut h1 = enroll(&mut server, "h1");
    let spare = enroll(&mut server, "h1");
    // epoch 1; only the helper renews
    bump_and_renew(&mut server, &spare, &mut [&mut h1]);
    // the helper certifies the shepherd's key at epoch 1: it verifies and
    // chains to the server, but the server never issued it
    let ch = h1
        .key
        .possession_challenge(shep.sk.verifying_key().to_bytes());
    let mut meta = support::meta("shep");
    meta.caveats = session_caveats(1);
    let by_peer = h1
        .key
        .delegate_external(&ch, &shep.sk.sign(&ch.signing_bytes()), meta)
        .unwrap();
    assert!(by_peer.verify_at(1).is_ok());
    let revived = AgentKey::from_seed_and_cert(&shep.sk.to_bytes(), by_peer).unwrap();
    let (n, s) = env.brief(&revived, None, "lane-a");
    let why = match server.admit(n, s) {
        Err(ServerError::Signer(why)) => why,
        other => panic!("expected a signer refusal, got {other:?}"),
    };
    assert!(why.contains("issued"), "{why}");
}

#[test]
fn a_standalone_session_end_is_refused_live() {
    let mut env = Env::new();
    let mut server = env.open();
    let key = env.server_key();
    let h1 = enroll(&mut server, "h1");
    let start = server.sessions().get(&h1.session).unwrap().start;
    let (n, s) = env.event(
        &key,
        Kind::SessionEnd,
        None,
        &[("session", start)],
        Body::SessionEnd {
            session: h1.session.clone(),
            reason: EndReason::Closed,
        },
    );
    let before = server.admitted();
    let why = session_err(server.admit(n, s));
    assert!(why.contains("epoch"), "{why}");
    assert_eq!((server.admitted(), server.epoch()), (before, 0));
}

#[test]
fn a_frame_with_a_session_end_but_no_epoch_bump_fails_open_and_is_left_alone() {
    let env = Env::new();
    let mut server = env.open();
    let h1 = enroll(&mut server, "h1");
    server.end_session(&h1.session, EndReason::Closed).unwrap();
    drop(server);
    // re-encode canonically, with the epoch event removed from the last frame
    let mut frames = read_frames(&env);
    frames.last_mut().unwrap().sealed.truncate(1);
    let bytes: Vec<u8> = frames
        .iter()
        .flat_map(|f| agent_mesh_flock_server::encode(f).unwrap())
        .collect();
    std::fs::write(env.log_path(), &bytes).unwrap();
    assert!(matches!(
        agent_mesh_flock_server::Server::open(&env.dir()),
        Err(ServerError::Corrupt { .. })
    ));
    assert_eq!(std::fs::read(env.log_path()).unwrap(), bytes);
}
