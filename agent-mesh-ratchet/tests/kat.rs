//! Deterministic known-answer test.
//!
//! vodozemac session establishment mixes in a fresh random base key, so a
//! *ciphertext* can't be a stable KAT. The Olm *identity*, however, is fully
//! determined by the account's key material — so unpickling a FIXED account
//! pickle reproduces a FIXED Curve25519 identity key every time, with no clock
//! or RNG entering the asserted value.
//!
//! The pickle below was generated once (random keys), then frozen as a literal.
//! Re-deriving its public identity must always yield `EXPECTED_CURVE_ID`.

use agent_mesh_ratchet::{AccountPickle, RatchetAccount};

/// A frozen vodozemac account pickle (serde JSON form). Generated once, then
/// embedded verbatim. NOT a real-world secret — it exists only to anchor the
/// deterministic identity below.
const FIXED_PICKLE_JSON: &str = r#"{"signing_key":{"Normal":[158,204,156,55,146,164,158,41,192,125,80,38,161,111,240,112,45,79,65,140,227,26,233,85,178,111,45,14,186,109,182,51]},"diffie_hellman_key":[2,192,107,189,8,170,164,168,46,140,6,172,175,142,232,156,227,196,214,175,210,1,41,6,186,9,46,136,190,141,44,10],"one_time_keys":{"next_key_id":2,"public_keys":{"0":[223,94,237,100,8,157,156,151,19,28,19,239,64,213,220,78,212,194,122,69,43,17,253,109,70,70,129,216,35,83,24,26],"1":[112,1,52,95,31,27,162,147,199,26,79,154,188,194,169,198,175,214,200,102,146,157,218,79,234,16,63,71,219,215,76,61]},"private_keys":{"0":[129,176,154,199,140,251,133,183,123,56,43,61,118,65,51,145,76,94,251,2,119,45,203,253,176,208,183,78,192,161,195,202],"1":[76,241,169,18,155,222,231,94,98,116,27,162,30,33,97,32,128,202,133,75,1,48,160,30,244,77,35,122,129,208,81,202]}},"fallback_keys":{"key_id":0,"fallback_key":null,"previous_fallback_key":null}}"#;

/// The Curve25519 identity key (base64) that `FIXED_PICKLE_JSON` must always
/// reproduce.
const EXPECTED_CURVE_ID: &str = "aEBY0EEMBkxqKpLm/iMUW4IcO2pJNrks40TjqJgpRnM";

#[test]
fn fixed_pickle_reproduces_stable_identity() {
    let pickle: AccountPickle =
        serde_json::from_str(FIXED_PICKLE_JSON).expect("the frozen pickle parses");
    let account = RatchetAccount::from_pickle(pickle);
    assert_eq!(
        account.curve_identity_base64(),
        EXPECTED_CURVE_ID,
        "a fixed account pickle must deterministically reproduce its identity"
    );
}

#[test]
fn fixed_pickle_round_trips_through_serde() {
    // Unpickle -> re-pickle -> unpickle reproduces the same identity, proving
    // the deterministic seam is stable in both directions.
    let pickle: AccountPickle = serde_json::from_str(FIXED_PICKLE_JSON).unwrap();
    let account = RatchetAccount::from_pickle(pickle);
    let re_pickled = serde_json::to_string(&account.pickle()).unwrap();
    let reloaded: AccountPickle = serde_json::from_str(&re_pickled).unwrap();
    let account2 = RatchetAccount::from_pickle(reloaded);
    assert_eq!(account2.curve_identity_base64(), EXPECTED_CURVE_ID);
}
