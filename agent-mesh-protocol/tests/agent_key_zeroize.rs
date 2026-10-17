//! A session key must scrub its seed when dropped. `AgentKey` owns its
//! signing key directly (no clone, no `ManuallyDrop`), so this bound is the
//! guarantee: if dalek's `zeroize` feature were ever turned off it stops
//! compiling.

use zeroize::ZeroizeOnDrop;

fn assert_scrubbed_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn the_signing_key_inside_an_agent_key_zeroizes_on_drop() {
    assert_scrubbed_on_drop::<ed25519_dalek::SigningKey>();
}
