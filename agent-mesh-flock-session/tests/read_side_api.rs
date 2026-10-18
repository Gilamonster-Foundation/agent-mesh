//! Feature names are not an API audit: a missed `#[cfg]` leaves a signing or
//! mutating function public with both writer features off, and the
//! `cargo tree` check in `read_side.rs` cannot see it. So this compiles a real
//! consumer of the two crates (see `tests_common::readside`).
#![cfg(unix)]

use std::path::Path;

#[test]
fn writer_apis_do_not_resolve_for_a_read_only_consumer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    tests_common::readside::assert_no_writer_apis(root, &[]);
}
