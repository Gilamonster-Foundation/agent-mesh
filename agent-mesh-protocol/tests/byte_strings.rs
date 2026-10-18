//! Keys, signatures and fingerprints are CBOR byte strings (major type 2) in
//! the canonical encoding, not arrays of one integer per byte. An array costs
//! 1-2 bytes per byte and makes a record's size depend on its key's bytes.

use agent_mesh_protocol::{
    AgentKey, AgentMetadata, Assertion, Caveats, CertChain, Fingerprint, UserKey, UserPublic,
};
use content_addressable::canonical::{from_canonical_dagcbor_checked, to_canonical_dagcbor};
use content_addressable::ContentId;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Serialize, Serializer};
use std::fmt;

/// What the encoding looks like, read without trusting any of our types.
#[derive(Debug, Default)]
struct Shape {
    /// Lengths of every byte string.
    byte_strings: Vec<usize>,
    /// Sequences of 32 or 64 small integers: a key or signature written as
    /// an array.
    int_arrays: usize,
}

impl Serialize for Shape {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for Shape {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Shape;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any cbor")
            }
            fn visit_bytes<E: de::Error>(self, b: &[u8]) -> Result<Shape, E> {
                Ok(Shape {
                    byte_strings: vec![b.len()],
                    int_arrays: 0,
                })
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Shape, A::Error> {
                let mut out = Shape::default();
                let (mut n, mut all_small) = (0, true);
                while let Some(item) = a.next_element::<Item>()? {
                    n += 1;
                    match item {
                        Item::Small => {}
                        Item::Shape(s) => {
                            all_small = false;
                            out.byte_strings.extend(s.byte_strings);
                            out.int_arrays += s.int_arrays;
                        }
                    }
                }
                if all_small && (n == 32 || n == 64) {
                    out.int_arrays += 1;
                }
                Ok(out)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Shape, A::Error> {
                let mut out = Shape::default();
                while let Some((_, v)) = m.next_entry::<de::IgnoredAny, Shape>()? {
                    out.byte_strings.extend(v.byte_strings);
                    out.int_arrays += v.int_arrays;
                }
                Ok(out)
            }
            fn visit_newtype_struct<D2: Deserializer<'de>>(
                self,
                d: D2,
            ) -> Result<Shape, D2::Error> {
                Shape::deserialize(d)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Shape, E> {
                Ok(Shape::default())
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Shape, E> {
                Ok(Shape::default())
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Shape, E> {
                Ok(Shape::default())
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Shape, E> {
                Ok(Shape::default())
            }
            fn visit_unit<E: de::Error>(self) -> Result<Shape, E> {
                Ok(Shape::default())
            }
            fn visit_none<E: de::Error>(self) -> Result<Shape, E> {
                Ok(Shape::default())
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Shape, E> {
                Ok(Shape::default())
            }
        }
        d.deserialize_any(V)
    }
}

/// A sequence element: a small integer, or anything else.
enum Item {
    Small,
    Shape(Shape),
}

impl<'de> Deserialize<'de> for Item {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // a small integer, or anything else read as a Shape
        struct Either;
        impl<'de> Visitor<'de> for Either {
            type Value = Item;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any cbor")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Item, E> {
                Ok(if v < 256 {
                    Item::Small
                } else {
                    Item::Shape(Shape::default())
                })
            }
            fn visit_bytes<E: de::Error>(self, b: &[u8]) -> Result<Item, E> {
                Ok(Item::Shape(Shape {
                    byte_strings: vec![b.len()],
                    int_arrays: 0,
                }))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, a: A) -> Result<Item, A::Error> {
                Ok(Item::Shape(de::Deserialize::deserialize(
                    de::value::SeqAccessDeserializer::new(a),
                )?))
            }
            fn visit_map<A: MapAccess<'de>>(self, m: A) -> Result<Item, A::Error> {
                Ok(Item::Shape(de::Deserialize::deserialize(
                    de::value::MapAccessDeserializer::new(m),
                )?))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Item, E> {
                Ok(Item::Shape(Shape::default()))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Item, E> {
                Ok(Item::Shape(Shape::default()))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Item, E> {
                Ok(Item::Shape(Shape::default()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Item, E> {
                Ok(Item::Shape(Shape::default()))
            }
        }
        d.deserialize_any(Either)
    }
}

// Reading the *shape* of bytes, not a value we then use: the unchecked reader is
// the right tool, because `Shape` cannot round-trip to the same bytes.
#[allow(deprecated)]
fn shape<T: Serialize>(v: &T) -> Shape {
    use content_addressable::canonical::from_canonical_dagcbor;
    let bytes = to_canonical_dagcbor(v).unwrap();
    from_canonical_dagcbor::<Shape>(&bytes).unwrap()
}

fn meta() -> AgentMetadata {
    AgentMetadata {
        role: "helper".into(),
        host: "h".into(),
        capabilities: vec![],
        issued_at: "2026-10-18T00:00:00Z".into(),
        expires_at: None,
        caveats: Caveats::top(),
    }
}

/// A session key under a server key under a user: two links, as in a flock.
fn chain() -> (UserKey, AgentKey, AgentKey) {
    let user = UserKey::generate();
    let server = AgentKey::issue(&user, meta());
    let session = server.delegate(meta()).unwrap();
    (user, server, session)
}

#[test]
fn a_cert_chain_encodes_its_keys_and_signatures_as_byte_strings() {
    let (_, _, session) = chain();
    let s = shape(session.cert());
    assert_eq!(
        s.int_arrays, 0,
        "no key or signature may be an integer array"
    );
    // session: agent_pubkey, issuer_sig; parent: Agent.pubkey, agent_pubkey,
    // issuer_sig; the user key under the parent
    let mut got = s.byte_strings.clone();
    got.sort_unstable();
    assert_eq!(got, vec![32, 32, 32, 32, 64, 64]);
}

#[test]
fn an_assertion_encodes_its_signature_as_a_byte_string() {
    let (_, _, session) = chain();
    let a = Assertion::sign(&session, &ContentId::from_canonical_bytes(b"x"));
    let s = shape(&a);
    assert_eq!(s.int_arrays, 0);
    assert_eq!(
        s.byte_strings.iter().filter(|n| **n == 64).count(),
        3,
        "sig + two cert sigs"
    );
}

#[test]
fn a_fingerprint_and_a_user_key_encode_as_byte_strings() {
    let (user, _, _) = chain();
    for s in [shape(&Fingerprint([9; 32])), shape(&user.public())] {
        assert_eq!(s.int_arrays, 0);
        assert_eq!(s.byte_strings, vec![32]);
    }
}

#[test]
fn everything_round_trips_through_the_canonical_codec() {
    let (user, _, session) = chain();
    let a = Assertion::sign(&session, &ContentId::from_canonical_bytes(b"x"));
    let bytes = to_canonical_dagcbor(&a).unwrap();
    let back: Assertion = from_canonical_dagcbor_checked(&bytes).unwrap();
    assert_eq!(back, a);
    back.author().verify().unwrap();
    let c: CertChain =
        from_canonical_dagcbor_checked(&to_canonical_dagcbor(session.cert()).unwrap()).unwrap();
    assert_eq!(&c, session.cert());
    let f: Fingerprint =
        from_canonical_dagcbor_checked(&to_canonical_dagcbor(&Fingerprint([3; 32])).unwrap())
            .unwrap();
    assert_eq!(f, Fingerprint([3; 32]));
    let u: UserPublic =
        from_canonical_dagcbor_checked(&to_canonical_dagcbor(&user.public()).unwrap()).unwrap();
    assert_eq!(u, user.public());
}

#[test]
fn the_size_does_not_depend_on_the_bytes_of_the_keys() {
    // all-low and all-high key bytes cost the same as byte strings (as arrays
    // they were 34 vs 66 bytes)
    let lo = to_canonical_dagcbor(&Fingerprint([1; 32])).unwrap().len();
    let hi = to_canonical_dagcbor(&Fingerprint([250; 32])).unwrap().len();
    assert_eq!(lo, hi);
    assert_eq!(lo, 34);
}
