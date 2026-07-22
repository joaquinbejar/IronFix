/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 22/7/26
******************************************************************************/

//! Compile-time proof that the derives type-check on a generic struct.
//!
//! A field whose type is a bare type parameter takes the fallback wire path:
//! `decode` calls [`FieldRef::parse`](ironfix_core::field::FieldRef::parse),
//! which needs [`FromStr`](std::str::FromStr), and `encode` formats with `{}`,
//! which needs [`Display`](std::fmt::Display). The user below declares only
//! `T: Clone`, so unless the derive adds those bounds the generated `impl`
//! blocks below fail to type-check — which is what this test asserts, simply by
//! being a crate that must compile. A generic `impl` is checked at definition
//! time, so the bound is exercised even without instantiating `T`.

use ironfix_derive::{FixField, FixMessage};

/// A generic message whose only field is a bare type parameter, forcing the
/// `FromStr` + `Display` fallback bound onto the generated `FixMessage` impl.
#[derive(FixMessage)]
#[fix(msg_type = "D")]
struct GenericOrder<T: Clone> {
    /// Takes the fallback wire path.
    #[fix(tag = 11)]
    id: T,
    /// An optional generic field is bounded on its inner type, not `Option`.
    #[fix(tag = 44)]
    price: Option<T>,
}

/// A generic field wrapper, exercising the same fallback bound on the generated
/// `FixField` impl.
#[derive(FixField)]
#[fix(tag = 11)]
struct GenericField<T: Clone>(T);

#[test]
fn test_generic_derives_type_check_and_instantiate() {
    // `i64` satisfies the bounds the derive added; constructing the types is a
    // further check beyond the definition-time one the impls already passed.
    let order = GenericOrder::<i64> {
        id: 7,
        price: Some(42),
    };
    let field = GenericField::<i64>(7);
    assert_eq!(order.id, 7);
    assert_eq!(order.price, Some(42));
    assert_eq!(field.0, 7);
}
