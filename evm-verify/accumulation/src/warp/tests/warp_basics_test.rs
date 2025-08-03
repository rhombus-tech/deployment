//! Basic tests for WARP verification system core components

use crate::warp::field::WarpField;
use ark_ff::{Field, One, Zero};

/// Test basic arithmetic operations on the WarpField
#[test]
fn test_warp_field_arithmetic() {
    // Test basic operations
    let a = WarpField::from(5u64);
    let b = WarpField::from(3u64);
    
    // Addition
    assert_eq!(a + b, WarpField::from(8u64));
    
    // Subtraction
    assert_eq!(a - b, WarpField::from(2u64));
    
    // Multiplication
    assert_eq!(a * b, WarpField::from(15u64));
    
    // Identities
    assert_eq!(a + WarpField::zero(), a);
    assert_eq!(a * WarpField::one(), a);
    
    // Inverse and division
    let b_inv = b.inverse().unwrap();
    assert_eq!(b * b_inv, WarpField::one());
}

/// Test additional field properties
#[test]
fn test_field_properties() {
    // Commutativity
    let a = WarpField::from(7u64);
    let b = WarpField::from(11u64);
    
    assert_eq!(a + b, b + a);
    assert_eq!(a * b, b * a);
    
    // Associativity
    let c = WarpField::from(13u64);
    assert_eq!((a + b) + c, a + (b + c));
    assert_eq!((a * b) * c, a * (b * c));
    
    // Distributivity
    assert_eq!(a * (b + c), a * b + a * c);
}

/// Test serialization and deserialization
#[test]
fn test_field_serialization() {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    
    let a = WarpField::from(42u64);
    let mut serialized = vec![];
    a.serialize(&mut serialized).unwrap();
    
    let b = WarpField::deserialize(&serialized[..]).unwrap();
    assert_eq!(a, b);
}
