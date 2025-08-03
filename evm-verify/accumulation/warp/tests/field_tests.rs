use evm_verify::accumulation::warp::field::WarpField;
use ark_ff::{Field, One, Zero};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn test_field_basic_arithmetic() {
    // Test addition
    let a = WarpField::from(5u64);
    let b = WarpField::from(3u64);
    assert_eq!(a + b, WarpField::from(8u64));
    
    // Test subtraction
    assert_eq!(a - b, WarpField::from(2u64));
    
    // Test multiplication
    assert_eq!(a * b, WarpField::from(15u64));
    
    // Test division
    assert_eq!(a / a, WarpField::one());
}

#[test]
fn test_field_identities() {
    let a = WarpField::from(42u64);
    
    // Zero identity
    assert_eq!(a + WarpField::zero(), a);
    assert_eq!(WarpField::zero() + a, a);
    assert_eq!(a - WarpField::zero(), a);
    assert_eq!(a * WarpField::zero(), WarpField::zero());
    
    // One identity
    assert_eq!(a * WarpField::one(), a);
    assert_eq!(WarpField::one() * a, a);
    assert_eq!(a / WarpField::one(), a);
}

#[test]
fn test_field_inverse() {
    let a = WarpField::from(7u64);
    let a_inv = a.inverse().unwrap();
    
    // Check that a * a^-1 = 1
    assert_eq!(a * a_inv, WarpField::one());
}

#[test]
fn test_field_associativity() {
    let a = WarpField::from(5u64);
    let b = WarpField::from(3u64);
    let c = WarpField::from(7u64);
    
    // Addition is associative: (a + b) + c = a + (b + c)
    assert_eq!((a + b) + c, a + (b + c));
    
    // Multiplication is associative: (a * b) * c = a * (b * c)
    assert_eq!((a * b) * c, a * (b * c));
}

#[test]
fn test_field_commutativity() {
    let a = WarpField::from(5u64);
    let b = WarpField::from(3u64);
    
    // Addition is commutative: a + b = b + a
    assert_eq!(a + b, b + a);
    
    // Multiplication is commutative: a * b = b * a
    assert_eq!(a * b, b * a);
}

#[test]
fn test_field_distributivity() {
    let a = WarpField::from(5u64);
    let b = WarpField::from(3u64);
    let c = WarpField::from(7u64);
    
    // Multiplication distributes over addition: a * (b + c) = a * b + a * c
    assert_eq!(a * (b + c), a * b + a * c);
}

#[test]
fn test_field_serialization() {
    // Create a field element
    let original = WarpField::from(123456789u64);
    
    // Serialize to bytes
    let bytes = original.to_bytes();
    
    // Deserialize back
    let deserialized = WarpField::from_bytes(&bytes);
    
    // Check equality
    assert_eq!(original, deserialized);
}

#[test]
fn test_field_random_elements() {
    // Use a fixed seed for deterministic testing
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    // Generate random field elements
    let a = WarpField::rand(&mut rng);
    let b = WarpField::rand(&mut rng);
    
    // Ensure they are not equal (with very high probability)
    assert_ne!(a, b);
    
    // Basic arithmetic should still work
    let c = a + b;
    assert_eq!(c - a, b);
    assert_eq!(c - b, a);
}
