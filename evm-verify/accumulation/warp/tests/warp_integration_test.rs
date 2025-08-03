use ark_ff::{Field, One, Zero};
use ark_accumulation::warp::field::WarpField;
use ark_accumulation::warp::polynomial::{MultilinearPolynomial, evaluate_multilinear};
use ark_accumulation::warp::commitment::{KZGCommitment, KZGProof, commit, create_proof, verify_proof};
use ark_accumulation::warp::verification::{WarpVerificationStrategy, SecurityWarning, create_warp_verification_strategy};
use ark_accumulation::warp::integration::{is_warp_strategy, create_warp_context, verify_with_warp};

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
fn test_polynomial_creation_and_evaluation() {
    // Create a simple multilinear polynomial: f(x,y) = 1 + 2x + 3y + 4xy
    let coeffs = vec![
        WarpField::from(1u64), // constant term
        WarpField::from(2u64), // x term
        WarpField::from(3u64), // y term
        WarpField::from(4u64), // xy term
    ];
    
    let poly = MultilinearPolynomial::new(2, coeffs);
    
    // Evaluate at (1,1)
    let point = vec![WarpField::one(), WarpField::one()];
    let result = poly.evaluate(&point);
    
    // 1 + 2*1 + 3*1 + 4*1*1 = 10
    assert_eq!(result, WarpField::from(10u64));
    
    // Evaluate at (0,0)
    let point = vec![WarpField::zero(), WarpField::zero()];
    let result = poly.evaluate(&point);
    
    // 1 + 2*0 + 3*0 + 4*0*0 = 1
    assert_eq!(result, WarpField::from(1u64));
}

#[test]
fn test_commitment_creation() {
    // Setup a polynomial f(x,y) = 1 + 2x + 3y + 4xy
    let coeffs = vec![
        WarpField::from(1u64),
        WarpField::from(2u64),
        WarpField::from(3u64),
        WarpField::from(4u64),
    ];
    
    let poly = MultilinearPolynomial::new(2, coeffs);
    
    // Create a commitment - this should not panic
    let commitment = commit(&poly);
    
    // Basic checks that the commitment is not trivially invalid
    assert!(!commitment.commitment_value.is_zero());
}
