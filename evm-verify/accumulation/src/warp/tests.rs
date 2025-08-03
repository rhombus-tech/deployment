//! Tests for WARP verification system

use crate::warp::field::WarpField;
use crate::warp::polynomial::{MultilinearPolynomial, evaluate_multilinear};
use crate::warp::commitment::{commit, create_proof, verify_proof};
use ark_ff::{Field, One, Zero};

#[test]
fn test_warp_field_arithmetic() {
    // Test basic arithmetic
    let a = WarpField::from(5u64);
    let b = WarpField::from(3u64);
    
    // Addition
    assert_eq!(a + b, WarpField::from(8u64));
    
    // Subtraction
    assert_eq!(a - b, WarpField::from(2u64));
    
    // Multiplication
    assert_eq!(a * b, WarpField::from(15u64));
    
    // Division
    assert_eq!(a / b, WarpField::from(5u64) / WarpField::from(3u64));
    
    // Multiplicative inverse
    let b_inv = b.inverse().unwrap();
    assert_eq!(b * b_inv, WarpField::one());
    
    // Field identities
    assert_eq!(a + WarpField::zero(), a);
    assert_eq!(a * WarpField::one(), a);
}

#[test]
fn test_multilinear_polynomial() {
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
fn test_commitment_and_proof() {
    // Setup a polynomial f(x,y) = 1 + 2x + 3y + 4xy
    let coeffs = vec![
        WarpField::from(1u64),
        WarpField::from(2u64),
        WarpField::from(3u64),
        WarpField::from(4u64),
    ];
    
    let poly = MultilinearPolynomial::new(2, coeffs);
    
    // Create a commitment
    let commitment = commit(&poly);
    
    // Evaluation point (2,3)
    let point = vec![WarpField::from(2u64), WarpField::from(3u64)];
    
    // Expected evaluation: 1 + 2*2 + 3*3 + 4*2*3 = 1 + 4 + 9 + 24 = 38
    let expected_eval = WarpField::from(38u64);
    
    // Create the proof
    let proof = create_proof(&poly, &point);
    
    // Verify the proof
    let result = verify_proof(&commitment, &point, expected_eval, &proof);
    assert!(result, "KZG proof verification failed");
}
