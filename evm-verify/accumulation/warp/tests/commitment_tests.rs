use evm_verify::accumulation::warp::field::WarpField;
use evm_verify::accumulation::warp::commitment::{KZGCommitmentScheme, generate_test_srs};
use evm_verify::accumulation::warp::polynomial::MultilinearPolynomial;
use ark_ff::{One, Zero};
use rand::{SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn test_kzg_commitment_basic() {
    // Generate a test SRS
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let max_degree = 16;
    let srs = generate_test_srs(&mut rng, max_degree);
    
    // Create a commitment scheme
    let scheme = KZGCommitmentScheme::new(srs);
    
    // Create a simple polynomial: f(x) = 1 + 2x
    let coeffs = vec![
        WarpField::from(1u64),
        WarpField::from(2u64),
    ];
    let poly = MultilinearPolynomial::new(1, coeffs);
    
    // Commit to the polynomial
    let commitment = scheme.commit(&poly);
    
    // Verify that the commitment is not trivial
    assert!(!commitment.is_zero());
}

#[test]
fn test_kzg_verification() {
    // Generate a test SRS
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let max_degree = 16;
    let srs = generate_test_srs(&mut rng, max_degree);
    
    // Create a commitment scheme
    let scheme = KZGCommitmentScheme::new(srs);
    
    // Create a polynomial: f(x) = 3 + 4x + 5x^2
    let coeffs = vec![
        WarpField::from(3u64),
        WarpField::from(4u64),
        WarpField::from(5u64),
    ];
    let poly = MultilinearPolynomial::new(2, coeffs);
    
    // Commit to the polynomial
    let commitment = scheme.commit(&poly);
    
    // Create an evaluation point
    let point = WarpField::from(7u64);
    
    // Evaluate the polynomial at the point
    let value = poly.evaluate(&vec![point]);
    
    // Create a proof of evaluation
    let proof = scheme.create_evaluation_proof(&poly, point);
    
    // Verify the proof
    let result = scheme.verify_evaluation(&commitment, point, value, &proof);
    
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_kzg_invalid_proof() {
    // Generate a test SRS
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let max_degree = 16;
    let srs = generate_test_srs(&mut rng, max_degree);
    
    // Create a commitment scheme
    let scheme = KZGCommitmentScheme::new(srs);
    
    // Create a polynomial: f(x) = 10 + 20x
    let coeffs = vec![
        WarpField::from(10u64),
        WarpField::from(20u64),
    ];
    let poly = MultilinearPolynomial::new(1, coeffs);
    
    // Commit to the polynomial
    let commitment = scheme.commit(&poly);
    
    // Create an evaluation point
    let point = WarpField::from(3u64);
    
    // Evaluate the polynomial at the point
    let actual_value = poly.evaluate(&vec![point]);
    
    // Use an incorrect value
    let incorrect_value = actual_value + WarpField::one();
    
    // Create a proof of evaluation
    let proof = scheme.create_evaluation_proof(&poly, point);
    
    // Verify the proof with incorrect value
    let result = scheme.verify_evaluation(&commitment, point, incorrect_value, &proof);
    
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should fail verification
}

#[test]
fn test_kzg_batch_verification() {
    // Generate a test SRS
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let max_degree = 16;
    let srs = generate_test_srs(&mut rng, max_degree);
    
    // Create a commitment scheme
    let scheme = KZGCommitmentScheme::new(srs);
    
    // Create two polynomials
    let poly1 = MultilinearPolynomial::new(1, vec![
        WarpField::from(1u64),
        WarpField::from(2u64),
    ]);
    
    let poly2 = MultilinearPolynomial::new(1, vec![
        WarpField::from(3u64),
        WarpField::from(4u64),
    ]);
    
    // Commit to both polynomials
    let commitment1 = scheme.commit(&poly1);
    let commitment2 = scheme.commit(&poly2);
    
    // Choose evaluation points
    let point1 = WarpField::from(5u64);
    let point2 = WarpField::from(6u64);
    
    // Evaluate polynomials
    let value1 = poly1.evaluate(&vec![point1]);
    let value2 = poly2.evaluate(&vec![point2]);
    
    // Create proofs
    let proof1 = scheme.create_evaluation_proof(&poly1, point1);
    let proof2 = scheme.create_evaluation_proof(&poly2, point2);
    
    // Create batch verification data
    let commitments = vec![commitment1, commitment2];
    let points = vec![point1, point2];
    let values = vec![value1, value2];
    let proofs = vec![proof1, proof2];
    
    // Verify batch
    let result = scheme.batch_verify_evaluations(&commitments, &points, &values, &proofs);
    
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_kzg_serialization() {
    // Generate a test SRS
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let max_degree = 16;
    let srs = generate_test_srs(&mut rng, max_degree);
    
    // Create a commitment scheme
    let scheme = KZGCommitmentScheme::new(srs.clone());
    
    // Create a polynomial
    let poly = MultilinearPolynomial::new(1, vec![
        WarpField::from(7u64),
        WarpField::from(8u64),
    ]);
    
    // Generate a commitment
    let commitment = scheme.commit(&poly);
    
    // Serialize commitment to bytes
    let serialized = commitment.to_bytes();
    
    // Deserialize
    let deserialized = scheme.commitment_from_bytes(&serialized).unwrap();
    
    // Check they're the same
    assert_eq!(commitment, deserialized);
}

#[test]
fn test_kzg_proof_serialization() {
    // Generate a test SRS
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let max_degree = 16;
    let srs = generate_test_srs(&mut rng, max_degree);
    
    // Create a commitment scheme
    let scheme = KZGCommitmentScheme::new(srs.clone());
    
    // Create a polynomial
    let poly = MultilinearPolynomial::new(1, vec![
        WarpField::from(9u64),
        WarpField::from(10u64),
    ]);
    
    // Generate a commitment
    let commitment = scheme.commit(&poly);
    
    // Create evaluation point and value
    let point = WarpField::from(11u64);
    let value = poly.evaluate(&vec![point]);
    
    // Create proof
    let proof = scheme.create_evaluation_proof(&poly, point);
    
    // Serialize proof
    let serialized = proof.to_bytes();
    
    // Deserialize
    let deserialized = scheme.proof_from_bytes(&serialized).unwrap();
    
    // Verify the deserialized proof works
    let result = scheme.verify_evaluation(&commitment, point, value, &deserialized);
    
    assert!(result.is_ok());
    assert!(result.unwrap());
}
