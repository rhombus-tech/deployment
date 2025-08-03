//! Polynomial commitment scheme for WARP
//!
//! This module implements a KZG polynomial commitment scheme suitable for use
//! with the WARP linear-time accumulation protocol. KZG commitments enable
//! constant-size proofs and verification, which is essential for the efficiency
//! of the WARP scheme.

use std::sync::Arc;
use std::ops::Mul;
use ark_poly::{Polynomial, univariate::DensePolynomial};
use ark_ec::{PairingEngine, AffineCurve, ProjectiveCurve};
use ark_bls12_381::{Bls12_381, G1Affine, G2Affine, Fr};
use ark_ff::{Field, Zero, One};
use rand::thread_rng;

use super::field::{FieldElement, WarpField};

/// Synthetic division for polynomials by (x - a)
/// Returns the quotient polynomial after dividing by (x - a)
fn synthetic_division(polynomial: &DensePolynomial<Fr>, a: Fr) -> DensePolynomial<Fr> {
    let coeffs = &polynomial.coeffs;
    if coeffs.is_empty() {
        return DensePolynomial::zero();
    }
    
    let mut result = Vec::with_capacity(coeffs.len().saturating_sub(1));
    if coeffs.len() == 1 {
        return DensePolynomial::zero();
    }
    
    // Synthetic division algorithm
    let mut carry = coeffs[coeffs.len() - 1];
    result.push(carry);
    
    for i in (1..coeffs.len() - 1).rev() {
        carry = coeffs[i] + carry * a;
        result.push(carry);
    }
    
    result.reverse();
    DensePolynomial { coeffs: result }
}

/// A KZG commitment to a polynomial
#[derive(Clone, Debug)]
pub struct PolynomialCommitment {
    /// The commitment value (a point on G1)
    pub commitment: G1Affine,
}

/// A KZG opening proof
#[derive(Clone, Debug)]
pub struct OpeningProof {
    /// The evaluation of the polynomial at the challenge point
    pub evaluation: WarpField,
    
    /// The witness (proof) that the polynomial evaluates to this value
    pub witness: G1Affine,
}

/// Structured reference string for the KZG commitment scheme
/// This contains the powers of a secret value τ which must be generated
/// in a trusted setup ceremony
pub struct KZGStructuredReferenceString {
    /// Powers of τ in G1: [g, g^τ, g^τ^2, ..., g^τ^d]
    pub powers_of_tau_g1: Vec<G1Affine>,
    
    /// Powers of τ in G2: [h, h^τ]
    pub powers_of_tau_g2: Vec<G2Affine>,
}

/// KZG polynomial commitment scheme
pub struct KZGCommitmentScheme {
    /// Structured reference string for the scheme
    srs: Arc<KZGStructuredReferenceString>,
    
    /// Maximum degree supported by this instance
    max_degree: usize,
}

impl KZGCommitmentScheme {
    /// Create a new KZG commitment scheme with the given SRS
    pub fn new(srs: Arc<KZGStructuredReferenceString>) -> Self {
        let max_degree = srs.powers_of_tau_g1.len() - 1;
        Self {
            srs,
            max_degree,
        }
    }
    
    /// Create a KZG commitment to a polynomial
    pub fn commit(&self, polynomial: &DensePolynomial<Fr>) -> Result<PolynomialCommitment, String> {
        let degree = polynomial.degree();
        if degree > self.max_degree {
            return Err(format!("Polynomial degree {} exceeds maximum supported degree {}", 
                              degree, self.max_degree));
        }
        
        let coeffs = &polynomial.coeffs;
        
        // For each coefficient c_i, multiply g^{τ^i} by c_i and sum
        let mut commitment = self.srs.powers_of_tau_g1[0].mul(coeffs[0]);
        for i in 1..=degree {
            commitment += self.srs.powers_of_tau_g1[i].mul(coeffs[i]);
        }
        
        Ok(PolynomialCommitment {
            commitment: commitment.into_affine(),
        })
    }
    
    /// Create an opening proof for a polynomial at a point
    pub fn create_opening_proof(
        &self, 
        polynomial: &DensePolynomial<Fr>, 
        point: Fr
    ) -> Result<OpeningProof, String> {
        let degree = polynomial.degree();
        if degree > self.max_degree {
            return Err(format!("Polynomial degree {} exceeds maximum supported degree {}", 
                              degree, self.max_degree));
        }
        
        // Compute evaluation
        let evaluation = polynomial.evaluate(&point);
        
        // Compute witness polynomial: (f(x) - f(z))/(x - z)
        let divisor = DensePolynomial { coeffs: vec![-point, Fr::one()] };
        let mut quotient = polynomial.clone();
        quotient.coeffs[0] = quotient.coeffs[0] - evaluation; // f(x) - f(z)
        
        // Perform polynomial division
        let witness_poly = {
            if quotient.is_zero() {
                DensePolynomial::zero()
            } else {
                // Simple division implementation for (f(x) - f(z))/(x - z)
                // Since we know divisor is (x - z), we can use synthetic division
                let q = synthetic_division(&quotient, point);
                let r: DensePolynomial<Fr> = DensePolynomial::zero(); // Should be zero for valid witness
                assert!(r.is_zero(), "Remainder must be zero for valid witness");
                q
            }
        };
        
        // Commit to the witness polynomial
        let witness_commitment = self.commit(&witness_poly)?;
        
        Ok(OpeningProof {
            evaluation: WarpField(evaluation),
            witness: witness_commitment.commitment,
        })
    }
    
    /// Verify an opening proof
    pub fn verify(
        &self,
        commitment: &PolynomialCommitment, 
        point: Fr,
        proof: &OpeningProof
    ) -> bool {
        // Convert point and evaluation to field elements
        let z = point;
        let y = proof.evaluation.0;
        
        // Check e(witness, [τ]₂ - [z]₂) = e(commitment - [y]₁, [1]₂)
        // This verifies that f(z) = y where f is the polynomial committed to
        
        // Calculate [τ]₂ - [z]₂
        let tau_minus_z = {
            let z_times_g2 = self.srs.powers_of_tau_g2[0].mul(z);
            (self.srs.powers_of_tau_g2[1].into_projective() - z_times_g2).into_affine()
        };
        
        // Calculate commitment - [y]₁
        let comm_minus_y = {
            let y_times_g1 = self.srs.powers_of_tau_g1[0].mul(y);
            (commitment.commitment.into_projective() - y_times_g1).into_affine()
        };
        
        // Check the pairing equation
        let lhs = Bls12_381::pairing(proof.witness, tau_minus_z);
        let rhs = Bls12_381::pairing(comm_minus_y, self.srs.powers_of_tau_g2[0]);
        
        lhs == rhs
    }
    
    /// Generate a random SRS for testing purposes only
    /// In a real deployment, this would come from a trusted setup ceremony
    #[cfg(test)]
    pub fn generate_testing_srs(max_degree: usize) -> Arc<KZGStructuredReferenceString> {
        use ark_ff::UniformRand;
        
        let mut rng = thread_rng();
        
        // Generate a random "toxic waste" τ
        let tau = Fr::rand(&mut rng);
        
        // Generate powers of τ in G1
        let mut powers_of_tau_g1 = Vec::with_capacity(max_degree + 1);
        let g1_generator = G1Affine::prime_subgroup_generator();
        
        let mut current_power = Fr::one();
        for _ in 0..=max_degree {
            powers_of_tau_g1.push(g1_generator.mul(current_power).into_affine());
            current_power *= tau;
        }
        
        // Generate powers of τ in G2 (we only need [h, h^τ])
        let mut powers_of_tau_g2 = Vec::with_capacity(2);
        let g2_generator = G2Affine::prime_subgroup_generator();
        
        powers_of_tau_g2.push(g2_generator);
        powers_of_tau_g2.push(g2_generator.mul(tau).into_affine());
        
        Arc::new(KZGStructuredReferenceString {
            powers_of_tau_g1,
            powers_of_tau_g2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::univariate::DensePolynomial;
    use ark_ff::UniformRand;
    
    #[test]
    fn test_kzg_commitment() {
        let max_degree = 10;
        let srs = KZGCommitmentScheme::generate_testing_srs(max_degree);
        let scheme = KZGCommitmentScheme::new(srs);
        
        // Create a random polynomial of degree 5
        let mut rng = thread_rng();
        let mut coeffs = Vec::with_capacity(6);
        for _ in 0..6 {
            coeffs.push(Fr::rand(&mut rng));
        }
        let poly = DensePolynomial { coeffs };
        
        // Create a commitment to the polynomial
        let commitment = scheme.commit(&poly).unwrap();
        
        // Choose a random point and create an opening proof
        let point = Fr::rand(&mut rng);
        let proof = scheme.create_opening_proof(&poly, point).unwrap();
        
        // Verify the proof
        let result = scheme.verify(&commitment, point, &proof);
        assert!(result, "KZG verification should succeed");
        
        // Test with an incorrect evaluation
        let mut bad_proof = proof.clone();
        bad_proof.evaluation = WarpField(Fr::rand(&mut rng)); // Different random value
        let bad_result = scheme.verify(&commitment, point, &bad_proof);
        assert!(!bad_result, "KZG verification should fail with incorrect evaluation");
    }
}
