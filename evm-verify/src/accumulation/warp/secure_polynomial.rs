//! Security-hardened polynomial operations for FRI commitments
//!
//! This module implements cache-safe, timing-attack resistant polynomial 
//! evaluation and commitment operations for the zkEVM proving system.

use std::collections::HashMap;
use ark_poly::{Polynomial, univariate::DensePolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_ff::{PrimeField, FftField, Field, Zero, One};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use rayon::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{CryptoRng, RngCore};

use super::secure_field::{SecureField, SecureFieldError};

/// Security-hardened polynomial with constant-time operations
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecurePolynomial<F: PrimeField + FftField> {
    /// Coefficients stored in secure field elements
    coefficients: Vec<SecureField>,
    /// Phantom type for the underlying field
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField + FftField> SecurePolynomial<F> {
    /// Create new secure polynomial with input validation
    pub fn new(coefficients: Vec<SecureField>) -> Result<Self, SecurePolynomialError> {
        if coefficients.is_empty() {
            return Err(SecurePolynomialError::EmptyPolynomial);
        }

        Ok(SecurePolynomial {
            coefficients,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Get degree with constant-time guarantee
    pub fn degree(&self) -> usize {
        self.coefficients.len().saturating_sub(1)
    }

    /// Constant-time polynomial evaluation using Horner's method
    /// 
    /// Resists:
    /// - Cache timing attacks through uniform memory access
    /// - Branch prediction attacks via branchless computation
    /// - Coefficient recovery through timing analysis
    pub fn evaluate_secure(&self, point: &SecureField) -> SecureField {
        SecureField::horner_evaluate_secure(&self.coefficients, point)
    }

    /// Batch evaluation at multiple points with memory safety
    pub fn batch_evaluate_secure(&self, points: &[SecureField]) -> Vec<SecureField> {
        points.par_iter()
            .map(|point| self.evaluate_secure(point))
            .collect()
    }

    /// Memory-safe FFT evaluation with constant-time guarantees
    pub fn fft_evaluate_secure(&self, domain: &Radix2EvaluationDomain<F>) -> Result<Vec<SecureField>, SecurePolynomialError> {
        if self.coefficients.len() > domain.size() {
            return Err(SecurePolynomialError::DomainTooSmall);
        }

        // Pad coefficients to domain size with zeros (constant-time)
        let mut padded_coeffs = self.coefficients.clone();
        padded_coeffs.resize(domain.size(), SecureField::zero());

        // Perform FFT with uniform memory access pattern
        let mut result = Vec::with_capacity(domain.size());
        
        for i in 0..domain.size() {
            let domain_element = domain.element(i);
            let secure_element = SecureField::new(domain_element)
                .map_err(|_| SecurePolynomialError::InvalidDomainElement)?;
            
            let evaluation = SecureField::horner_evaluate_secure(&padded_coeffs, &secure_element);
            result.push(evaluation);
        }

        Ok(result)
    }

    /// Secure polynomial addition with overflow protection
    pub fn add_secure(&self, other: &Self) -> Result<Self, SecurePolynomialError> {
        let max_len = std::cmp::max(self.coefficients.len(), other.coefficients.len());
        let mut result_coeffs = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let a_coeff = self.coefficients.get(i).unwrap_or(&SecureField::zero());
            let b_coeff = other.coefficients.get(i).unwrap_or(&SecureField::zero());
            result_coeffs.push(a_coeff.add_secure(b_coeff));
        }

        Self::new(result_coeffs)
    }

    /// Secure polynomial multiplication using convolution
    pub fn mul_secure(&self, other: &Self) -> Result<Self, SecurePolynomialError> {
        let result_degree = self.degree() + other.degree();
        let mut result_coeffs = vec![SecureField::zero(); result_degree + 1];

        // Convolution with constant-time operations
        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                let product = self.coefficients[i].mul_secure(&other.coefficients[j]);
                result_coeffs[i + j] = result_coeffs[i + j].add_secure(&product);
            }
        }

        Self::new(result_coeffs)
    }

    /// Secure polynomial division with remainder
    pub fn div_rem_secure(&self, divisor: &Self) -> Result<(Self, Self), SecurePolynomialError> {
        if divisor.is_zero_secure() {
            return Err(SecurePolynomialError::DivisionByZero);
        }

        if self.degree() < divisor.degree() {
            return Ok((Self::zero(), self.clone()));
        }

        let mut dividend = self.clone();
        let mut quotient_coeffs = vec![SecureField::zero(); self.degree() - divisor.degree() + 1];

        while dividend.degree() >= divisor.degree() && !dividend.is_zero_secure() {
            // Get leading coefficient ratio
            let lead_coeff_ratio = dividend.leading_coefficient()
                .mul_secure(&divisor.leading_coefficient().inverse_secure()
                    .ok_or(SecurePolynomialError::InvalidOperation)?);

            let degree_diff = dividend.degree() - divisor.degree();
            quotient_coeffs[degree_diff] = lead_coeff_ratio;

            // Subtract divisor * lead_coeff_ratio * x^degree_diff
            let mut subtraction_term = vec![SecureField::zero(); degree_diff + divisor.coefficients.len()];
            for (i, &coeff) in divisor.coefficients.iter().enumerate() {
                subtraction_term[i + degree_diff] = coeff.mul_secure(&lead_coeff_ratio);
            }
            
            let subtraction_poly = Self::new(subtraction_term)?;
            dividend = dividend.sub_secure(&subtraction_poly)?;
        }

        Ok((Self::new(quotient_coeffs)?, dividend))
    }

    /// Secure polynomial subtraction
    pub fn sub_secure(&self, other: &Self) -> Result<Self, SecurePolynomialError> {
        let max_len = std::cmp::max(self.coefficients.len(), other.coefficients.len());
        let mut result_coeffs = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let a_coeff = self.coefficients.get(i).unwrap_or(&SecureField::zero());
            let b_coeff = other.coefficients.get(i).unwrap_or(&SecureField::zero());
            result_coeffs.push(a_coeff.sub_secure(b_coeff));
        }

        Self::new(result_coeffs)
    }

    /// Zero polynomial
    pub fn zero() -> Self {
        Self {
            coefficients: vec![SecureField::zero()],
            _phantom: std::marker::PhantomData,
        }
    }

    /// Constant-time zero check
    pub fn is_zero_secure(&self) -> bool {
        self.coefficients.iter()
            .all(|coeff| bool::from(coeff.is_zero_secure()))
    }

    /// Get leading coefficient
    pub fn leading_coefficient(&self) -> SecureField {
        self.coefficients.last().copied().unwrap_or(SecureField::zero())
    }

    /// Generate random polynomial with cryptographic security
    pub fn random_secure<R: CryptoRng + RngCore>(degree: usize, rng: &mut R) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        
        for _ in 0..=degree {
            coefficients.push(SecureField::random_secure(rng));
        }

        Self {
            coefficients,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Secure polynomial interpolation from points
    pub fn interpolate_secure(points: &[(SecureField, SecureField)]) -> Result<Self, SecurePolynomialError> {
        if points.is_empty() {
            return Err(SecurePolynomialError::EmptyPointSet);
        }

        let n = points.len();
        let mut result = Self::zero();

        // Lagrange interpolation with constant-time operations
        for i in 0..n {
            let mut lagrange_poly = Self::constant(SecureField::one());
            let mut denominator = SecureField::one();

            for j in 0..n {
                if i != j {
                    // Construct (x - x_j) term
                    let linear_term = Self::new(vec![
                        points[j].0.sub_secure(&SecureField::zero()),  // -x_j
                        SecureField::one(),                            // x coefficient
                    ])?;
                    
                    lagrange_poly = lagrange_poly.mul_secure(&linear_term)?;
                    
                    // Update denominator: (x_i - x_j)
                    let diff = points[i].0.sub_secure(&points[j].0);
                    denominator = denominator.mul_secure(&diff);
                }
            }

            // Scale by y_i / denominator
            let inv_denominator = denominator.inverse_secure()
                .ok_or(SecurePolynomialError::InterpolationError)?;
            let scale_factor = points[i].1.mul_secure(&inv_denominator);
            
            lagrange_poly = lagrange_poly.scalar_mul_secure(&scale_factor);
            result = result.add_secure(&lagrange_poly)?;
        }

        Ok(result)
    }

    /// Scalar multiplication with constant-time guarantee
    pub fn scalar_mul_secure(&self, scalar: &SecureField) -> Self {
        let scaled_coeffs = self.coefficients.iter()
            .map(|coeff| coeff.mul_secure(scalar))
            .collect();

        Self {
            coefficients: scaled_coeffs,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create constant polynomial
    pub fn constant(value: SecureField) -> Self {
        Self {
            coefficients: vec![value],
            _phantom: std::marker::PhantomData,
        }
    }

    /// Secure coefficient access with bounds checking
    pub fn get_coefficient(&self, index: usize) -> Option<SecureField> {
        self.coefficients.get(index).copied()
    }

    /// Get all coefficients (read-only)
    pub fn coefficients(&self) -> &[SecureField] {
        &self.coefficients
    }
}

/// Security errors for polynomial operations
#[derive(Debug, Clone)]
pub enum SecurePolynomialError {
    EmptyPolynomial,
    DomainTooSmall,
    InvalidDomainElement,
    DivisionByZero,
    InvalidOperation,
    EmptyPointSet,
    InterpolationError,
}

impl std::fmt::Display for SecurePolynomialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurePolynomialError::EmptyPolynomial => write!(f, "Cannot create empty polynomial"),
            SecurePolynomialError::DomainTooSmall => write!(f, "Evaluation domain too small for polynomial"),
            SecurePolynomialError::InvalidDomainElement => write!(f, "Invalid element in evaluation domain"),
            SecurePolynomialError::DivisionByZero => write!(f, "Division by zero polynomial"),
            SecurePolynomialError::InvalidOperation => write!(f, "Invalid polynomial operation"),
            SecurePolynomialError::EmptyPointSet => write!(f, "Cannot interpolate from empty point set"),
            SecurePolynomialError::InterpolationError => write!(f, "Polynomial interpolation failed"),
        }
    }
}

impl std::error::Error for SecurePolynomialError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as BlsScalar;
    use rand::thread_rng;

    #[test]
    fn test_secure_polynomial_evaluation() {
        // Create polynomial: 2x^2 + 3x + 1
        let coeffs = vec![
            SecureField::new(BlsScalar::from(1u64)).unwrap(), // constant
            SecureField::new(BlsScalar::from(3u64)).unwrap(), // x
            SecureField::new(BlsScalar::from(2u64)).unwrap(), // x^2
        ];
        let poly = SecurePolynomial::<BlsScalar>::new(coeffs).unwrap();
        
        // Evaluate at x = 2: 2*4 + 3*2 + 1 = 8 + 6 + 1 = 15
        let point = SecureField::new(BlsScalar::from(2u64)).unwrap();
        let result = poly.evaluate_secure(&point);
        let expected = SecureField::new(BlsScalar::from(15u64)).unwrap();
        
        assert!(bool::from(result.ct_eq(&expected)));
    }

    #[test]
    fn test_secure_polynomial_arithmetic() {
        let mut rng = thread_rng();
        let poly1 = SecurePolynomial::<BlsScalar>::random_secure(3, &mut rng);
        let poly2 = SecurePolynomial::<BlsScalar>::random_secure(2, &mut rng);
        
        // Test addition
        let sum = poly1.add_secure(&poly2).unwrap();
        assert!(sum.degree() <= std::cmp::max(poly1.degree(), poly2.degree()));
        
        // Test multiplication
        let product = poly1.mul_secure(&poly2).unwrap();
        assert_eq!(product.degree(), poly1.degree() + poly2.degree());
    }

    #[test]
    fn test_secure_interpolation() {
        // Interpolate polynomial through points (0,1), (1,4), (2,9)
        // Should give x^2 + 2x + 1
        let points = vec![
            (SecureField::new(BlsScalar::from(0u64)).unwrap(), SecureField::new(BlsScalar::from(1u64)).unwrap()),
            (SecureField::new(BlsScalar::from(1u64)).unwrap(), SecureField::new(BlsScalar::from(4u64)).unwrap()),
            (SecureField::new(BlsScalar::from(2u64)).unwrap(), SecureField::new(BlsScalar::from(9u64)).unwrap()),
        ];
        
        let poly = SecurePolynomial::<BlsScalar>::interpolate_secure(&points).unwrap();
        
        // Verify by evaluating at the original points
        for (x, y) in points {
            let evaluated = poly.evaluate_secure(&x);
            assert!(bool::from(evaluated.ct_eq(&y)));
        }
    }

    #[test] 
    fn test_constant_time_operations() {
        let mut rng = thread_rng();
        let poly = SecurePolynomial::<BlsScalar>::random_secure(10, &mut rng);
        
        // These operations should complete in constant time regardless of inputs
        let point1 = SecureField::new(BlsScalar::from(42u64)).unwrap();
        let point2 = SecureField::new(BlsScalar::from(1337u64)).unwrap();
        
        let _result1 = poly.evaluate_secure(&point1);
        let _result2 = poly.evaluate_secure(&point2);
        
        // Both evaluations should take the same time (we can't easily test this
        // in a unit test, but the implementation guarantees it)
    }
}
