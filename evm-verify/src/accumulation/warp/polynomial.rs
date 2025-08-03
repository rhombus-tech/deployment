//! Polynomial representation and operations for WARP
//!
//! This module implements multilinear polynomials and operations required for
//! the WARP linear-time accumulation scheme. Multilinear polynomials are
//! fundamental to the WARP construction as they provide the basis for
//! efficient constraint checking.

use std::collections::HashMap;
use std::ops::{Add, Mul, Sub, Neg};
use ark_ff::Field;
use ark_bls12_381::Fr;

use super::field::{FieldElement, WarpField};

/// Multilinear polynomial in evaluation form
/// Represented as a map from boolean vectors (as u64) to field elements
#[derive(Clone, Debug)]
pub struct MultilinearPolynomial {
    /// Number of variables in the polynomial
    pub num_vars: usize,
    
    /// Map from evaluation point (encoded as u64 for efficiency) to value
    pub evaluations: HashMap<u64, WarpField>,
}

impl MultilinearPolynomial {
    /// Create a new multilinear polynomial with n variables
    pub fn new(num_vars: usize) -> Self {
        let expected_size = 1 << num_vars; // 2^n evaluations
        let mut evaluations = HashMap::with_capacity(expected_size);
        
        // Initialize all evaluations to zero
        for i in 0..expected_size {
            evaluations.insert(i as u64, WarpField::zero());
        }
        
        Self {
            num_vars,
            evaluations,
        }
    }
    
    /// Create a constant polynomial (all evaluations are the same)
    pub fn constant(num_vars: usize, value: WarpField) -> Self {
        let expected_size = 1 << num_vars; // 2^n evaluations
        let mut evaluations = HashMap::with_capacity(expected_size);
        
        // Initialize all evaluations to the constant value
        for i in 0..expected_size {
            evaluations.insert(i as u64, value);
        }
        
        Self {
            num_vars,
            evaluations,
        }
    }
    
    /// Create a polynomial representing the i-th variable (X_i)
    pub fn variable(num_vars: usize, var_idx: usize) -> Self {
        if var_idx >= num_vars {
            panic!("Variable index out of bounds");
        }
        
        let expected_size = 1 << num_vars; // 2^n evaluations
        let mut evaluations = HashMap::with_capacity(expected_size);
        
        // For X_i, the evaluation is 1 when the i-th bit is set, 0 otherwise
        for point in 0..expected_size {
            let eval = if ((point >> var_idx) & 1) == 1 {
                WarpField::one()
            } else {
                WarpField::zero()
            };
            evaluations.insert(point as u64, eval);
        }
        
        Self {
            num_vars,
            evaluations,
        }
    }
    
    /// Evaluate the polynomial at a point
    pub fn evaluate(&self, point: &[bool]) -> WarpField {
        if point.len() != self.num_vars {
            panic!("Evaluation point has incorrect dimension");
        }
        
        // Convert boolean array to u64 for lookup
        let mut idx = 0u64;
        for (i, &bit) in point.iter().enumerate() {
            if bit {
                idx |= 1 << i;
            }
        }
        
        // Look up the evaluation
        *self.evaluations.get(&idx).unwrap_or(&WarpField::zero())
    }
    
    /// Calculate the sum of all evaluations (used in the sumcheck protocol)
    pub fn sum_evaluations(&self) -> WarpField {
        self.evaluations.values().fold(WarpField::zero(), |acc, &val| acc + val)
    }
    
    /// Restrict the polynomial by fixing the first variable to a specific value
    /// Returns a polynomial with one fewer variable
    pub fn restrict_variable(&self, var_idx: usize, value: bool) -> Self {
        if var_idx >= self.num_vars {
            panic!("Variable index out of bounds");
        }
        
        let new_num_vars = self.num_vars - 1;
        let expected_size = 1 << new_num_vars; // 2^(n-1) evaluations
        let mut new_evaluations = HashMap::with_capacity(expected_size);
        
        // For each evaluation point in the restricted polynomial
        for point in 0..expected_size {
            // Construct the full evaluation point by inserting the fixed variable
            let mut full_point = 0;
            let mut bit_idx = 0;
            
            for i in 0..self.num_vars {
                if i == var_idx {
                    // Insert the fixed value for the restricted variable
                    if value {
                        full_point |= 1 << i;
                    }
                } else {
                    // Copy bit from the restricted point
                    if ((point >> bit_idx) & 1) == 1 {
                        full_point |= 1 << i;
                    }
                    bit_idx += 1;
                }
            }
            
            // Copy the evaluation from the original polynomial
            let zero = WarpField::zero();
            let eval = self.evaluations.get(&(full_point as u64)).unwrap_or(&zero);
            new_evaluations.insert(point as u64, *eval);
        }
        
        Self {
            num_vars: new_num_vars,
            evaluations: new_evaluations,
        }
    }
    
    /// Convert a multilinear polynomial to a lower-degree univariate polynomial
    /// by fixing all but one variable to specific values
    pub fn to_univariate(&self, var_idx: usize, fixed_values: &[bool]) -> Vec<WarpField> {
        if fixed_values.len() != self.num_vars - 1 {
            panic!("Fixed values has incorrect length");
        }
        
        // The resulting univariate polynomial has degree 1
        let mut coeffs = vec![WarpField::zero(), WarpField::zero()];
        
        // Evaluate at x = 0 and x = 1
        for x in 0..2 {
            // Construct the full evaluation point
            let mut eval_point = Vec::with_capacity(self.num_vars);
            let mut fixed_idx = 0;
            
            for i in 0..self.num_vars {
                if i == var_idx {
                    eval_point.push(x == 1);
                } else {
                    eval_point.push(fixed_values[fixed_idx]);
                    fixed_idx += 1;
                }
            }
            
            // Evaluate the polynomial at this point
            coeffs[x] = self.evaluate(&eval_point);
        }
        
        // The resulting coefficients represent f(x) = coeffs[0] + coeffs[1]*x
        // Interpolate to get the coefficients of the univariate polynomial
        let a0 = coeffs[0];
        let a1 = coeffs[1] - coeffs[0];
        
        vec![a0, a1]
    }
}

// Implementation of addition for MultilinearPolynomial
impl Add for MultilinearPolynomial {
    type Output = Self;
    
    fn add(self, rhs: Self) -> Self::Output {
        if self.num_vars != rhs.num_vars {
            panic!("Cannot add polynomials with different numbers of variables");
        }
        
        let mut result = MultilinearPolynomial::new(self.num_vars);
        
        // Add the evaluations pointwise
        for (point, value) in self.evaluations {
            let rhs_value = rhs.evaluations.get(&point).copied().unwrap_or(WarpField::zero());
            result.evaluations.insert(point, value + rhs_value);
        }
        
        result
    }
}

// Implementation of subtraction for MultilinearPolynomial
impl Sub for MultilinearPolynomial {
    type Output = Self;
    
    fn sub(self, rhs: Self) -> Self::Output {
        if self.num_vars != rhs.num_vars {
            panic!("Cannot subtract polynomials with different numbers of variables");
        }
        
        let mut result = MultilinearPolynomial::new(self.num_vars);
        
        // Subtract the evaluations pointwise
        for (point, value) in self.evaluations {
            let zero = WarpField::zero();
            let rhs_value = rhs.evaluations.get(&point).unwrap_or(&zero);
            result.evaluations.insert(point, value - *rhs_value);
        }
        
        result
    }
}

// Implementation of multiplication for MultilinearPolynomial
impl Mul for MultilinearPolynomial {
    type Output = Self;
    
    fn mul(self, rhs: Self) -> Self::Output {
        if self.num_vars != rhs.num_vars {
            panic!("Cannot multiply polynomials with different numbers of variables");
        }
        
        let mut result = MultilinearPolynomial::new(self.num_vars);
        
        // Multiply the evaluations pointwise
        for (point, value) in self.evaluations {
            let zero = WarpField::zero();
            let rhs_value = rhs.evaluations.get(&point).unwrap_or(&zero);
            result.evaluations.insert(point, value * *rhs_value);
        }
        
        result
    }
}

// Implementation of negation for MultilinearPolynomial
impl Neg for MultilinearPolynomial {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        let mut result = MultilinearPolynomial::new(self.num_vars);
        
        // Negate each evaluation
        for (point, value) in self.evaluations {
            result.evaluations.insert(point, value.neg());
        }
        
        result
    }
}

/// Represents a multilinear extension (MLE) of a function
pub struct MultilinearExtension {
    /// Number of variables in the extension
    pub num_vars: usize,
}

impl MultilinearExtension {
    /// Create a new multilinear extension with n variables
    pub fn new(num_vars: usize) -> Self {
        Self { num_vars }
    }
    
    /// Evaluate a multilinear extension at a point in the extension field
    pub fn evaluate(&self, polynomial: &MultilinearPolynomial, point: &[WarpField]) -> WarpField {
        if polynomial.num_vars != self.num_vars || point.len() != self.num_vars {
            panic!("Dimension mismatch in multilinear extension evaluation");
        }
        
        // Evaluate using the standard multilinear extension formula
        // f(r) = ∑_x f(x) * ∏_i (1 - r_i) * (1 - x_i) + r_i * x_i
        let mut result = WarpField::zero();
        
        // Iterate over all possible boolean vectors
        for idx in 0..(1 << self.num_vars) {
            let mut weight = WarpField::one();
            let mut x = Vec::with_capacity(self.num_vars);
            
            // Extract the bits of idx to form the boolean vector x
            for i in 0..self.num_vars {
                let bit = ((idx >> i) & 1) == 1;
                x.push(bit);
                
                // Calculate the weight term: (1 - r_i) * (1 - x_i) + r_i * x_i
                let r_i = point[i];
                let x_i = if bit { WarpField::one() } else { WarpField::zero() };
                
                let term = if bit {
                    // r_i (when x_i = 1)
                    r_i
                } else {
                    // (1 - r_i) (when x_i = 0)
                    WarpField::one() - r_i
                };
                
                weight = weight * term;
            }
            
            // Look up the function value at x
            let fx = polynomial.evaluate(&x);
            
            // Accumulate the weighted term
            result = result + fx * weight;
        }
        
        result
    }
}

/// A claim that a multilinear polynomial evaluates to a specific value at a given point
#[derive(Clone, Debug)]
pub struct MultilinearEvalClaim {
    /// The point at which the polynomial is evaluated
    pub point: Vec<WarpField>,
    
    /// The claimed evaluation of the polynomial at the point
    pub value: WarpField,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_multilinear_polynomial_create() {
        // Create a constant polynomial
        let p1 = MultilinearPolynomial::constant(3, WarpField::from(5u64));
        assert_eq!(p1.evaluations.len(), 8); // 2^3 = 8 evaluations
        
        // Create a single variable polynomial (X_0)
        let p2 = MultilinearPolynomial::variable(3, 0);
        assert_eq!(p2.evaluations.len(), 8);
        
        // Check evaluation on all points
        for i in 0..8 {
            let point = [
                (i & 1) == 1,
                ((i >> 1) & 1) == 1,
                ((i >> 2) & 1) == 1,
            ];
            
            assert_eq!(p1.evaluate(&point), WarpField::from(5u64));
            assert_eq!(p2.evaluate(&point), if point[0] { WarpField::one() } else { WarpField::zero() });
        }
    }
    
    #[test]
    fn test_multilinear_operations() {
        // Create two polynomials
        let p1 = MultilinearPolynomial::constant(2, WarpField::from(3u64));
        let p2 = MultilinearPolynomial::variable(2, 0);
        
        // Test addition
        let p_add = p1.clone() + p2.clone();
        assert_eq!(p_add.evaluate(&[false, false]), WarpField::from(3u64));
        assert_eq!(p_add.evaluate(&[true, false]), WarpField::from(4u64));
        
        // Test multiplication
        let p_mul = p1.clone() * p2.clone();
        assert_eq!(p_mul.evaluate(&[false, false]), WarpField::zero());
        assert_eq!(p_mul.evaluate(&[true, false]), WarpField::from(3u64));
    }
    
    #[test]
    fn test_restriction() {
        let p = MultilinearPolynomial::variable(3, 0);
        
        // Restrict the first variable to true
        let p_restricted = p.restrict_variable(0, true);
        assert_eq!(p_restricted.num_vars, 2);
        assert_eq!(p_restricted.evaluate(&[false, false]), WarpField::one());
        assert_eq!(p_restricted.evaluate(&[true, false]), WarpField::one());
        
        // Restrict the first variable to false
        let p_restricted = p.restrict_variable(0, false);
        assert_eq!(p_restricted.num_vars, 2);
        assert_eq!(p_restricted.evaluate(&[false, false]), WarpField::zero());
        assert_eq!(p_restricted.evaluate(&[true, false]), WarpField::zero());
    }
    
    #[test]
    fn test_multilinear_extension() {
        // Create a simple multilinear polynomial
        let mut poly = MultilinearPolynomial::new(2);
        poly.evaluations.insert(0, WarpField::from(1u64));  // f(0,0) = 1
        poly.evaluations.insert(1, WarpField::from(2u64));  // f(1,0) = 2
        poly.evaluations.insert(2, WarpField::from(3u64));  // f(0,1) = 3
        poly.evaluations.insert(3, WarpField::from(4u64));  // f(1,1) = 4
        
        let mle = MultilinearExtension::new(2);
        
        // Test evaluation at a non-boolean point
        let two = WarpField::from(2u64);
        let half = two.inverse().unwrap();  // 1/2
        let point = [half, half];
        
        // Expected result: Each term has weight 1/4, so (1+2+3+4)/4 = 10/4 = 5/2
        let ten = WarpField::from(10u64);
        let four = WarpField::from(4u64);
        let expected = ten * four.inverse().unwrap();  // 10/4 = 5/2
        let result = mle.evaluate(&poly, &point);
        
        assert_eq!(result, expected);
    }
}
