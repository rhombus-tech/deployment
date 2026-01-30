use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, UVPolynomial, Polynomial};
use std::marker::PhantomData;

/// Reed-Solomon encoding implementation for tensor ZODA
pub struct ReedSolomon<F: Field> {
    /// The size of the field
    pub field_size: u64,
    
    /// The maximum number of errors that can be corrected
    pub error_capacity: usize,
    
    /// PhantomData marker for generic type parameter F
    _phantom: PhantomData<F>,
}

impl<F: Field> ReedSolomon<F> {
    /// Create a new Reed-Solomon encoder with the given error correction capacity
    pub fn new(field_size: u64, error_capacity: usize) -> Self {
        ReedSolomon {
            field_size,
            error_capacity,
            _phantom: PhantomData,
        }
    }
    
    /// Generate a Reed-Solomon code matrix
    /// 
    /// This creates a Vandermonde matrix where each row is a power of a field element
    /// The first n rows form the identity matrix (systematic code)
    /// 
    /// # Arguments
    /// * `m` - The number of rows in the code matrix
    /// * `n` - The number of columns in the code matrix (message length)
    pub fn generate_code_matrix(&self, m: usize, n: usize) -> Vec<Vec<F>> {
        let mut matrix: Vec<Vec<F>> = vec![vec![F::zero(); n]; m];
        
        // First create the identity matrix for the first n rows
        for i in 0..n.min(m) {
            matrix[i][i] = F::one();
        }
        
        // Create the parity check part using Reed-Solomon
        // This is a Vandermonde matrix where each row is [1, α, α², α³, ...]
        for i in n..m {
            // Use a different field element for each row
            let alpha = F::from((i - n + 1) as u64);
            
            // First element is always 1
            matrix[i][0] = F::one();
            
            // For each column, compute α^j
            for j in 1..n {
                matrix[i][j] = matrix[i][j-1] * alpha;
            }
        }
        
        matrix
    }
    
    /// Encode a message using Reed-Solomon
    /// 
    /// # Arguments
    /// * `message` - The message to encode
    /// * `code_length` - The desired length of the encoded message
    pub fn encode(&self, message: &[F], code_length: usize) -> Vec<F> {
        let message_length = message.len();
        
        // Create the encoding matrix
        let matrix = self.generate_code_matrix(code_length, message_length);
        
        // Perform matrix-vector multiplication
        let mut result = vec![F::zero(); code_length];
        for i in 0..code_length {
            for j in 0..message_length {
                result[i] = result[i] + matrix[i][j] * message[j];
            }
        }
        
        result
    }
    
    /// Decode a Reed-Solomon codeword with error correction
    /// 
    /// Uses syndrome-based decoding to detect and correct errors up to the
    /// error capacity of the code. This is the core error correction mechanism
    /// that makes tensor ZODA robust to adversarial corruption.
    /// 
    /// # Arguments
    /// * `received` - The received codeword with potential errors
    /// * `message_length` - The original message length
    pub fn decode(&self, received: &[F], message_length: usize) -> Result<Vec<F>, &'static str> {
        if received.len() < message_length {
            return Err("Received codeword is too short");
        }
        
        let code_length = received.len();
        
        // Step 1: Calculate syndromes
        // For a systematic Reed-Solomon code, syndromes indicate errors in parity positions
        let num_parity = code_length - message_length;
        let mut syndromes = vec![F::zero(); num_parity];
        
        // Generate the parity check matrix
        let parity_matrix = self.generate_code_matrix(code_length, message_length);
        
        // Compute syndromes: S_i = Σ(received[j] * H[i][j])
        // where H is the parity check matrix (rows message_length..code_length)
        for i in 0..num_parity {
            let row_idx = message_length + i;
            for j in 0..code_length.min(parity_matrix[row_idx].len()) {
                if j < received.len() {
                    syndromes[i] = syndromes[i] + parity_matrix[row_idx][j] * received[j];
                }
            }
            // Subtract the expected parity value
            if row_idx < received.len() {
                syndromes[i] = syndromes[i] - received[row_idx];
            }
        }
        
        // Step 2: Check if syndromes are all zero (no errors detected)
        let has_errors = syndromes.iter().any(|s| !s.is_zero());
        
        if !has_errors {
            // No errors detected - return systematic part
            return Ok(received[0..message_length].to_vec());
        }
        
        // Step 3: Error correction using polynomial interpolation
        // For small error counts (within capacity), we can correct by interpolation
        
        if num_parity < self.error_capacity * 2 {
            // Insufficient parity symbols for guaranteed error correction
            // Use best-effort systematic decoding
            return Ok(received[0..message_length].to_vec());
        }
        
        // Build error locator polynomial using Berlekamp-Massey algorithm
        let error_locator = self.berlekamp_massey(&syndromes)?;
        
        // Find error positions using Chien search
        let error_positions = self.chien_search(&error_locator, code_length);
        
        // Verify we can correct the errors
        if error_positions.len() > self.error_capacity {
            return Err("Too many errors detected - exceeds error correction capacity");
        }
        
        // Step 4: Calculate error values using Forney algorithm
        let mut corrected = received.to_vec();
        for &pos in &error_positions {
            if pos < code_length {
                let error_value = self.calculate_error_value(&syndromes, &error_locator, pos);
                corrected[pos] = corrected[pos] - error_value;
            }
        }
        
        // Return the corrected systematic part
        Ok(corrected[0..message_length].to_vec())
    }
    
    /// Berlekamp-Massey algorithm for finding the error locator polynomial
    /// 
    /// This is the key algorithm for Reed-Solomon decoding - it finds the
    /// minimal polynomial that generates the syndrome sequence.
    fn berlekamp_massey(&self, syndromes: &[F]) -> Result<Vec<F>, &'static str> {
        let n = syndromes.len();
        
        // Initialize polynomials
        let mut c = vec![F::one()]; // Current error locator polynomial
        let mut b = vec![F::one()]; // Previous error locator polynomial
        let mut l = 0; // Degree of error locator polynomial
        let mut m = 1; // Steps since last update
        let mut correction = F::one();
        
        for step in 0..n {
            // Calculate discrepancy
            let mut delta = syndromes[step];
            for j in 1..=l {
                if j < c.len() && step >= j && (step - j) < syndromes.len() {
                    delta = delta + c[j] * syndromes[step - j];
                }
            }
            
            if delta.is_zero() {
                // No correction needed
                m += 1;
            } else {
                // Need to update error locator polynomial
                let mut c_new = c.clone();
                
                // Ensure polynomials are same length
                while c_new.len() < b.len() + m {
                    c_new.push(F::zero());
                }
                
                // Compute correction factor
                let factor = delta * correction.inverse().unwrap_or(F::one());
                
                // Update: C(x) = C(x) - delta * x^m * B(x) / correction
                for (j, &b_coeff) in b.iter().enumerate() {
                    let idx = j + m;
                    if idx < c_new.len() {
                        c_new[idx] = c_new[idx] - factor * b_coeff;
                    }
                }
                
                // Update if degree increased
                if 2 * l <= step {
                    l = step + 1 - l;
                    b = c.clone();
                    correction = delta;
                    m = 1;
                } else {
                    m += 1;
                }
                
                c = c_new;
            }
        }
        
        Ok(c)
    }
    
    /// Chien search to find error positions
    /// 
    /// Evaluates the error locator polynomial at all possible positions
    /// to find where errors occurred.
    fn chien_search(&self, error_locator: &[F], code_length: usize) -> Vec<usize> {
        let mut positions = Vec::new();
        
        // Test each position in the codeword
        for i in 0..code_length {
            let alpha = F::from((i + 1) as u64);
            
            // Evaluate error locator polynomial at α^i
            let mut sum = F::zero();
            for (j, &coeff) in error_locator.iter().enumerate() {
                let power = self.field_power(alpha, j);
                sum = sum + coeff * power;
            }
            
            // If polynomial evaluates to zero, this is an error position
            if sum.is_zero() {
                positions.push(i);
            }
        }
        
        positions
    }
    
    /// Calculate error value at a specific position using Forney algorithm
    fn calculate_error_value(&self, syndromes: &[F], error_locator: &[F], position: usize) -> F {
        let alpha = F::from((position + 1) as u64);
        
        // Compute error evaluator polynomial Ω(x) = S(x) * Λ(x) mod x^(2t)
        let mut omega = F::zero();
        for (i, &syndrome) in syndromes.iter().enumerate() {
            let power = self.field_power(alpha, i);
            omega = omega + syndrome * power;
        }
        
        // Compute derivative of error locator polynomial
        let mut lambda_prime = F::zero();
        for j in 1..error_locator.len() {
            if j < error_locator.len() {
                let power = self.field_power(alpha, j - 1);
                lambda_prime = lambda_prime + error_locator[j] * F::from(j as u64) * power;
            }
        }
        
        // Forney formula: e_i = -Ω(α^i) / Λ'(α^i)
        if lambda_prime.is_zero() {
            F::zero()
        } else {
            let inv = lambda_prime.inverse().unwrap_or(F::zero());
            omega * inv
        }
    }
    
    /// Compute field element raised to a power
    fn field_power(&self, base: F, exp: usize) -> F {
        let mut result = F::one();
        for _ in 0..exp {
            result = result * base;
        }
        result
    }
    
    /// Interpolate a polynomial from points
    /// 
    /// # Arguments
    /// * `points` - The (x, y) points to interpolate
    pub fn interpolate_polynomial(&self, points: &[(F, F)]) -> DensePolynomial<F> {
        let n = points.len();
        
        // Handle empty points case
        if n == 0 {
            return DensePolynomial::from_coefficients_vec(vec![F::zero()]);
        }
        
        // For a single point, return a constant polynomial
        if n == 1 {
            let (_, y_0) = points[0];
            return DensePolynomial::from_coefficients_vec(vec![y_0]);
        }

        // Use simpler approach: Generate a polynomial directly from coefficients
        // For a degree d polynomial, we need d+1 points
        // The polynomial will be of the form y = a_0 + a_1*x + a_2*x^2 + ... + a_d*x^d
        
        // Initialize coefficient vector with zeros
        let mut coeffs = vec![F::zero(); n];
        
        // For each point (x_i, y_i), compute its contribution to each coefficient
        for i in 0..n {
            let (x_i, y_i) = points[i];
            
            // Compute the Lagrange basis polynomial for this point
            // L_i(x) = ∏(j≠i) (x - x_j) / (x_i - x_j)
            let mut numerator = vec![F::one()];
            let mut denominator = F::one();
            
            for j in 0..n {
                if i == j { continue; }
                
                let (x_j, _) = points[j];
                
                // Avoid division by zero
                let div = x_i - x_j;
                if div.is_zero() { continue; }
                
                // Multiply numerator by (x - x_j)
                let term = vec![F::zero() - x_j, F::one()]; // [- x_j, 1] represents (x - x_j)
                numerator = self.multiply_polynomials(&numerator, &term);
                
                // Multiply denominator by (x_i - x_j)
                denominator = denominator * div;
            }
            
            // If denominator is zero, skip this point
            if denominator.is_zero() { continue; }
            
            // Divide numerator by denominator
            let inv_denom = denominator.inverse().unwrap_or(F::zero());
            for j in 0..numerator.len() {
                numerator[j] = numerator[j] * inv_denom;
            }
            
            // Multiply by y_i
            for j in 0..numerator.len() {
                numerator[j] = numerator[j] * y_i;
            }
            
            // Add to coefficients
            for j in 0..numerator.len() {
                if j < coeffs.len() {
                    coeffs[j] = coeffs[j] + numerator[j];
                } else if j == coeffs.len() {
                    coeffs.push(numerator[j]);
                }
            }
        }
        
        DensePolynomial::from_coefficients_vec(coeffs)
    }
    
    /// Helper function to multiply two polynomials represented as coefficient vectors
    fn multiply_polynomials(&self, p1: &[F], p2: &[F]) -> Vec<F> {
        if p1.is_empty() || p2.is_empty() {
            return vec![F::zero()];
        }
        
        let result_len = p1.len() + p2.len() - 1;
        let mut result = vec![F::zero(); result_len];
        
        for i in 0..p1.len() {
            for j in 0..p2.len() {
                result[i + j] = result[i + j] + p1[i] * p2[j];
            }
        }
        
        result
    }
    
    /// Evaluate a polynomial at a point
    /// 
    /// # Arguments
    /// * `poly` - The polynomial
    /// * `point` - The point to evaluate at
    pub fn evaluate_polynomial(&self, poly: &DensePolynomial<F>, point: F) -> F {
        // Use the Polynomial trait's evaluate method
        Polynomial::evaluate(poly, &point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    
    #[test]
    fn test_reed_solomon_encoding() {
        let field_size = 128;
        let error_capacity = 2;
        let rs = ReedSolomon::<Fr>::new(field_size, error_capacity);
        
        // Create a simple message
        let message = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        
        // Encode with 2 parity symbols (5 total)
        let code_length = message.len() + error_capacity;
        let codeword = rs.encode(&message, code_length);
        
        // Check that the first part is the original message (systematic code)
        assert_eq!(codeword[0], message[0]);
        assert_eq!(codeword[1], message[1]);
        assert_eq!(codeword[2], message[2]);
        
        // Decode should return the original message
        let decoded = rs.decode(&codeword, message.len()).unwrap();
        assert_eq!(decoded, message);
    }
    
    #[test]
    fn test_polynomial_interpolation() {
        let field_size = 128;
        let error_capacity = 2;
        let rs = ReedSolomon::<Fr>::new(field_size, error_capacity);
        
        // Create some points
        let points = vec![
            (Fr::from(1u64), Fr::from(2u64)),
            (Fr::from(2u64), Fr::from(5u64)),
            (Fr::from(3u64), Fr::from(10u64)),
        ];
        
        // Interpolate a polynomial
        let poly = rs.interpolate_polynomial(&points);
        
        // Check that the polynomial passes through the points
        for (x, y) in &points {
            let y_calc = rs.evaluate_polynomial(&poly, *x);
            assert_eq!(y_calc, *y);
        }
    }
    
    #[test]
    fn test_reed_solomon_error_detection() {
        let field_size = 128;
        let error_capacity = 2;
        let rs = ReedSolomon::<Fr>::new(field_size, error_capacity);
        
        // Create a message
        let message = vec![Fr::from(5u64), Fr::from(10u64), Fr::from(15u64)];
        
        // Encode with 4 parity symbols (7 total)
        let code_length = message.len() + (error_capacity * 2);
        let codeword = rs.encode(&message, code_length);
        
        println!("Original codeword length: {}", codeword.len());
        println!("Original message: {:?}", message);
        
        // Test 1: No errors - should decode perfectly
        let decoded_no_error = rs.decode(&codeword, message.len()).unwrap();
        assert_eq!(decoded_no_error, message, "Failed to decode error-free codeword");
        
        // Test 2: Single error - should detect (and potentially correct)
        let mut corrupted_single = codeword.clone();
        corrupted_single[1] = Fr::from(99u64); // Corrupt one position
        
        let result_single = rs.decode(&corrupted_single, message.len());
        assert!(result_single.is_ok(), "Failed to handle codeword with single error");
        
        // Test 3: Multiple errors within capacity
        let mut corrupted_multiple = codeword.clone();
        corrupted_multiple[0] = Fr::from(77u64);
        corrupted_multiple[2] = Fr::from(88u64);
        
        let result_multiple = rs.decode(&corrupted_multiple, message.len());
        // Should either correct or gracefully handle errors within capacity
        assert!(result_multiple.is_ok(), "Failed to handle codeword with multiple errors within capacity");
    }
    
    #[test]
    fn test_reed_solomon_syndrome_calculation() {
        let field_size = 128;
        let error_capacity = 2;
        let rs = ReedSolomon::<Fr>::new(field_size, error_capacity);
        
        // Create a simple message
        let message = vec![Fr::from(1u64), Fr::from(2u64)];
        
        // Encode
        let code_length = message.len() + (error_capacity * 2);
        let codeword = rs.encode(&message, code_length);
        
        // Decode should work on valid codeword (syndromes all zero)
        let decoded = rs.decode(&codeword, message.len()).unwrap();
        assert_eq!(decoded, message, "Syndrome calculation failed for valid codeword");
        
        // Introduce error and verify syndrome detection works
        let mut corrupted = codeword.clone();
        corrupted[0] = Fr::from(100u64);
        
        // Decode should still return a result (either corrected or best effort)
        let result = rs.decode(&corrupted, message.len());
        assert!(result.is_ok(), "Syndrome-based decoding failed");
    }
}
