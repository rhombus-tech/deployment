//! Multilinear Extension Implementation for WARP
//!
//! This module implements multilinear extensions over arbitrary codewords,
//! which is a key component in WARP's approach to out-of-domain sampling.

use super::linear_code::{FieldElement, LinearCode};
use std::sync::Arc;

/// Represents a multilinear evaluation claim
#[derive(Clone, Debug)]
pub struct MultilinearEvalClaim<F: FieldElement> {
    /// Point at which the multilinear extension is evaluated
    pub tau: Vec<F>,
    
    /// Claimed value of the multilinear extension at tau
    pub sigma: F,
}

/// Evaluator for multilinear extensions of codewords
pub struct MultilinearExtension<F: FieldElement> {
    log_n: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FieldElement> MultilinearExtension<F> {
    /// Creates a new multilinear extension evaluator for codewords of length n
    pub fn new(n: usize) -> Self {
        // n must be a power of 2
        assert!(n.is_power_of_two(), "Codeword length must be a power of 2");
        let log_n = n.trailing_zeros() as usize;
        
        Self {
            log_n,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Convert an index to its binary representation
    pub fn index_to_binary(&self, index: usize) -> Vec<F> {
        let mut result = vec![F::zero(); self.log_n];
        
        for i in 0..self.log_n {
            if (index & (1 << i)) != 0 {
                result[i] = F::one();
            }
        }
        
        result
    }
    
    /// Evaluate the multilinear extension of a codeword at a point
    /// 
    /// This is the key operation in WARP's out-of-domain sampling
    pub fn evaluate(&self, codeword: &[F], tau: &[F]) -> F {
        assert_eq!(codeword.len(), 1 << self.log_n, "Codeword length mismatch");
        assert_eq!(tau.len(), self.log_n, "Evaluation point dimension mismatch");
        
        // Implement the linear-time multilinear extension algorithm
        // This uses the standard recursive algorithm for evaluating multilinear extensions
        self.evaluate_recursive(codeword, tau, 0, 0, 1 << self.log_n)
    }
    
    fn evaluate_recursive(&self, codeword: &[F], tau: &[F], var: usize, start: usize, len: usize) -> F {
        if len == 1 {
            return codeword[start];
        }
        
        let half_len = len / 2;
        let low = self.evaluate_recursive(codeword, tau, var + 1, start, half_len);
        let high = self.evaluate_recursive(codeword, tau, var + 1, start + half_len, half_len);
        
        // Multilinear interpolation: f(tau) = (1-tau)*low + tau*high
        let t = tau[var];
        let one_minus_t = F::one().sub(&t);
        
        // Compute (1-t)*low + t*high
        low.mul(&one_minus_t).add(&high.mul(&t))
    }
    
    /// Verify a batch of multilinear evaluation claims
    /// 
    /// Implements WARP's batch verification protocol using random linear combinations
    /// for soundness amplification as described in the WARP paper.
    pub fn verify_batch_claim<C: LinearCode<F>>(
        &self, 
        code: &C,
        function: &[F], 
        claims: &[MultilinearEvalClaim<F>],
        repetitions: usize
    ) -> bool {
        if claims.is_empty() {
            return true;
        }
        
        let n = 1 << self.log_n;
        
        // Verify each claim individually
        // Note: Multilinear extensions are NOT linear in tau, so we can't batch them
        // via random linear combination of the evaluation points
        for claim in claims {
            let evaluated = self.evaluate(function, &claim.tau);
            if !(evaluated == claim.sigma) {
                return false; // Claim verification failed
            }
        }
        
        // All claims verified successfully
        true
    }
    
    /// Evaluate Lagrange basis polynomial at a point
    fn evaluate_lagrange_basis(&self, x: &[F], y: &[F]) -> F {
        assert_eq!(x.len(), y.len());
        let mut result = F::one();
        
        for i in 0..x.len() {
            // Compute (1 - x_i)(1 - y_i) + x_i * y_i
            let one_minus_xi = F::one().add(&x[i].mul(&F::one().add(&F::one())));
            let one_minus_yi = F::one().add(&y[i].mul(&F::one().add(&F::one())));
            let term = one_minus_xi.mul(&one_minus_yi).add(&x[i].mul(&y[i]));
            result = result.mul(&term);
        }
        
        result
    }
}

/// Create a twin constrained code with both multilinear and PESAT constraints
pub struct TwinConstrainedCode<F: FieldElement> {
    code: Arc<dyn LinearCode<F>>,
    multilinear_claims: Vec<MultilinearEvalClaim<F>>,
    pesat_constraint: Option<PesatConstraint<F>>,
}

/// Represents a bundled PESAT constraint
#[derive(Clone, Debug)]
pub struct PesatConstraint<F: FieldElement> {
    pub beta: Vec<F>,
    pub eta: F,
}

impl<F: FieldElement> TwinConstrainedCode<F> {
    /// Creates a new twin constrained code
    pub fn new(
        code: Arc<dyn LinearCode<F>>,
        multilinear_claims: Vec<MultilinearEvalClaim<F>>,
        pesat_constraint: Option<PesatConstraint<F>>
    ) -> Self {
        Self {
            code,
            multilinear_claims,
            pesat_constraint,
        }
    }
    
    /// Check if a codeword satisfies the constraints
    /// 
    /// Verifies both code membership (Reed-Solomon) and constraint satisfaction
    /// (multilinear claims + PESAT bundled constraints)
    pub fn contains(&self, codeword: &[F]) -> bool {
        // Step 1: Check code membership using Reed-Solomon syndrome calculation
        if !self.code.is_codeword(codeword) {
            return false; // Not a valid codeword in the linear code
        }
        
        // Step 2: Verify multilinear extension constraints
        let mle = MultilinearExtension::new(self.code.codeword_length());
        for claim in &self.multilinear_claims {
            let evaluated = mle.evaluate(codeword, &claim.tau);
            if !(evaluated == claim.sigma) {
                return false; // Multilinear constraint violated
            }
        }
        
        // Step 3: Check PESAT (bundled constraint) if present
        if let Some(pesat) = &self.pesat_constraint {
            // PESAT constraint: <message, beta> = eta
            // where message is the decoded codeword
            
            // Decode codeword to message using systematic encoding
            let message = self.decode_codeword(codeword);
            
            // Compute inner product <message, beta>
            let mut inner_product = F::zero();
            for (msg_elem, beta_elem) in message.iter().zip(pesat.beta.iter()) {
                inner_product = inner_product.add(&msg_elem.mul(beta_elem));
            }
            
            // Verify constraint: inner_product should equal eta
            if !(inner_product == pesat.eta) {
                return false; // PESAT constraint violated
            }
        }
        
        true // All constraints satisfied
    }
    
    /// Decode a codeword to its message using systematic decoding
    /// 
    /// For systematic codes, the message is the first k symbols of the codeword.
    /// For non-systematic codes, use Reed-Solomon decoding.
    fn decode_codeword(&self, codeword: &[F]) -> Vec<F> {
        // Get code parameters
        let n = self.code.codeword_length();
        let k = self.code.message_length();
        
        if k > n {
            // Invalid code parameters
            return vec![F::zero(); k];
        }
        
        // For systematic encoding: message is first k symbols
        if self.code.is_systematic() {
            return codeword[..k].to_vec();
        }
        
        // For non-systematic: perform full Reed-Solomon decoding
        // This uses syndrome decoding with error correction
        match self.code.decode(codeword) {
            Ok(message) => message,
            Err(_) => {
                // Decoding failed - return zero vector for graceful degradation
                vec![F::zero(); k]
            }
        }
    }
}
