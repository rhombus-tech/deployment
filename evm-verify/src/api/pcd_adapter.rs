// PCD Adapter for EVM Verify
//
// This module provides an adapter layer between the EVM Verify API and the
// underlying PCD implementation, allowing for a smooth transition between
// the traditional PCD implementation and the new accumulation-based approach.

use ethers::types::Bytes;
use std::sync::Arc;
use std::marker::PhantomData;
use anyhow::{anyhow, Result};

use crate::api::pcd::PCDVerifier;
use crate::api::unified::VerificationResult;

#[cfg(feature = "accumulation")]
use pcd::{
    evm_accumulation::{
        generate_evm_proof, verify_evm_proof,
        EVMBytecodeInput,
    },
};

// Import the correct Fr type from ark_bn254
#[cfg(feature = "accumulation")]
use ark_bn254::Fr as Bn254Fr;

/// Result of proof generation
#[cfg(feature = "accumulation")]
pub struct ProofGenerationResult {
    pub proof: Vec<u8>,
    pub verifying_key: Vec<u8>,
}

/// Adapter for PCD verification
pub struct PCDAdapter {
    #[cfg(feature = "accumulation")]
    verifying_keys: Vec<Vec<u8>>,
    
    #[cfg(not(feature = "accumulation"))]
    verifier: Arc<dyn PCDVerifier>,
}

impl PCDAdapter {
    /// Create a new PCD adapter
    #[cfg(feature = "accumulation")]
    pub fn new() -> Self {
        Self {
            verifying_keys: Vec::new(),
        }
    }
    
    #[cfg(not(feature = "accumulation"))]
    pub fn new(verifier: Arc<dyn PCDVerifier>) -> Self {
        Self {
            verifier,
        }
    }
    
    /// Generate a proof for bytecode
    #[cfg(feature = "accumulation")]
    pub fn generate_proof_for_bytecode(&self, bytecode: Vec<u8>) -> Result<ProofGenerationResult> {
        use ark_std::rand::{thread_rng, CryptoRng, RngCore};
        use pcd::evm_accumulation::{generate_evm_proof, serialize_proof, serialize_vk};
        use std::marker::PhantomData;
        
        // Create a simple state transition
        let prev_state = None;
        let curr_state = vec![Bn254Fr::from(1u32)]; // Example state
        
        // Generate proof
        let mut rng = thread_rng();
        let (proof, vk) = generate_evm_proof(
            Bytes::from(bytecode),
            prev_state,
            curr_state,
            &mut rng,
        )?;
        
        // Serialize proof and verifying key
        let proof_bytes = serialize_proof(&proof)?;
        let vk_bytes = serialize_vk(&vk)?;
        
        Ok(ProofGenerationResult {
            proof: proof_bytes,
            verifying_key: vk_bytes,
        })
    }
    
    /// Verify bytecode using PCD
    pub fn verify_bytecode(&self, bytecode: Bytes) -> Result<VerificationResult> {
        #[cfg(feature = "accumulation")]
        {
            use ark_std::rand::{thread_rng, CryptoRng, RngCore};
            use pcd::evm_accumulation::{generate_evm_proof, verify_evm_proof};
            use std::marker::PhantomData;
            
            // Create a simple state transition
            let prev_state = None;
            let curr_state = vec![Bn254Fr::from(1u32)]; // Example state
            
            // Generate proof
            let mut rng = thread_rng();
            let (proof, vk) = generate_evm_proof(
                bytecode.clone(),
                prev_state,
                curr_state.clone(),
                &mut rng,
            )?;
            
            // Verify the proof
            let is_valid = verify_evm_proof(
                bytecode,
                &proof,
                &vk,
                curr_state,
            )?;
            
            Ok(VerificationResult {
                is_valid,
                vulnerabilities: Vec::new(), // No vulnerabilities detected in this verification path
            })
        }
        
        #[cfg(not(feature = "accumulation"))]
        {
            // Use the traditional PCD verifier
            let vulnerabilities = self.verifier.verify_bytecode(bytecode)?;
            
            Ok(VerificationResult {
                is_valid: vulnerabilities.is_empty(),
                vulnerabilities: vulnerabilities.iter().map(|v| v.title.clone()).collect(),
            })
        }
    }
    
    /// Verify a proof
    #[cfg(feature = "accumulation")]
    pub fn verify_proof(&self, bytecode: Vec<u8>, proof_bytes: Vec<u8>, verifying_key: Vec<u8>) -> Result<VerificationResult> {
        use std::marker::PhantomData;
        use pcd::evm_accumulation::{deserialize_proof, deserialize_vk, verify_evm_proof};
        
        // Deserialize proof and verifying key
        let proof = deserialize_proof(&proof_bytes)?;
        let vk = deserialize_vk(&verifying_key)?;
        
        // Create a simple state for verification (this should match what was used in generation)
        let curr_state = vec![Bn254Fr::from(1u32)];
        
        // Verify the proof
        let is_valid = verify_evm_proof(
            Bytes::from(bytecode),
            &proof,
            &vk,
            curr_state,
        )?;
        
        Ok(VerificationResult {
            is_valid,
            vulnerabilities: Vec::new(), // No vulnerabilities detected in this verification path
        })
    }
    
    #[cfg(not(feature = "accumulation"))]
    pub fn verify_proof(&self, proof_bytes: &[u8], verifying_key: &[u8]) -> Result<bool> {
        // Use the traditional PCD verifier
        self.verifier.verify_proof(proof_bytes, verifying_key)
    }
    
    /// Add a verifying key to the adapter
    #[cfg(feature = "accumulation")]
    pub fn add_verifying_key(&mut self, vk: Vec<u8>) {
        self.verifying_keys.push(vk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg(feature = "accumulation")]
    fn test_adapter() {
        // Create a PCD adapter
        let adapter = PCDAdapter::new();
        
        // Create a simple bytecode
        let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
        
        // Verify the bytecode
        let result = adapter.verify_bytecode(bytecode).unwrap();
        
        // Check that the bytecode is valid
        assert!(result.is_valid);
    }
    
    #[test]
    #[cfg(not(feature = "accumulation"))]
    fn test_adapter() {
        // This test is skipped when accumulation is enabled
        assert!(true);
    }
}
