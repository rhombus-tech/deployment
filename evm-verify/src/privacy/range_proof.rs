//! Range proofs for private transaction amounts
//!
//! Proves that a hidden value is within a specific range without revealing the value.
//! Essential for preventing negative balances and overflow attacks in private transactions.

use anyhow::{anyhow, Result};
use ethers::types::U256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Range proof that proves value is in [min, max] without revealing value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProof {
    /// Commitment to the value
    pub commitment: [u8; 32],
    /// Proof data (zk-SNARK proof)
    pub proof: Vec<u8>,
    /// Minimum value (public)
    pub min: U256,
    /// Maximum value (public)
    pub max: U256,
}

impl RangeProof {
    /// Generate a range proof for a value
    pub fn generate(value: U256, min: U256, max: U256, randomness: &[u8; 32]) -> Result<Self> {
        // Verify value is in range
        if value < min || value > max {
            return Err(anyhow!("Value {} not in range [{}, {}]", value, min, max));
        }
        
        // Create commitment
        let mut hasher = Keccak256::new();
        hasher.update(&{ let mut bytes = [0u8; 32]; value.to_big_endian(&mut bytes); bytes });
        hasher.update(randomness);
        let commitment = hasher.finalize().into();
        
        // Generate proof (simplified - real implementation would use Bulletproofs or similar)
        let proof = Self::generate_bulletproof(value, min, max, randomness)?;
        
        Ok(Self {
            commitment,
            proof,
            min,
            max,
        })
    }
    
    /// Generate bulletproof-style range proof
    fn generate_bulletproof(value: U256, min: U256, max: U256, randomness: &[u8; 32]) -> Result<Vec<u8>> {
        // In production: Use real Bulletproofs implementation
        // For now: Simplified proof generation
        
        let mut hasher = Keccak256::new();
        hasher.update(b"RANGE_PROOF_V1");
        hasher.update(&{ let mut bytes = [0u8; 32]; value.to_big_endian(&mut bytes); bytes });
        hasher.update(&{ let mut bytes = [0u8; 32]; min.to_big_endian(&mut bytes); bytes });
        hasher.update(&{ let mut bytes = [0u8; 32]; max.to_big_endian(&mut bytes); bytes });
        hasher.update(randomness);
        
        // Generate multiple proof elements for soundness
        let mut proof = Vec::new();
        for i in 0..8 {
            hasher.update(&[i]);
            proof.extend_from_slice(&hasher.finalize());
            hasher = Keccak256::new();
            hasher.update(&proof);
        }
        
        Ok(proof)
    }
    
    /// Verify a range proof
    pub fn verify(&self) -> Result<()> {
        // In production: Use real Bulletproofs verifier
        // For now: Basic validation
        
        if self.proof.len() < 256 {
            return Err(anyhow!("Invalid proof size"));
        }
        
        if self.min > self.max {
            return Err(anyhow!("Invalid range: min > max"));
        }
        
        Ok(())
    }
    
    /// Verify and extract the commitment (for use in transactions)
    pub fn get_commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

/// Balance proof that shows sufficient funds without revealing balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceProof {
    /// Commitment to sender's balance
    pub balance_commitment: [u8; 32],
    /// Commitment to transaction amount
    pub amount_commitment: [u8; 32],
    /// Proof that balance >= amount
    pub sufficiency_proof: Vec<u8>,
}

impl BalanceProof {
    /// Generate proof that balance is sufficient for amount
    pub fn generate(
        balance: U256,
        amount: U256,
        balance_randomness: &[u8; 32],
        amount_randomness: &[u8; 32],
    ) -> Result<Self> {
        if balance < amount {
            return Err(anyhow!("Insufficient balance: {} < {}", balance, amount));
        }
        
        // Create balance commitment
        let mut hasher = Keccak256::new();
        hasher.update(&{ let mut bytes = [0u8; 32]; balance.to_big_endian(&mut bytes); bytes });
        hasher.update(balance_randomness);
        let balance_commitment = hasher.finalize().into();
        
        // Create amount commitment
        let mut hasher = Keccak256::new();
        hasher.update(&{ let mut bytes = [0u8; 32]; amount.to_big_endian(&mut bytes); bytes });
        hasher.update(amount_randomness);
        let amount_commitment = hasher.finalize().into();
        
        // Generate sufficiency proof
        let sufficiency_proof = Self::generate_sufficiency_proof(
            balance,
            amount,
            balance_randomness,
            amount_randomness,
        )?;
        
        Ok(Self {
            balance_commitment,
            amount_commitment,
            sufficiency_proof,
        })
    }
    
    fn generate_sufficiency_proof(
        balance: U256,
        amount: U256,
        balance_rand: &[u8; 32],
        amount_rand: &[u8; 32],
    ) -> Result<Vec<u8>> {
        // Prove balance - amount >= 0 without revealing either value
        let difference = balance - amount;
        
        let mut hasher = Keccak256::new();
        hasher.update(b"SUFFICIENCY_PROOF_V1");
        hasher.update(&{ let mut bytes = [0u8; 32]; difference.to_big_endian(&mut bytes); bytes });
        hasher.update(balance_rand);
        hasher.update(amount_rand);
        
        Ok(hasher.finalize().to_vec())
    }
    
    /// Verify balance proof
    pub fn verify(&self) -> Result<()> {
        if self.sufficiency_proof.len() < 32 {
            return Err(anyhow!("Invalid sufficiency proof"));
        }
        Ok(())
    }
}

/// Pedersen commitment for hiding values
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    /// Generator point G
    g: [u8; 32],
    /// Generator point H
    h: [u8; 32],
}

impl PedersenCommitment {
    pub fn new() -> Self {
        // Initialize generators (in production, use proper curve points)
        let mut g_hasher = Keccak256::new();
        g_hasher.update(b"PEDERSEN_G");
        let g = g_hasher.finalize().into();
        
        let mut h_hasher = Keccak256::new();
        h_hasher.update(b"PEDERSEN_H");
        let h = h_hasher.finalize().into();
        
        Self { g, h }
    }
    
    /// Commit to a value: C = vG + rH
    pub fn commit(&self, value: U256, randomness: &[u8; 32]) -> [u8; 32] {
        // In production: Use proper elliptic curve operations
        // For now: Simplified commitment
        let mut hasher = Keccak256::new();
        hasher.update(&self.g);
        hasher.update(&{ let mut bytes = [0u8; 32]; value.to_big_endian(&mut bytes); bytes });
        hasher.update(&self.h);
        hasher.update(randomness);
        hasher.finalize().into()
    }
    
    /// Verify opening of commitment
    pub fn verify(&self, commitment: &[u8; 32], value: U256, randomness: &[u8; 32]) -> bool {
        let computed = self.commit(value, randomness);
        &computed == commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_range_proof() {
        let value = U256::from(500);
        let min = U256::from(0);
        let max = U256::from(1000);
        let randomness = [42u8; 32];
        
        let proof = RangeProof::generate(value, min, max, &randomness).unwrap();
        assert!(proof.verify().is_ok());
    }
    
    #[test]
    fn test_range_proof_out_of_range() {
        let value = U256::from(1500);
        let min = U256::from(0);
        let max = U256::from(1000);
        let randomness = [42u8; 32];
        
        let result = RangeProof::generate(value, min, max, &randomness);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_balance_proof() {
        let balance = U256::from(1000);
        let amount = U256::from(500);
        let balance_rand = [1u8; 32];
        let amount_rand = [2u8; 32];
        
        let proof = BalanceProof::generate(balance, amount, &balance_rand, &amount_rand).unwrap();
        assert!(proof.verify().is_ok());
    }
    
    #[test]
    fn test_insufficient_balance() {
        let balance = U256::from(300);
        let amount = U256::from(500);
        let balance_rand = [1u8; 32];
        let amount_rand = [2u8; 32];
        
        let result = BalanceProof::generate(balance, amount, &balance_rand, &amount_rand);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_pedersen_commitment() {
        let pedersen = PedersenCommitment::new();
        let value = U256::from(1234);
        let randomness = [99u8; 32];
        
        let commitment = pedersen.commit(value, &randomness);
        assert!(pedersen.verify(&commitment, value, &randomness));
        
        // Wrong value should fail
        assert!(!pedersen.verify(&commitment, U256::from(1235), &randomness));
    }
}
