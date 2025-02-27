use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;

use crate::circuits::PCDCircuit;

#[cfg(test)]
mod tests;

/// PCD Verifier for checking proof chains
pub struct PCDVerifier {
    /// Verification keys for each step in the chain
    verification_keys: Vec<VerifyingKey<Bn254>>,
}

impl PCDVerifier {
    /// Create a new verifier with the given verification keys
    pub fn new(verification_keys: Vec<VerifyingKey<Bn254>>) -> Self {
        Self { verification_keys }
    }
    
    /// Verify a chain of proofs
    pub fn verify_chain<C>(
        &self,
        circuits: &[&C],
        proofs: &[Proof<Bn254>],
    ) -> Result<bool, anyhow::Error>
    where
        C: PCDCircuit,
    {
        if proofs.len() != self.verification_keys.len() || proofs.len() != circuits.len() {
            return Ok(false);
        }
        
        // Verify each proof in the chain
        for i in 0..proofs.len() {
            let vk = &self.verification_keys[i];
            let circuit = circuits[i];
            let proof = &proofs[i];
            
            // Get public inputs for this circuit
            let public_inputs = circuit.get_public_inputs();
            
            // Verify the current proof
            if !Groth16::<Bn254>::verify(vk, &public_inputs, proof)? {
                return Ok(false);
            }
            
            // Verify chain connection
            if i > 0 {
                let prev_outputs = circuits[i-1].get_public_outputs();
                if !circuit.verify_chain(&prev_outputs)? {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
}
