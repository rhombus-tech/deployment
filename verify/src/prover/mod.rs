use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{
    Groth16,
    Proof,
    ProvingKey,
    VerifyingKey,
    prepare_verifying_key,
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use anyhow::Result;

use crate::circuits::MemorySafetyPCDCircuit;

/// Generate proving and verifying keys for the combined memory safety and PCD circuit
pub fn generate_combined_keys(
    circuit: &MemorySafetyPCDCircuit<Fr>,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)> {
    let mut rng = StdRng::from_seed([42; 32]); // Fixed seed for deterministic testing
    let (params, vk) = Groth16::<Bls12_381>::setup(circuit.clone(), &mut rng)?;
    Ok((params, vk))
}

/// Generate a proof for the combined circuit
pub fn generate_combined_proof(
    circuit: MemorySafetyPCDCircuit<Fr>,
    proving_key: &ProvingKey<Bls12_381>,
) -> Result<Proof<Bls12_381>> {
    let mut rng = StdRng::from_seed([42; 32]); // Fixed seed for deterministic testing
    let proof = Groth16::<Bls12_381>::prove(proving_key, circuit, &mut rng)?;
    Ok(proof)
}

/// Verify a combined memory safety and PCD proof
pub fn verify_combined_proof(
    proof: &Proof<Bls12_381>,
    verifying_key: &VerifyingKey<Bls12_381>,
    public_inputs: &[Fr],
) -> Result<bool> {
    let pvk = prepare_verifying_key(verifying_key);
    Ok(Groth16::<Bls12_381>::verify_proof(&pvk, proof, public_inputs)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combined_proof_generation() -> Result<()> {
        // Create a test circuit with initial state
        let circuit = MemorySafetyPCDCircuit {
            prev_state: None,
            curr_state: vec![Fr::from(1u32)],
            memory_accesses: vec![(0, 4)], // Single 4-byte read at offset 0
            allocations: vec![(0, 65536)], // One page allocated at address 0
        };

        // Generate keys
        let (pk, vk) = generate_combined_keys(&circuit)?;

        // Generate proof
        let proof = generate_combined_proof(circuit, &pk)?;

        // Verify proof with empty public inputs since we're not exposing any values
        let public_inputs = vec![];
        assert!(verify_combined_proof(&proof, &vk, &public_inputs)?);

        Ok(())
    }

    #[test]
    fn test_combined_proof_transition() -> Result<()> {
        // Create a test circuit with state transition
        let circuit = MemorySafetyPCDCircuit {
            prev_state: Some((
                vec![Fr::from(1u32)],
                vec![(0, 4)],
                vec![(0, 65536)],
            )),
            curr_state: vec![Fr::from(2u32)],
            memory_accesses: vec![(4, 4)], // Single 4-byte read at offset 4
            allocations: vec![(0, 65536)], // Same allocation
        };

        // Generate keys
        let (pk, vk) = generate_combined_keys(&circuit)?;

        // Generate proof
        let proof = generate_combined_proof(circuit, &pk)?;

        // Verify proof with empty public inputs since we're not exposing any values
        let public_inputs = vec![];
        assert!(verify_combined_proof(&proof, &vk, &public_inputs)?);

        Ok(())
    }
}
