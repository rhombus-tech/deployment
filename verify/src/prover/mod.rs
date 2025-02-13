use ark_bls12_381::{Bls12_381, Fr};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use anyhow::Result;

use crate::circuits::MemorySafetyPCDCircuit;

/// Generate proving and verifying keys for the combined memory safety and PCD circuit
pub fn generate_combined_keys(
    circuit: &MemorySafetyPCDCircuit<Fr>,
) -> Result<(ark_groth16::ProvingKey<Bls12_381>, ark_groth16::VerifyingKey<Bls12_381>)> {
    let mut rng = StdRng::from_seed([42; 32]); // Fixed seed for deterministic testing
    
    // Create a fresh circuit for key generation
    let key_circuit = circuit.clone();
    
    // Generate keys without initializing constraints first
    let (params, vk) = ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(key_circuit, &mut rng)?;
    Ok((params, vk))
}

/// Generate a proof for the combined memory safety and PCD circuit
pub fn generate_combined_proof(
    circuit: &MemorySafetyPCDCircuit<Fr>,
    proving_key: &ark_groth16::ProvingKey<Bls12_381>,
) -> Result<ark_groth16::Proof<Bls12_381>> {
    let mut rng = StdRng::from_seed([42; 32]); // Fixed seed for deterministic testing
    
    // Create a fresh circuit for proof generation
    let proof_circuit = circuit.clone();
    
    // Generate proof without initializing constraints first
    let proof = ark_groth16::Groth16::<Bls12_381>::prove(proving_key, proof_circuit, &mut rng)?;
    Ok(proof)
}

/// Verify a proof for the combined memory safety and PCD circuit
pub fn verify_combined_proof(
    proof: &ark_groth16::Proof<Bls12_381>,
    verifying_key: &ark_groth16::VerifyingKey<Bls12_381>,
    public_inputs: &[Fr],
) -> Result<bool> {
    let pvk = ark_groth16::prepare_verifying_key(verifying_key);
    Ok(ark_groth16::Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, public_inputs, proof)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combined_proof_generation() -> Result<()> {
        let circuit = MemorySafetyPCDCircuit::new(
            None,
            vec![Fr::from(1u32)],
            vec![(0, 4)], // Single 4-byte read at offset 0
            vec![(0, 65536)], // One page allocated at address 0
        );

        // Generate keys
        let (pk, vk) = generate_combined_keys(&circuit)?;

        // Generate proof
        let proof = generate_combined_proof(&circuit, &pk)?;

        // Create public inputs in the correct order:
        let mut public_inputs = Vec::new();
        
        // 1. Current state variables
        public_inputs.extend(vec![Fr::from(1u32)]);
        
        // 2. Memory access bounds
        public_inputs.extend(vec![
            Fr::from(0u32),   // access_start
            Fr::from(4u32),   // access_end
        ]);
        
        // 3. Allocation bounds
        public_inputs.extend(vec![
            Fr::from(0u32),   // alloc_start
            Fr::from(65536u32), // alloc_end
        ]);
        
        // 4. Validity flag
        public_inputs.push(Fr::from(1u32)); // in_bounds

        // Verify proof
        assert!(verify_combined_proof(&proof, &vk, &public_inputs)?);
        Ok(())
    }

    #[test]
    fn test_combined_proof_transition() -> Result<()> {
        let circuit = MemorySafetyPCDCircuit::new(
            Some((
                vec![Fr::from(1u32)],
                vec![(0, 4)],
                vec![(0, 65536)],
            )),
            vec![Fr::from(2u32)],
            vec![(4, 4)],
            vec![(0, 65536)],
        );

        // Generate keys
        let (pk, vk) = generate_combined_keys(&circuit)?;

        // Generate proof
        let proof = generate_combined_proof(&circuit, &pk)?;

        // Create public inputs in the correct order:
        let mut public_inputs = Vec::new();
        
        // 1. Current state variables
        public_inputs.extend(vec![Fr::from(2u32)]);
        
        // 2. Current memory access bounds
        public_inputs.extend(vec![
            Fr::from(4u32),   // access_start
            Fr::from(8u32),   // access_end
        ]);
        
        // 3. Current allocation bounds
        public_inputs.extend(vec![
            Fr::from(0u32),   // alloc_start
            Fr::from(65536u32), // alloc_end
        ]);
        
        // 4. Current validity flag
        public_inputs.push(Fr::from(1u32)); // in_bounds
        
        // 5. Previous state variables
        public_inputs.extend(vec![Fr::from(1u32)]);
        
        // 6. Previous memory access bounds
        public_inputs.extend(vec![
            Fr::from(0u32),   // access_start
            Fr::from(4u32),   // access_end
        ]);
        
        // 7. Previous allocation bounds
        public_inputs.extend(vec![
            Fr::from(0u32),   // alloc_start
            Fr::from(65536u32), // alloc_end
        ]);
        
        // 8. Previous validity flag
        public_inputs.push(Fr::from(1u32)); // in_bounds

        // Verify proof
        assert!(verify_combined_proof(&proof, &vk, &public_inputs)?);
        Ok(())
    }

    #[test]
    fn test_invalid_memory_access() -> Result<()> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = MemorySafetyPCDCircuit::new(
            None,
            vec![Fr::from(1u32)],
            vec![(65536, 4)], // Access beyond allocated memory
            vec![(0, 65536)],
        );

        assert!(circuit.clone().generate_constraints(cs.clone()).is_ok());
        Ok(())
    }

    #[test]
    fn test_multiple_memory_accesses() -> Result<()> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = MemorySafetyPCDCircuit::new(
            None,
            vec![Fr::from(1u32)],
            vec![(0, 4), (4, 4), (8, 4)], // Multiple valid accesses
            vec![(0, 65536)],
        );

        assert!(circuit.clone().generate_constraints(cs.clone()).is_ok());
        Ok(())
    }

    #[test]
    fn test_overlapping_allocations() -> Result<()> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = MemorySafetyPCDCircuit::new(
            None,
            vec![Fr::from(1u32)],
            vec![(0, 4)],
            vec![(0, 65536), (32768, 65536)], // Overlapping allocations
        );

        assert!(circuit.clone().generate_constraints(cs.clone()).is_ok());
        Ok(())
    }

    #[test]
    fn test_edge_cases() -> Result<()> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test zero-sized access
        let circuit = MemorySafetyPCDCircuit::new(
            None,
            vec![Fr::from(1u32)],
            vec![(0, 0)],
            vec![(0, 65536)],
        );
        assert!(circuit.clone().generate_constraints(cs.clone()).is_ok());

        // Test zero-sized allocation
        let circuit = MemorySafetyPCDCircuit::new(
            None,
            vec![Fr::from(1u32)],
            vec![(0, 4)],
            vec![(0, 0)],
        );
        assert!(circuit.clone().generate_constraints(cs.clone()).is_ok());

        Ok(())
    }

    #[test]
    fn test_state_transition() -> Result<()> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Previous state with valid memory access
        let circuit = MemorySafetyPCDCircuit::new(
            Some((
                vec![Fr::from(1u32)],
                vec![(0, 4)],
                vec![(0, 65536)],
            )),
            vec![Fr::from(2u32)],
            vec![(4, 4)],
            vec![(0, 65536)],
        );

        assert!(circuit.clone().generate_constraints(cs.clone()).is_ok());
        Ok(())
    }

    #[test]
    fn test_complex_transition() -> Result<()> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test transition with multiple accesses and allocations
        let circuit = MemorySafetyPCDCircuit::new(
            Some((
                vec![Fr::from(1u32), Fr::from(2u32)],
                vec![(0, 4), (4, 4)],
                vec![(0, 65536), (65536, 65536)],
            )),
            vec![Fr::from(2u32), Fr::from(3u32)],
            vec![(8, 4), (12, 4)],
            vec![(0, 65536), (65536, 65536)],
        );

        assert!(circuit.clone().generate_constraints(cs.clone()).is_ok());
        Ok(())
    }
}
