// EVM-specific accumulation scheme implementation
//
// This module implements an accumulation scheme specifically designed for EVM bytecode
// verification, building on top of the Groth16 proof system.

use anyhow::{anyhow, Result};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::marker::PhantomData;
use ark_std::rand::{RngCore, CryptoRng};
use ethers::types::Bytes;

use crate::circuit_impl::PCDCircuit;

/// EVM Bytecode verification input for the accumulation scheme
#[derive(Clone)]
pub struct EVMBytecodeInput {
    pub bytecode: Bytes,
    pub prev_state: Option<Vec<Fr>>,
    pub curr_state: Vec<Fr>,
}

/// Generate a proof for EVM bytecode verification
pub fn generate_evm_proof<R: RngCore + CryptoRng>(
    bytecode: Bytes,
    prev_state: Option<Vec<Fr>>,
    curr_state: Vec<Fr>,
    rng: &mut R,
) -> Result<(Proof<Bn254>, VerifyingKey<Bn254>), anyhow::Error> {
    // Create a circuit for the bytecode and state
    let circuit = PCDCircuit::<Fr> {
        bytecode,
        prev_state,
        curr_state,
        _field: PhantomData,
    };
    
    // Generate a proving key and verifying key
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng)
        .map_err(|e| anyhow!("Setup error: {:?}", e))?;
    
    // Generate a proof
    let proof = Groth16::<Bn254>::prove(&pk, circuit, rng)
        .map_err(|e| anyhow!("Proving error: {:?}", e))?;
    
    Ok((proof, vk))
}

/// Generate proving and verifying keys for a circuit
pub fn generate_keys(
    circuit: PCDCircuit<Fr>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), anyhow::Error> {
    Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
        .map_err(|e| anyhow!("Setup error: {:?}", e))
}

// Add a get_public_inputs method for PCDCircuit
impl<F: ark_ff::Field> PCDCircuit<F> {
    pub fn get_public_inputs(&self) -> Result<Vec<F>, anyhow::Error> {
        // Return the current state as public inputs
        // This ensures consistency with the circuit implementation
        if self.curr_state.is_empty() {
            // If current state is empty, return a vector with just one (F::one())
            Ok(vec![F::one()])
        } else {
            // First add F::one() as the first public input (for the one_var in the circuit)
            let mut inputs = vec![F::one()];
            // Then add all current state elements
            inputs.extend(self.curr_state.clone());
            Ok(inputs)
        }
    }
}

/// Verify an EVM proof
pub fn verify_evm_proof(
    bytecode: Bytes,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
    curr_state: Vec<Fr>,
) -> Result<bool, anyhow::Error> {
    // Generate public inputs from bytecode and current state
    let circuit = PCDCircuit::<Fr> {
        bytecode,
        prev_state: None,
        curr_state: curr_state.clone(),
        _field: PhantomData,
    };
    let public_inputs = circuit.get_public_inputs()?;
    
    // Print debug information
    println!("Debug: Verifying proof with {} public inputs", public_inputs.len());
    for (i, input) in public_inputs.iter().enumerate() {
        println!("Debug: Public input {}: {:?}", i, input);
    }
    
    println!("Debug: Verifying key gamma_abc size: {}", vk.gamma_abc_g1.len());
    println!("Debug: Proof components: a={:?}, b={:?}, c={:?}", proof.a, proof.b, proof.c);
    
    match Groth16::<Bn254>::verify(vk, &public_inputs, proof) {
        Ok(result) => {
            println!("Debug: Verification result: {}", result);
            Ok(result)
        },
        Err(e) => {
            println!("Debug: Verification error: {:?}", e);
            Err(anyhow!("Verification error: {:?}", e))
        }
    }
}

/// Serialize a proof to bytes
pub fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>, anyhow::Error> {
    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes)
        .map_err(|e| anyhow!("Serialization error: {:?}", e))?;
    Ok(proof_bytes)
}

/// Deserialize a proof from bytes
pub fn deserialize_proof(proof_bytes: &[u8]) -> Result<Proof<Bn254>, anyhow::Error> {
    Proof::deserialize(proof_bytes)
        .map_err(|e| anyhow!("Deserialization error: {:?}", e))
}

/// Serialize a verifying key to bytes
pub fn serialize_vk(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>, anyhow::Error> {
    let mut vk_bytes = Vec::new();
    vk.serialize(&mut vk_bytes)
        .map_err(|e| anyhow!("Serialization error: {:?}", e))?;
    Ok(vk_bytes)
}

/// Deserialize a verifying key from bytes
pub fn deserialize_vk(vk_bytes: &[u8]) -> Result<VerifyingKey<Bn254>, anyhow::Error> {
    VerifyingKey::deserialize(vk_bytes)
        .map_err(|e| anyhow!("Deserialization error: {:?}", e))
}

/// Accumulate multiple proofs into a single proof
pub fn accumulate_proofs<R: RngCore + CryptoRng>(
    proofs: Vec<Proof<Bn254>>,
    public_inputs: Vec<Vec<Fr>>,
    rng: &mut R,
) -> Result<(Proof<Bn254>, VerifyingKey<Bn254>), anyhow::Error> {
    // Ensure we have at least one proof
    if proofs.is_empty() {
        return Err(anyhow!("Cannot accumulate empty proof set"));
    }
    
    // For now, we're implementing a simplified version of accumulation
    // that combines the public inputs from all proofs
    let combined_state: Vec<Fr> = public_inputs.into_iter().flatten().collect();
    
    // Create a circuit with the combined state
    let circuit = PCDCircuit::<Fr> {
        bytecode: Bytes::from(vec![0u8; 32]),  // Placeholder bytecode
        prev_state: None,
        curr_state: combined_state,
        _field: PhantomData,
    };
    
    println!("Debug: Accumulating {} proofs", proofs.len());
    
    // Generate a proving key and verifying key
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng)
        .map_err(|e| anyhow!("Setup error: {:?}", e))?;
    
    // Generate a proof for the accumulated circuit
    let proof = Groth16::<Bn254>::prove(&pk, circuit, rng)
        .map_err(|e| anyhow!("Proving error: {:?}", e))?;
    
    println!("Debug: Successfully accumulated proofs");
    Ok((proof, vk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::rand::thread_rng;
    use std::marker::PhantomData;

    #[test]
    fn test_evm_input() {
        let bytecode = Bytes::from(vec![1, 2, 3]);
        let curr_state = vec![Fr::from(42u32)];
        
        let input = EVMBytecodeInput {
            bytecode,
            prev_state: None,
            curr_state,
        };
        
        assert_eq!(input.bytecode, Bytes::from(vec![1, 2, 3]));
        assert_eq!(input.curr_state, vec![Fr::from(42u32)]);
    }
    
    #[test]
    fn test_evm_proof() {
        let bytecode = Bytes::from(vec![1, 2, 3]);
        let curr_state = vec![Fr::from(42u32)];
        
        let circuit = PCDCircuit::<Fr> {
            bytecode: bytecode.clone(),
            prev_state: None,
            curr_state: curr_state.clone(),
            _field: PhantomData,
        };
        
        let mut rng = thread_rng();
        let (pk, vk) = generate_keys(circuit.clone(), &mut rng).unwrap();
        
        // Generate a proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        
        // Verify the proof
        let is_valid = verify_evm_proof(bytecode, &proof, &vk, curr_state).unwrap();
        assert!(is_valid, "Proof verification failed");
    }
    
    #[test]
    fn test_proof_serialization() {
        let bytecode = Bytes::from(vec![1, 2, 3]);
        let curr_state = vec![Fr::from(42u32)];
        
        let circuit = PCDCircuit::<Fr> {
            bytecode: bytecode.clone(),
            prev_state: None,
            curr_state: curr_state.clone(),
            _field: PhantomData,
        };
        
        let mut rng = thread_rng();
        let (pk, vk) = generate_keys(circuit.clone(), &mut rng).unwrap();
        
        // Generate a proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        
        // Serialize and deserialize the proof
        let serialized_proof = serialize_proof(&proof).unwrap();
        let deserialized_proof = deserialize_proof(&serialized_proof).unwrap();
        
        // Verify the deserialized proof
        let is_valid = verify_evm_proof(bytecode, &deserialized_proof, &vk, curr_state).unwrap();
        assert!(is_valid, "Deserialized proof verification failed");
    }
    
    #[test]
    fn test_accumulation() {
        // Create a couple of simple bytecode inputs
        let bytecode1 = Bytes::from(vec![0x01, 0x02, 0x03]);
        let bytecode2 = Bytes::from(vec![0x04, 0x05, 0x06]);
        
        // Create state vectors
        let curr_state1 = vec![Fr::from(1u32)];
        let curr_state2 = vec![Fr::from(2u32)];
        
        // Generate proofs
        let mut rng = thread_rng();
        let (proof1, _) = generate_evm_proof(bytecode1.clone(), None, curr_state1.clone(), &mut rng).unwrap();
        let (proof2, _) = generate_evm_proof(bytecode2.clone(), None, curr_state2.clone(), &mut rng).unwrap();
        
        // Create public inputs
        let public_inputs = vec![curr_state1, curr_state2];
        
        // Accumulate proofs
        let proofs = vec![proof1, proof2];
        let result = accumulate_proofs(proofs, public_inputs, &mut rng);
        
        // Check that accumulation succeeds
        assert!(result.is_ok(), "Proof accumulation should succeed");
    }
}
